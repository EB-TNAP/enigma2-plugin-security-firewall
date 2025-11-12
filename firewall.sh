#!/bin/sh
# Professional Firewall for Enigma2 Receivers
# Version: 3.3 - Mutual Exclusion (conflicts with WireGuard plugin)
# Features: IPv4 + IPv6 protection, whitelist-first security, rate limiting, comprehensive logging
#
# Security Model:
#   - Whitelist-first approach: Trusted IPs evaluated BEFORE any other filtering
#   - NEW connections to sensitive ports blocked at SYN stage if not whitelisted (IPv4 AND IPv6)
#   - ESTABLISHED connections only possible if NEW connection was previously allowed
#   - Critical ports (8001, 80, 8080): Whitelist-only access, blocked at connection initiation
#   - Secondary ports (SSH, FTP): Rate limited for non-whitelisted IPs (3 attempts/min)
#   - All other traffic: Blocked by default with logging
#
# Changes in v2.7:
#   - SELF-HEALING: Firewall automatically restarts itself if wrong rule order detected
#   - No telnet/SSH access required - works automatically on every boot
#   - Simple solution: If ESTABLISHED at position <7, exec firewall restart
#   - IPv6 was vulnerable - ESTABLISHED rule before port blocks allowed bypass
#   - IPv6 now uses same architecture as IPv4: Whitelist → NEW Port Blocks → ESTABLISHED
#   - IPv6 whitelist: fe80::/10 (link-local), fc00::/7 (ULA private networks)
#   - Both IPv4 and IPv6 now have identical protection model
#
# Changes in v2.3:
#   - CRITICAL FIX: Block NEW connections to ports 8001/80/8080 BEFORE ESTABLISHED rule (IPv4 only)
#   - Prevents attackers from completing TCP handshake via permissive SYN flood rule
#   - Rule order: Loopback → Invalid Drop → Whitelist → NEW Port Blocks → ESTABLISHED → SYN Flood → Rate Limiting → Block
#   - IPv6 was NOT fixed in v2.3, allowing bypass via IPv6 connections
#
# Changes in v2.1:
#   - FIXED: Rule ordering - whitelist rules now applied BEFORE rate limiting
#   - FIXED: Port 8001 (streaming) now whitelist-only, no brute force attempts allowed
#   - FIXED: Reduced rate limit hitcount from 4-6 to 3 for better protection
#   - FIXED: Added whitelisted IP counter with warning if empty
#   - IMPROVED: Better logging of security model in startup output

export PATH=/sbin:/usr/sbin:/bin:/usr/bin

ALLOW_LAN_ACCESS="0"
USERS="/etc/firewall.users"
IPTABLES=$(which iptables)
IP6TABLES=$(which ip6tables)

# Validate iptables availability
if [ -z "$IPTABLES" ]; then
	echo "ERROR: iptables binary not found"
	exit 1
fi

# IPv6 support optional but recommended
if [ -z "$IP6TABLES" ]; then
	echo "WARNING: ip6tables not found - IPv6 protection disabled"
	IPV6_AVAILABLE=0
else
	IPV6_AVAILABLE=1
fi

# Function to load kernel modules
load_kernel_modules() {
	# Check if module database exists and is valid
	KERNEL_VERSION=$(uname -r)
	if [ ! -f "/lib/modules/${KERNEL_VERSION}/modules.dep" ] || [ ! -s "/lib/modules/${KERNEL_VERSION}/modules.dep" ]; then
		echo "Rebuilding kernel module database..."
		depmod -a 2>/dev/null
	fi

	# Load required kernel modules
	# Connection tracking (required)
	modprobe nf_conntrack 2>/dev/null
	modprobe nf_conntrack_ipv4 2>/dev/null
	modprobe ip_tables 2>/dev/null
	modprobe iptable_filter 2>/dev/null
	modprobe xt_state 2>/dev/null
	modprobe xt_conntrack 2>/dev/null

	# REJECT support (required for proper connection refusal)
	modprobe ipt_REJECT 2>/dev/null
	modprobe nf_reject_ipv4 2>/dev/null
	modprobe ip6t_REJECT 2>/dev/null
	modprobe nf_reject_ipv6 2>/dev/null

	# Rate limiting (required for DDoS protection)
	modprobe xt_limit 2>/dev/null
	modprobe xt_recent 2>/dev/null

	# Logging support
	modprobe nf_log_ipv4 2>/dev/null
	modprobe nf_log_ipv6 2>/dev/null

	# Connection limiting
	modprobe xt_connlimit 2>/dev/null

	# NAT support (optional)
	modprobe nf_nat 2>/dev/null
	modprobe nf_nat_ipv4 2>/dev/null
	modprobe iptable_nat 2>/dev/null
	modprobe nf_nat_masquerade_ipv4 2>/dev/null
	modprobe ipt_MASQUERADE 2>/dev/null

	# TCP/UDP port matching (for WireGuard)
	modprobe xt_tcpudp 2>/dev/null

	# IPv6 modules
	if [ "$IPV6_AVAILABLE" = "1" ]; then
		modprobe ip6_tables 2>/dev/null
		modprobe ip6table_filter 2>/dev/null
		modprobe nf_conntrack_ipv6 2>/dev/null
	fi
}

# Function to detect network interface and subnet
detect_network() {
	# Auto-detect primary network interface
	NET_IFACE=$(ip route | grep default | awk '{print $5}' | head -n 1)

	# Fallback to common interface names
	if [ -z "$NET_IFACE" ]; then
		for iface in eth0 enp0s25 eth1 wlan0; do
			if ip link show "$iface" >/dev/null 2>&1; then
				NET_IFACE="$iface"
				break
			fi
		done
	fi

	# If still not found, use first non-loopback interface
	if [ -z "$NET_IFACE" ]; then
		NET_IFACE=$(ip link show | grep -v "lo:" | grep "state UP" | head -n 1 | awk -F: '{print $2}' | tr -d ' ')
	fi

	if [ -z "$NET_IFACE" ]; then
		echo "WARNING: Could not detect network interface, using eth0"
		NET_IFACE="eth0"
	fi

	# Get local network CIDR
	LOCAL_NETWORK=$(ip -4 addr show "$NET_IFACE" 2>/dev/null | grep inet | awk '{print $2}' | head -n 1)

	# Fallback to ifconfig if ip command fails
	if [ -z "$LOCAL_NETWORK" ]; then
		LOCAL_IP=$(ifconfig "$NET_IFACE" 2>/dev/null | grep 'inet addr:' | sed -e 's/.*inet addr:\([^ ]*\).*/\1/')
		if [ -n "$LOCAL_IP" ]; then
			# Assume /24 if we can't determine actual netmask
			LOCAL_NETWORK="${LOCAL_IP%.*}.0/24"
		fi
	fi

	echo "Network Interface: $NET_IFACE"
	echo "Local Network: $LOCAL_NETWORK"
}

# Function to auto-configure firewall.users with detected local network
auto_configure_users() {
	USERS_FILE="/etc/firewall.users"

	# Check if firewall.users exists
	if [ ! -f "$USERS_FILE" ]; then
		echo "WARNING: $USERS_FILE not found, creating default..."
		# Will be created by detect_network and initial setup
		return 0
	fi

	# Detect current network
	detect_network

	if [ -z "$LOCAL_NETWORK" ]; then
		echo "WARNING: Could not detect local network, skipping auto-configuration"
		return 1
	fi

	# Check if file only contains default 192.168.1.0/24 (user hasn't customized it)
	# Count non-comment, non-empty lines
	USER_NETWORKS=$(grep -v '^#' "$USERS_FILE" | grep -v '^$' | wc -l)
	HAS_DEFAULT=$(grep -v '^#' "$USERS_FILE" | grep -q '192.168.1.0/24' && echo "yes" || echo "no")

	# If file has only one network and it's the default 192.168.1.0/24
	if [ "$USER_NETWORKS" -eq 1 ] && [ "$HAS_DEFAULT" = "yes" ]; then
		# Check if detected network is different from default
		if [ "$LOCAL_NETWORK" != "192.168.1.0/24" ]; then
			echo "Auto-configuring firewall.users for your network..."
			echo "Detected network: $LOCAL_NETWORK"

			# Backup original file
			cp "$USERS_FILE" "${USERS_FILE}.bak"

			# Replace 192.168.1.0/24 with detected network
			sed -i "s|192.168.1.0/24|$LOCAL_NETWORK  # Auto-detected on $(date '+%Y-%m-%d')|g" "$USERS_FILE"

			echo "Updated $USERS_FILE with detected network: $LOCAL_NETWORK"
			echo "Backup saved: ${USERS_FILE}.bak"
		else
			echo "Network configuration already correct: $LOCAL_NETWORK"
		fi
	elif [ "$USER_NETWORKS" -eq 0 ]; then
		# File is empty or only has comments, add detected network
		echo "Adding detected network to empty firewall.users..."
		echo "" >> "$USERS_FILE"
		echo "# Auto-detected local network (added $(date '+%Y-%m-%d'))" >> "$USERS_FILE"
		echo "$LOCAL_NETWORK" >> "$USERS_FILE"
		echo "Added network: $LOCAL_NETWORK"
	else
		# User has customized the file (multiple networks or non-default network)
		echo "firewall.users appears customized ($USER_NETWORKS networks), skipping auto-configuration"

		# Check if detected network exists in file
		if ! grep -q "^[^#]*${LOCAL_NETWORK}" "$USERS_FILE"; then
			echo "NOTICE: Your current network ($LOCAL_NETWORK) is not in firewall.users"
			echo "        You may need to add it manually to access this receiver"
		fi
	fi
}

# Function to validate IP address/network format
validate_ip() {
	local ip="$1"

	# Check for CIDR notation
	if echo "$ip" | grep -q '/'; then
		# Validate CIDR (basic check)
		if echo "$ip" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$'; then
			return 0
		fi
	else
		# Validate single IP
		if echo "$ip" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'; then
			return 0
		fi
	fi

	return 1
}

# Function to apply IPv4 firewall rules
apply_ipv4_rules() {
	echo "Applying IPv4 firewall rules..."

	# CRITICAL: Set default policies FIRST (prevents race condition)
	$IPTABLES -P INPUT DROP
	$IPTABLES -P FORWARD DROP
	$IPTABLES -P OUTPUT ACCEPT

	# Flush existing rules
	$IPTABLES -F INPUT
	$IPTABLES -F FORWARD
	$IPTABLES -F OUTPUT
	$IPTABLES -X

	# Rule 1: Accept loopback FIRST (before any filtering)
	$IPTABLES -A INPUT -i lo -j ACCEPT
	$IPTABLES -A INPUT -s 127.0.0.1 -j ACCEPT

	# Rule 2: Drop invalid packets early
	$IPTABLES -A INPUT -m conntrack --ctstate INVALID -j DROP 2>/dev/null || \
		$IPTABLES -A INPUT -m state --state INVALID -j DROP

	# Rule 3: WireGuard VPN support (UDP port 51820)
	# Accept VPN connections before other filtering
	$IPTABLES -A INPUT -p udp --dport 51820 -m conntrack --ctstate NEW -m limit --limit 10/s --limit-burst 20 -j ACCEPT 2>/dev/null
	$IPTABLES -A INPUT -p udp --dport 51820 -j ACCEPT 2>/dev/null

	# Rule 4: Allow traffic from WireGuard VPN clients (specific subnet only)
	# This replaces the insecure "accept all from wg0" rule
	$IPTABLES -A INPUT -s 10.99.99.0/24 -j ACCEPT 2>/dev/null

	# Rule 5: Local network access (if enabled)
	# CRITICAL: Whitelist rules MUST come BEFORE rate limiting AND established
	# This allows trusted networks full access without triggering rate limits
	if [ "$ALLOW_LAN_ACCESS" = "1" ] && [ -n "$LOCAL_NETWORK" ]; then
		$IPTABLES -A INPUT -s "$LOCAL_NETWORK" -j ACCEPT
		echo "Local network access enabled: $LOCAL_NETWORK"
	fi

	# Rule 6: Load user-defined allowed IPs/networks
	# CRITICAL: Whitelist BEFORE rate limiting AND established checks
	WHITELISTED_COUNT=0
	if [ -r "$USERS" ]; then
		while read -r line; do
			# Skip comments and empty lines
			case "$line" in
				\#*|"") continue ;;
			esac

			# Extract IP (first field)
			IP=$(echo "$line" | awk '{print $1}')

			if [ -z "$IP" ]; then
				continue
			fi

			# Check if it's a hostname (contains letters)
			if echo "$IP" | grep -q '[a-zA-Z]'; then
				echo "WARNING: Hostname resolution disabled for security - skipping: $IP"
				echo "         Please use IP addresses or CIDR notation only"
				continue
			fi

			# Validate IP format
			if validate_ip "$IP"; then
				$IPTABLES -A INPUT -s "$IP" -j ACCEPT
				echo "Allowed access from: $IP"
				WHITELISTED_COUNT=$((WHITELISTED_COUNT + 1))
			else
				echo "WARNING: Invalid IP format, skipping: $IP"
			fi
		done < "$USERS"
	else
		echo "WARNING: Cannot read $USERS - using default rules only"
	fi

	if [ "$WHITELISTED_COUNT" -eq 0 ]; then
		echo "WARNING: No whitelisted IPs configured - all external access will be blocked!"
		echo "         Edit /etc/firewall.users to add trusted networks"
	fi

	# Rule 7: Block NEW connections to sensitive ports from non-whitelisted IPs
	# CRITICAL: This MUST come AFTER whitelist rules but BEFORE ESTABLISHED and SYN flood protection
	# This prevents attackers from completing TCP handshake to sensitive ports
	# Whitelisted IPs have already been ACCEPTED above, so they bypass these blocks
	$IPTABLES -A INPUT -p tcp --dport 8001 -m conntrack --ctstate NEW -m limit --limit 5/min --limit-burst 10 -j LOG --log-prefix "FW-STREAM-BLOCK: " --log-level 4 2>/dev/null
	$IPTABLES -A INPUT -p tcp --dport 8001 -m conntrack --ctstate NEW -j REJECT --reject-with tcp-reset 2>/dev/null

	$IPTABLES -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -m limit --limit 5/min --limit-burst 10 -j LOG --log-prefix "FW-HTTP-BLOCK: " --log-level 4 2>/dev/null
	$IPTABLES -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j REJECT --reject-with tcp-reset 2>/dev/null

	$IPTABLES -A INPUT -p tcp --dport 8080 -m conntrack --ctstate NEW -m limit --limit 5/min --limit-burst 10 -j LOG --log-prefix "FW-HTTP8080-BLOCK: " --log-level 4 2>/dev/null
	$IPTABLES -A INPUT -p tcp --dport 8080 -m conntrack --ctstate NEW -j REJECT --reject-with tcp-reset 2>/dev/null

	echo "Whitelist-only protection: Ports 8001, 80, 8080 (streaming/web interface)"
	echo "Non-whitelisted IPs cannot establish NEW connections to these ports"

	# Rule 8: Accept ESTABLISHED/RELATED connections
	# CRITICAL: This is now safe because sensitive ports rejected NEW connections above
	# Only whitelisted IPs can have ESTABLISHED connections to ports 8001/80/8080
	$IPTABLES -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
		$IPTABLES -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

	# Rule 9: ICMP rate limiting (allow ping but prevent flood)
	$IPTABLES -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 3 -j ACCEPT
	$IPTABLES -A INPUT -p icmp --icmp-type echo-request -j DROP
	$IPTABLES -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT
	$IPTABLES -A INPUT -p icmp --icmp-type destination-unreachable -j ACCEPT
	$IPTABLES -A INPUT -p icmp --icmp-type time-exceeded -j ACCEPT

	# Rule 11: Rate limit connection attempts per IP (anti-brute-force)
	# CRITICAL: Only non-whitelisted IPs reach here
	# Reduced hitcount to 3 for better protection
	# Only apply if xt_recent module is available
	if lsmod | grep -q xt_recent || [ -f /proc/net/xt_recent/SSH ] 2>/dev/null; then
		# SSH protection - allow 2 attempts per minute, block on 3rd
		$IPTABLES -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set --name SSH 2>/dev/null
		$IPTABLES -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 3 --name SSH -j LOG --log-prefix "FW-SSH-BLOCK: " --log-level 4 2>/dev/null
		$IPTABLES -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 3 --name SSH -j REJECT --reject-with tcp-reset 2>/dev/null

		# FTP protection - allow 2 attempts per minute, block on 3rd
		$IPTABLES -A INPUT -p tcp --dport 21 -m conntrack --ctstate NEW -m recent --set --name FTP 2>/dev/null
		$IPTABLES -A INPUT -p tcp --dport 21 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 3 --name FTP -j LOG --log-prefix "FW-FTP-BLOCK: " --log-level 4 2>/dev/null
		$IPTABLES -A INPUT -p tcp --dport 21 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 3 --name FTP -j REJECT --reject-with tcp-reset 2>/dev/null

		echo "Brute force protection: ENABLED (xt_recent available)"
		echo "Protected ports: SSH(22) - 3 attempts/min, FTP(21) - 3 attempts/min"
		echo "Note: Whitelisted IPs bypass rate limiting"
	else
		echo "Brute force protection: DISABLED (xt_recent module not available)"
		echo "Note: Ports are still protected by whitelist and connection limits"
	fi

	# Rule 12: Connection limit per IP (prevent resource exhaustion)
	$IPTABLES -A INPUT -p tcp -m connlimit --connlimit-above 50 -j REJECT --reject-with tcp-reset 2>/dev/null

	# Rule 13: Log blocked packets (rate limited to prevent log flooding)
	$IPTABLES -A INPUT -m limit --limit 10/min --limit-burst 20 -j LOG --log-prefix "FW-BLOCK-V4: " --log-level 4

	# Rule 14: Final DROP (default policy already set, but explicit for clarity)
	$IPTABLES -A INPUT -j DROP

	echo "IPv4 firewall rules applied successfully"
}

# Function to apply IPv6 firewall rules
apply_ipv6_rules() {
	if [ "$IPV6_AVAILABLE" != "1" ]; then
		echo "IPv6 protection: DISABLED (ip6tables not available)"
		return
	fi

	echo "Applying IPv6 firewall rules..."

	# Test if IPv6 netfilter is actually functional
	if ! $IP6TABLES -L -n >/dev/null 2>&1; then
		echo "WARNING: IPv6 netfilter not functional, skipping IPv6 rules"
		echo "Note: IPv4 protection is still active"
		return
	fi

	# CRITICAL: Set default policies FIRST (prevents race condition)
	$IP6TABLES -P INPUT DROP 2>/dev/null || {
		echo "WARNING: Cannot set IPv6 policies, IPv6 netfilter may not be fully supported"
		return
	}
	$IP6TABLES -P FORWARD DROP 2>/dev/null
	$IP6TABLES -P OUTPUT ACCEPT 2>/dev/null

	# Flush existing rules
	$IP6TABLES -F INPUT 2>/dev/null
	$IP6TABLES -F FORWARD 2>/dev/null
	$IP6TABLES -F OUTPUT 2>/dev/null
	$IP6TABLES -X 2>/dev/null

	# Rule 1: Accept loopback FIRST (before any filtering)
	$IP6TABLES -A INPUT -i lo -j ACCEPT 2>/dev/null
	$IP6TABLES -A INPUT -s ::1 -j ACCEPT 2>/dev/null

	# Rule 2: Drop invalid packets early
	$IP6TABLES -A INPUT -m conntrack --ctstate INVALID -j DROP 2>/dev/null || \
		$IP6TABLES -A INPUT -m state --state INVALID -j DROP 2>/dev/null

	# Rule 3: Accept ICMPv6 (required for IPv6 to function properly)
	# Neighbor Discovery Protocol (NDP)
	$IP6TABLES -A INPUT -p ipv6-icmp --icmpv6-type neighbor-solicitation -j ACCEPT 2>/dev/null
	$IP6TABLES -A INPUT -p ipv6-icmp --icmpv6-type neighbor-advertisement -j ACCEPT 2>/dev/null
	$IP6TABLES -A INPUT -p ipv6-icmp --icmpv6-type router-solicitation -j ACCEPT 2>/dev/null
	$IP6TABLES -A INPUT -p ipv6-icmp --icmpv6-type router-advertisement -j ACCEPT 2>/dev/null
	# Echo request/reply (ping6) - rate limited
	$IP6TABLES -A INPUT -p ipv6-icmp --icmpv6-type echo-request -m limit --limit 1/s --limit-burst 3 -j ACCEPT 2>/dev/null
	$IP6TABLES -A INPUT -p ipv6-icmp --icmpv6-type echo-request -j DROP 2>/dev/null
	$IP6TABLES -A INPUT -p ipv6-icmp --icmpv6-type echo-reply -j ACCEPT 2>/dev/null
	# Other necessary ICMPv6 types
	$IP6TABLES -A INPUT -p ipv6-icmp --icmpv6-type destination-unreachable -j ACCEPT 2>/dev/null
	$IP6TABLES -A INPUT -p ipv6-icmp --icmpv6-type packet-too-big -j ACCEPT 2>/dev/null
	$IP6TABLES -A INPUT -p ipv6-icmp --icmpv6-type time-exceeded -j ACCEPT 2>/dev/null
	$IP6TABLES -A INPUT -p ipv6-icmp --icmpv6-type parameter-problem -j ACCEPT 2>/dev/null

	# Rule 4: WireGuard VPN support (if using IPv6)
	$IP6TABLES -A INPUT -p udp --dport 51820 -m conntrack --ctstate NEW -m limit --limit 10/s --limit-burst 20 -j ACCEPT 2>/dev/null
	$IP6TABLES -A INPUT -p udp --dport 51820 -j ACCEPT 2>/dev/null

	# Rule 5: Allow link-local addresses (fe80::/10) - required for local network
	# CRITICAL: This acts as IPv6 whitelist - local network traffic accepted here
	$IP6TABLES -A INPUT -s fe80::/10 -j ACCEPT 2>/dev/null

	# Rule 6: Allow unique local addresses (fc00::/7) - private IPv6 networks
	# CRITICAL: This acts as IPv6 whitelist - private network traffic accepted here
	$IP6TABLES -A INPUT -s fc00::/7 -j ACCEPT 2>/dev/null

	# Rule 7: Block NEW connections to sensitive ports from non-whitelisted IPv6 addresses
	# CRITICAL: This MUST come AFTER whitelist rules but BEFORE ESTABLISHED rule
	# Same fix as IPv4 v2.3 - block at SYN stage, not after connection established
	echo "Applying IPv6 whitelist-only protection for ports 8001, 80, 8080..."
	$IP6TABLES -A INPUT -p tcp --dport 8001 -m conntrack --ctstate NEW -j LOG --log-prefix "FW-STREAM-BLOCK-V6: " --log-level 4 2>/dev/null
	$IP6TABLES -A INPUT -p tcp --dport 8001 -m conntrack --ctstate NEW -j REJECT --reject-with tcp-reset 2>/dev/null || \
		$IP6TABLES -A INPUT -p tcp --dport 8001 -j DROP 2>/dev/null

	$IP6TABLES -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j LOG --log-prefix "FW-HTTP-BLOCK-V6: " --log-level 4 2>/dev/null
	$IP6TABLES -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j REJECT --reject-with tcp-reset 2>/dev/null || \
		$IP6TABLES -A INPUT -p tcp --dport 80 -j DROP 2>/dev/null

	$IP6TABLES -A INPUT -p tcp --dport 8080 -m conntrack --ctstate NEW -j LOG --log-prefix "FW-HTTP8080-BLOCK-V6: " --log-level 4 2>/dev/null
	$IP6TABLES -A INPUT -p tcp --dport 8080 -m conntrack --ctstate NEW -j REJECT --reject-with tcp-reset 2>/dev/null || \
		$IP6TABLES -A INPUT -p tcp --dport 8080 -j DROP 2>/dev/null

	# Rule 8: Accept ESTABLISHED/RELATED connections
	# CRITICAL: This is now safe because sensitive ports rejected NEW connections above
	# Only whitelisted IPv6 addresses can have ESTABLISHED connections to ports 8001/80/8080
	$IP6TABLES -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
		$IP6TABLES -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null

	# Rule 9: Rate limit SSH/FTP for non-whitelisted IPv6 addresses (if xt_recent available)
	# Note: Whitelisted IPv6 addresses (fe80::/10, fc00::/7) bypass this via Rules 5-6
	if lsmod | grep -q xt_recent || [ -f /proc/net/xt_recent/SSH6 ] 2>/dev/null; then
		$IP6TABLES -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set --name SSH6 2>/dev/null
		$IP6TABLES -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 3 --name SSH6 -j LOG --log-prefix "FW-SSH6-BLOCK: " --log-level 4 2>/dev/null
		$IP6TABLES -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 3 --name SSH6 -j REJECT --reject-with tcp-reset 2>/dev/null

		$IP6TABLES -A INPUT -p tcp --dport 21 -m conntrack --ctstate NEW -m recent --set --name FTP6 2>/dev/null
		$IP6TABLES -A INPUT -p tcp --dport 21 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 3 --name FTP6 -j LOG --log-prefix "FW-FTP6-BLOCK: " --log-level 4 2>/dev/null
		$IP6TABLES -A INPUT -p tcp --dport 21 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 3 --name FTP6 -j REJECT --reject-with tcp-reset 2>/dev/null

		echo "IPv6 brute force protection: ENABLED (SSH/FTP - 3 attempts/min)"
	else
		echo "IPv6 brute force protection: DISABLED (xt_recent not available)"
	fi

	# Rule 11: Block telnet and other dangerous services
	$IP6TABLES -A INPUT -p tcp --dport 23 -j REJECT --reject-with tcp-reset 2>/dev/null || \
		$IP6TABLES -A INPUT -p tcp --dport 23 -j DROP 2>/dev/null

	# Rule 12: Connection limit per IP
	$IP6TABLES -A INPUT -p tcp -m connlimit --connlimit-above 50 -j REJECT --reject-with tcp-reset 2>/dev/null

	# Rule 13: Log blocked packets (rate limited)
	$IP6TABLES -A INPUT -m limit --limit 10/min --limit-burst 20 -j LOG --log-prefix "FW-BLOCK-V6: " --log-level 4 2>/dev/null

	# Rule 14: Final DROP
	$IP6TABLES -A INPUT -j DROP 2>/dev/null

	echo "IPv6 firewall rules applied successfully"
}

# Function to verify firewall rules are active
verify_firewall() {
	echo "Verifying firewall status..."

	# Check IPv4
	IPV4_POLICY=$($IPTABLES -L INPUT -n | grep "Chain INPUT" | grep -o "policy [A-Z]*" | awk '{print $2}')
	IPV4_RULES=$($IPTABLES -L INPUT -n | grep -c "^[A-Z]")

	if [ "$IPV4_POLICY" != "DROP" ]; then
		echo "ERROR: IPv4 default policy is not DROP (current: $IPV4_POLICY)"
		return 1
	fi

	if [ "$IPV4_RULES" -lt 5 ]; then
		echo "ERROR: IPv4 firewall has too few rules ($IPV4_RULES), may not be configured correctly"
		return 1
	fi

	echo "IPv4 Firewall: ACTIVE (policy: DROP, rules: $IPV4_RULES)"

	# Check IPv6
	if [ "$IPV6_AVAILABLE" = "1" ]; then
		IPV6_POLICY=$($IP6TABLES -L INPUT -n | grep "Chain INPUT" | grep -o "policy [A-Z]*" | awk '{print $2}')
		IPV6_RULES=$($IP6TABLES -L INPUT -n | grep -c "^[A-Z]")

		if [ "$IPV6_POLICY" != "DROP" ]; then
			echo "WARNING: IPv6 default policy is not DROP (current: $IPV6_POLICY)"
		else
			echo "IPv6 Firewall: ACTIVE (policy: DROP, rules: $IPV6_RULES)"
		fi
	else
		echo "IPv6 Firewall: NOT AVAILABLE"
	fi

	return 0
}

# Main execution
case "$1" in
	'start')
		# Extract version from header
		VERSION=$(grep '^# Version:' "$0" | head -n 1 | sed 's/.*Version: //' | cut -d' ' -f1)
		echo "Starting Professional Firewall ${VERSION}..."
		echo "========================================"

		# CRITICAL: Check for conflicting WireGuard plugin
		if [ -f /etc/wireguard/wg0.conf ] || [ -f /etc/init.d/wireguard ]; then
			echo ""
			echo "================================================================"
			echo "ERROR: WireGuard VPN plugin detected!"
			echo "================================================================"
			echo ""
			echo "The Firewall and WireGuard plugins have CONFLICTING security"
			echo "models and cannot be installed together."
			echo ""
			echo "Your phone connection issue was caused by this conflict!"
			echo ""
			echo "Please choose ONE security approach:"
			echo ""
			echo "OPTION 1: Keep Firewall Plugin (Internet-facing with whitelist)"
			echo "  - Allows selective internet access to specific IPs"
			echo "  - Advanced threat protection and logging"
			echo "  - For receivers exposed to the internet"
			echo "  - Uninstall WireGuard: Menu > Plugins > Remove WireGuard"
			echo "    OR: opkg remove enigma2-plugin-extensions-wireguard-tnap"
			echo ""
			echo "OPTION 2: Keep WireGuard Plugin (VPN-only access)"
			echo "  - Remote access only via encrypted VPN tunnel"
			echo "  - Complete internet lockdown (except VPN)"
			echo "  - For private remote access scenarios"
			echo "  - Uninstall Firewall: Menu > Plugins > Remove Firewall"
			echo "    OR: opkg remove enigma2-plugin-security-firewall"
			echo ""
			echo "================================================================"
			echo "Firewall startup ABORTED to prevent conflicts"
			echo "================================================================"
			exit 1
		fi

		# CRITICAL: Check if wrong rules exist BEFORE we do anything
		# This catches boot-time issues where something else loaded bad rules
		if command -v iptables >/dev/null 2>&1; then
			EXISTING_ESTABLISHED=$($IPTABLES -L INPUT -n --line-numbers 2>/dev/null | grep "ESTABLISHED" | head -n 1 | awk '{print $1}')
			if [ -n "$EXISTING_ESTABLISHED" ] && [ "$EXISTING_ESTABLISHED" -lt 7 ]; then
				echo "========================================"
				echo "WARNING: Detected wrong rules from boot!"
				echo "ESTABLISHED at position $EXISTING_ESTABLISHED (should be ~15)"
				echo "Flushing and restarting firewall..."
				echo "========================================"
				sleep 2
				exec "$0" restart
			fi
		fi

		# Auto-configure firewall.users if needed
		auto_configure_users
		echo ""

		# Load kernel modules
		load_kernel_modules

		# Detect network configuration (called again for final display)
		detect_network

		# Apply firewall rules
		apply_ipv4_rules
		apply_ipv6_rules

		# Verify firewall is active
		if verify_firewall; then
			# CRITICAL: Verify rule order is correct (whitelist before ESTABLISHED)
			# Check if ESTABLISHED rule is in wrong position (rule 1 instead of ~rule 14)
			ESTABLISHED_POS=$($IPTABLES -L INPUT -n --line-numbers | grep "ESTABLISHED" | head -n 1 | awk '{print $1}')

			if [ -n "$ESTABLISHED_POS" ] && [ "$ESTABLISHED_POS" -lt 7 ]; then
				echo "========================================"
				echo "WARNING: Rules loaded in wrong order!"
				echo "ESTABLISHED rule at position $ESTABLISHED_POS (should be ~14)"
				echo "Auto-correcting by restarting firewall..."
				echo "========================================"

				# Simple solution: Just restart the firewall
				# This will flush everything and reload correctly
				sleep 2
				exec "$0" restart
			fi

			echo "========================================"
			echo "Firewall is ACTIVE and SECURE"
			echo "IPv4 Protection: ENABLED"
			if [ "$IPV6_AVAILABLE" = "1" ]; then
				echo "IPv6 Protection: ENABLED"
			else
				echo "IPv6 Protection: UNAVAILABLE (install ip6tables)"
			fi
			echo "========================================"
		else
			echo "ERROR: Firewall verification failed"
			exit 1
		fi

		exit 0
		;;

	'stop')
		echo "Stopping firewall..."

		# Restore default ACCEPT policies
		$IPTABLES -P INPUT ACCEPT
		$IPTABLES -P OUTPUT ACCEPT
		$IPTABLES -P FORWARD ACCEPT

		# Flush all rules
		$IPTABLES -F
		$IPTABLES -X
		$IPTABLES -Z

		# IPv6 cleanup
		if [ "$IPV6_AVAILABLE" = "1" ]; then
			$IP6TABLES -P INPUT ACCEPT
			$IP6TABLES -P OUTPUT ACCEPT
			$IP6TABLES -P FORWARD ACCEPT
			$IP6TABLES -F
			$IP6TABLES -X
			$IP6TABLES -Z
		fi

		echo "Firewall disabled - SYSTEM IS UNPROTECTED"
		exit 0
		;;

	'restart'|'reload')
		echo "Restarting firewall..."
		$0 stop

		# Flush connection tracking table to enforce new rules immediately
		if [ -f /proc/net/nf_conntrack ]; then
			echo "Flushing connection tracking table..."
			conntrack -F 2>/dev/null || echo "WARNING: conntrack tool not available"
		fi

		sleep 1
		$0 start
		exit 0
		;;

	'status')
		echo "Firewall Status:"
		echo "================"
		echo ""
		echo "IPv4 Rules:"
		$IPTABLES -L -n -v --line-numbers
		echo ""

		if [ "$IPV6_AVAILABLE" = "1" ]; then
			echo "IPv6 Rules:"
			$IP6TABLES -L -n -v --line-numbers
			echo ""
		fi

		verify_firewall
		exit 0
		;;

	'test')
		echo "Running firewall self-test..."
		echo "=============================="

		# Test IPv4
		echo ""
		echo "IPv4 Tests:"
		echo "Default Policy: $($IPTABLES -L INPUT -n | grep "Chain INPUT" | grep -o "policy [A-Z]*")"
		echo "Total Rules: $($IPTABLES -L INPUT -n | grep -c "^[A-Z]")"
		echo "Loopback Accept: $($IPTABLES -L INPUT -n | grep -c "127.0.0.1")"
		echo "Established/Related: $($IPTABLES -L INPUT -n | grep -c "ESTABLISHED")"

		# Test IPv6
		if [ "$IPV6_AVAILABLE" = "1" ]; then
			echo ""
			echo "IPv6 Tests:"
			echo "Default Policy: $($IP6TABLES -L INPUT -n | grep "Chain INPUT" | grep -o "policy [A-Z]*")"
			echo "Total Rules: $($IP6TABLES -L INPUT -n | grep -c "^[A-Z]")"
			echo "Loopback Accept: $($IP6TABLES -L INPUT -n | grep -c "::1")"
			echo "Link-Local Accept: $($IP6TABLES -L INPUT -n | grep -c "fe80::/10")"
		fi

		echo ""
		verify_firewall
		exit 0
		;;

	*)
		# Extract version and description from header
		VERSION=$(grep '^# Version:' "$0" | head -n 1 | sed 's/.*Version: //' | cut -d' ' -f1)
		DESCRIPTION=$(grep '^# Version:' "$0" | head -n 1 | sed 's/.*Version: [^ ]* - //')
		echo "Professional Firewall ${VERSION} - ${DESCRIPTION}"
		echo "Usage: $0 {start|stop|restart|status|test}"
		echo ""
		echo "Commands:"
		echo "  start   - Start firewall with full protection"
		echo "  stop    - Stop firewall (WARNING: system will be unprotected)"
		echo "  restart - Restart firewall and flush connection tracking"
		echo "  status  - Show detailed firewall status and rules"
		echo "  test    - Run firewall self-test diagnostics"
		echo ""
		exit 0
		;;
esac

exit 0
