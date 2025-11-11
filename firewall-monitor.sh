#!/bin/sh
# Firewall Monitor - Logs connection attempts WITHOUT blocking
# Shows what the firewall would block if it were enabled
# Useful for seeing threats in real-time
#
# Version: 2.1
# Features:
#   - Automatic log source detection (syslog or dmesg)
#   - Works on embedded systems without persistent syslog
#   - Duplicate entry prevention
#   - Automatic log rotation
#   - Attack classification (SSH/FTP brute force, streaming blocks, etc.)
#
# Log Sources:
#   - Preferred: /var/log/messages (persistent syslog)
#   - Fallback: dmesg (kernel ring buffer, for embedded systems)
#   - Automatically detects and uses available source

export PATH=/sbin:/usr/sbin:/bin:/usr/bin
IPTABLES=`which iptables`
LOGFILE="/var/log/firewall-attempts.log"
USERS="/etc/firewall.users"

if [ "$IPTABLES#" = "#" ]; then echo "Iptables binary not found !"; exit; fi

case "$1" in
	'start')
		echo "Starting Firewall Monitor (logging only, NOT blocking)..."

		# Create log directory if needed
		mkdir -p /var/log
		touch $LOGFILE

		# Clear any existing monitor rules
		$IPTABLES -D INPUT -j LOG --log-prefix "FW-MONITOR: " 2>/dev/null

		# Load kernel modules
		modprobe nf_conntrack 2>/dev/null
		modprobe ip_tables 2>/dev/null
		modprobe xt_conntrack 2>/dev/null
		modprobe nf_log_ipv4 2>/dev/null
		modprobe xt_limit 2>/dev/null

		# Get allowed networks from config
		ALLOWED_IPS=""
		if [ -r $USERS ]; then
			ALLOWED_IPS=$(cat $USERS | grep -v '^#' | grep -v '^$' | awk '{print $1}')
		fi

		# Accept established connections (no logging needed)
		$IPTABLES -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
			$IPTABLES -I INPUT 1 -m state --state ESTABLISHED,RELATED -j ACCEPT

		# Accept loopback (no logging needed)
		$IPTABLES -I INPUT 2 -s 127.0.0.1 -j ACCEPT

		# Accept allowed IPs (no logging needed)
		RULE_NUM=3
		for IP in $ALLOWED_IPS; do
			if [ -n "$IP" ]; then
				$IPTABLES -I INPUT $RULE_NUM -s $IP -j ACCEPT
				RULE_NUM=$((RULE_NUM + 1))
			fi
		done

		# Log EVERYTHING ELSE (potential threats) but DON'T block
		# Limit to 30 per minute to avoid log flooding
		$IPTABLES -A INPUT -m limit --limit 30/min -j LOG --log-prefix "FW-MONITOR: " --log-level 4

		# Create PID directory if needed
		mkdir -p /var/run

		# Start background log processor with persistent PID
		sh -c '
			# Write our PID to file
			echo $$ > /var/run/firewall-monitor.pid

			IPTABLES='"'$(which iptables)'"'
			USERS="/etc/firewall.users"

			# Log rotation function
			rotate_log() {
				LOG="/var/log/firewall-attempts.log"
				MAX_SIZE=1048576  # 1MB in bytes
				MAX_ROTATIONS=3

				if [ -f "$LOG" ]; then
					SIZE=$(stat -c%s "$LOG" 2>/dev/null || echo 0)
					if [ "$SIZE" -gt "$MAX_SIZE" ]; then
						# Rotate old logs
						i=$MAX_ROTATIONS
						while [ $i -gt 1 ]; do
							if [ -f "$LOG.$((i-1))" ]; then
								mv "$LOG.$((i-1))" "$LOG.$i"
							fi
							i=$((i-1))
						done
						# Move current log to .1
						mv "$LOG" "$LOG.1"
						touch "$LOG"
						echo "Log rotated at $(date)" >> "$LOG"
					fi
				fi
			}

			# Function to ensure monitor rules are active
			ensure_rules() {
				# Check if firewall is running (has DROP policy and BLOCK logging)
				FIREWALL_ACTIVE=false
				if $IPTABLES -L INPUT 2>/dev/null | grep -q "FW-BLOCK-V4:"; then
					FIREWALL_ACTIVE=true
				elif $IPTABLES -L INPUT -n 2>/dev/null | grep "Chain INPUT" | grep -q "policy DROP"; then
					# Firewall might be active (DROP policy set)
					FIREWALL_ACTIVE=true
				fi

				# If firewall is active, don'\''t add monitor rules (firewall logs instead)
				if [ "$FIREWALL_ACTIVE" = "true" ]; then
					return 0
				fi

				# Firewall is NOT active, ensure monitor rules exist
				# Check if our LOG rule exists
				if ! $IPTABLES -L INPUT 2>/dev/null | grep -q "FW-MONITOR"; then
					# Rules missing, re-add them
					# Get allowed networks from config
					ALLOWED_IPS=""
					if [ -r $USERS ]; then
						ALLOWED_IPS=$(cat $USERS | grep -v '"'^#'"' | grep -v '"'^$'"' | awk '"'{print $1}'"')
					fi

					# Accept established connections (no logging needed)
					$IPTABLES -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
						$IPTABLES -I INPUT 1 -m state --state ESTABLISHED,RELATED -j ACCEPT

					# Accept loopback (no logging needed)
					$IPTABLES -I INPUT 2 -s 127.0.0.1 -j ACCEPT

					# Accept allowed IPs (no logging needed)
					RULE_NUM=3
					for IP in $ALLOWED_IPS; do
						if [ -n "$IP" ]; then
							$IPTABLES -I INPUT $RULE_NUM -s $IP -j ACCEPT
							RULE_NUM=$((RULE_NUM + 1))
						fi
					done

					# Re-add LOG rule (only in monitor-only mode)
					$IPTABLES -A INPUT -m limit --limit 30/min -j LOG --log-prefix "FW-MONITOR: " --log-level 4
				fi
			}

			# Track last processed line to avoid duplicates
			LAST_LINE_FILE="/var/run/firewall-monitor-lastline"
			DMESG_MARKER="/var/run/firewall-monitor-dmesg-marker"
			SYSLOG="/var/log/messages"
			USE_DMESG=0

			# Detect available log source
			if [ -f "$SYSLOG" ] && [ -r "$SYSLOG" ]; then
				LOG_SOURCE="syslog"
				echo "Monitor using syslog: $SYSLOG"
			else
				LOG_SOURCE="dmesg"
				USE_DMESG=1
				echo "Monitor using dmesg (syslog not available)"
			fi

			# Initialize tracking file - process last 200 lines on first start
			if [ ! -f "$LAST_LINE_FILE" ]; then
				START_LINE=0
				if [ "$USE_DMESG" -eq 0 ] && [ -f "$SYSLOG" ]; then
					TOTAL_LINES=$(wc -l < "$SYSLOG" 2>/dev/null || echo 0)
					START_LINE=$((TOTAL_LINES - 200))
					test "$START_LINE" -lt 0 && START_LINE=0
					echo "Monitor starting: Processing last 200 lines of syslog for recent attacks..."
				else
					echo "Monitor starting: Processing dmesg for recent attacks..."
				fi
				echo "$START_LINE" > "$LAST_LINE_FILE"
			fi

			while true; do
				# Check log size every iteration
				rotate_log

				# Ensure monitor rules are still active (survives firewall stop/restart)
				ensure_rules

				# Process logs based on available source
				if [ "$USE_DMESG" -eq 1 ]; then
					# DMESG MODE: Read from kernel ring buffer
					# Get current dmesg output and filter for firewall entries
					dmesg | grep -E "FW-MONITOR:|FW-BLOCK-V4:|FW-BLOCK-V6:|FW-SSH-BLOCK:|FW-FTP-BLOCK:|FW-SSH6-BLOCK:|FW-STREAM-BLOCK:|FW-HTTP-BLOCK:|FW-HTTP8080-BLOCK:" > /tmp/firewall-dmesg-current.tmp

					# Compare with previous run to detect new entries
					if [ -f "$DMESG_MARKER" ]; then
						# Extract only new lines
						comm -13 "$DMESG_MARKER" /tmp/firewall-dmesg-current.tmp | while read LINE; do
							TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")

							# Extract source IP from log line
							SRC_IP=$(echo "$LINE" | grep -o "SRC=[0-9.]*" | cut -d= -f2)
							DST_PORT=$(echo "$LINE" | grep -o "DPT=[0-9]*" | cut -d= -f2)
							PROTO=$(echo "$LINE" | grep -o "PROTO=[A-Z0-9]*" | cut -d= -f2)

							# Skip invalid or noise entries
							if [ -z "$SRC_IP" ] || [ "$SRC_IP" = "0.0.0.0" ]; then
								continue
							fi

							# Skip multicast/broadcast destinations (not attacks)
							DST_IP=$(echo "$LINE" | grep -o "DST=[0-9.]*" | cut -d= -f2)
							if echo "$DST_IP" | grep -qE "^(224\.|239\.|255\.255\.255\.255)"; then
								continue
							fi

							# Determine block type from log prefix
							BLOCK_TYPE="ATTEMPT"
							if echo "$LINE" | grep -q "FW-SSH-BLOCK:"; then
								BLOCK_TYPE="SSH-BRUTE-FORCE"
							elif echo "$LINE" | grep -q "FW-FTP-BLOCK:"; then
								BLOCK_TYPE="FTP-BRUTE-FORCE"
							elif echo "$LINE" | grep -q "FW-SSH6-BLOCK:"; then
								BLOCK_TYPE="SSH6-BRUTE-FORCE"
							elif echo "$LINE" | grep -q "FW-STREAM-BLOCK:"; then
								BLOCK_TYPE="STREAM-BLOCKED"
							elif echo "$LINE" | grep -q "FW-HTTP-BLOCK:"; then
								BLOCK_TYPE="HTTP-BLOCKED"
							elif echo "$LINE" | grep -q "FW-HTTP8080-BLOCK:"; then
								BLOCK_TYPE="HTTP8080-BLOCKED"
							elif echo "$LINE" | grep -q "FW-BLOCK-"; then
								BLOCK_TYPE="BLOCKED"
							fi

							# Log entry with port if available
							if [ -n "$DST_PORT" ]; then
								echo "[$TIMESTAMP] $BLOCK_TYPE from $SRC_IP to port $DST_PORT ($PROTO)" >> /var/log/firewall-attempts.log
							else
								echo "[$TIMESTAMP] $BLOCK_TYPE from $SRC_IP proto $PROTO" >> /var/log/firewall-attempts.log
							fi
						done
					fi

					# Save current state for next comparison
					cp /tmp/firewall-dmesg-current.tmp "$DMESG_MARKER"
					rm -f /tmp/firewall-dmesg-current.tmp

				else
					# SYSLOG MODE: Read from persistent syslog file
					# Get last processed line number
					LAST_LINE=$(cat "$LAST_LINE_FILE" 2>/dev/null || echo "0")
					CURRENT_LINES=$(wc -l < "$SYSLOG" 2>/dev/null || echo "0")

					# Process only new lines since last check
					if [ "$CURRENT_LINES" -gt "$LAST_LINE" ]; then
						NEW_LINES=$((CURRENT_LINES - LAST_LINE))

						tail -n "$NEW_LINES" "$SYSLOG" 2>/dev/null | grep -E "FW-MONITOR:|FW-BLOCK-V4:|FW-BLOCK-V6:|FW-SSH-BLOCK:|FW-FTP-BLOCK:|FW-SSH6-BLOCK:|FW-STREAM-BLOCK:|FW-HTTP-BLOCK:|FW-HTTP8080-BLOCK:" | while read LINE; do
							# Extract timestamp from syslog line (if available)
							TIMESTAMP=$(echo "$LINE" | awk '"'{print $1, $2, $3}'"' | grep -q "^[A-Z]" && echo "$LINE" | awk '"'{print $1, $2, $3}'"' || date "+%Y-%m-%d %H:%M:%S")

							# Extract source IP from log line
							SRC_IP=$(echo "$LINE" | grep -o "SRC=[0-9.]*" | cut -d= -f2)
							DST_PORT=$(echo "$LINE" | grep -o "DPT=[0-9]*" | cut -d= -f2)
							PROTO=$(echo "$LINE" | grep -o "PROTO=[A-Z0-9]*" | cut -d= -f2)

							# Skip invalid or noise entries
							if [ -z "$SRC_IP" ] || [ "$SRC_IP" = "0.0.0.0" ]; then
								continue
							fi

							# Skip multicast/broadcast destinations (not attacks)
							DST_IP=$(echo "$LINE" | grep -o "DST=[0-9.]*" | cut -d= -f2)
							if echo "$DST_IP" | grep -qE "^(224\.|239\.|255\.255\.255\.255)"; then
								continue
							fi

							# Determine block type from log prefix
							BLOCK_TYPE="ATTEMPT"
							if echo "$LINE" | grep -q "FW-SSH-BLOCK:"; then
								BLOCK_TYPE="SSH-BRUTE-FORCE"
							elif echo "$LINE" | grep -q "FW-FTP-BLOCK:"; then
								BLOCK_TYPE="FTP-BRUTE-FORCE"
							elif echo "$LINE" | grep -q "FW-SSH6-BLOCK:"; then
								BLOCK_TYPE="SSH6-BRUTE-FORCE"
							elif echo "$LINE" | grep -q "FW-STREAM-BLOCK:"; then
								BLOCK_TYPE="STREAM-BLOCKED"
							elif echo "$LINE" | grep -q "FW-HTTP-BLOCK:"; then
								BLOCK_TYPE="HTTP-BLOCKED"
							elif echo "$LINE" | grep -q "FW-HTTP8080-BLOCK:"; then
								BLOCK_TYPE="HTTP8080-BLOCKED"
							elif echo "$LINE" | grep -q "FW-BLOCK-"; then
								BLOCK_TYPE="BLOCKED"
							fi

							# Log entry with port if available
							if [ -n "$DST_PORT" ]; then
								echo "[$TIMESTAMP] $BLOCK_TYPE from $SRC_IP to port $DST_PORT ($PROTO)" >> /var/log/firewall-attempts.log
							else
								echo "[$TIMESTAMP] $BLOCK_TYPE from $SRC_IP proto $PROTO" >> /var/log/firewall-attempts.log
							fi
						done

						# Update last processed line number
						echo "$CURRENT_LINES" > "$LAST_LINE_FILE"
					fi
				fi

				sleep 5
			done
		' >/dev/null 2>&1 &

		echo "Monitor active! Logging to $LOGFILE"
		echo "NOTE: Connections are NOT being blocked, only logged."
		;;

	'stop')
		echo "Stopping Firewall Monitor..."

		# Kill background log processor
		if [ -f /var/run/firewall-monitor.pid ]; then
			kill $(cat /var/run/firewall-monitor.pid) 2>/dev/null
			rm -f /var/run/firewall-monitor.pid
		fi

		# Remove tracking files
		rm -f /var/run/firewall-monitor-lastline 2>/dev/null
		rm -f /var/run/firewall-monitor-dmesg-marker 2>/dev/null
		rm -f /tmp/firewall-dmesg-current.tmp 2>/dev/null

		# Remove monitoring rules but keep system accessible
		$IPTABLES -D INPUT -j LOG --log-prefix "FW-MONITOR: " 2>/dev/null
		$IPTABLES -F INPUT 2>/dev/null

		# Ensure default policy is ACCEPT (monitor mode = no blocking)
		$IPTABLES -P INPUT ACCEPT
		$IPTABLES -P OUTPUT ACCEPT
		$IPTABLES -P FORWARD ACCEPT

		echo "Monitor stopped. System is now UNPROTECTED!"
		;;

	'status')
		if [ -f /var/run/firewall-monitor.pid ] && kill -0 $(cat /var/run/firewall-monitor.pid) 2>/dev/null; then
			echo "Monitor is ACTIVE (logging, not blocking)"
			echo "Log file: $LOGFILE"
			if [ -f $LOGFILE ]; then
				LINES=$(wc -l < $LOGFILE)
				echo "Logged attempts: $LINES"
				echo ""
				echo "Recent attempts:"
				tail -10 $LOGFILE
			fi
		else
			echo "Monitor is INACTIVE"
		fi
		;;

	'clear-log')
		echo "Clearing monitor log..."
		> $LOGFILE
		echo "Log cleared."
		;;

	'rotate-log')
		echo "Rotating monitor log..."
		if [ -f $LOGFILE ]; then
			# Rotate old logs
			i=3
			while [ $i -gt 1 ]; do
				if [ -f "$LOGFILE.$((i-1))" ]; then
					mv "$LOGFILE.$((i-1))" "$LOGFILE.$i"
				fi
				i=$((i-1))
			done
			# Move current log to .1
			mv "$LOGFILE" "$LOGFILE.1"
			touch $LOGFILE
			echo "Log rotated. Old log saved as $LOGFILE.1"
		else
			echo "No log file to rotate."
		fi
		;;

	'show-log')
		if [ -f $LOGFILE ]; then
			cat $LOGFILE
		else
			echo "No log file found."
		fi
		;;

	'stats')
		if [ -f $LOGFILE ]; then
			echo "=== Firewall Monitor Statistics ==="
			echo ""
			echo "Total attempts: $(wc -l < $LOGFILE)"
			echo ""
			echo "Top attacking IPs:"
			grep -o "from [0-9.]*" $LOGFILE | awk '{print $2}' | sort | uniq -c | sort -rn | head -10
			echo ""
			echo "Top targeted ports:"
			grep -o "port [0-9]*" $LOGFILE | awk '{print $2}' | sort | uniq -c | sort -rn | head -10
		else
			echo "No log file found."
		fi
		;;

	'reprocess')
		echo "Reprocessing logs for firewall entries..."
		echo "This will rescan recent log data for all firewall blocks"

		# Reset tracking to force full reprocess
		rm -f /var/run/firewall-monitor-lastline
		rm -f /var/run/firewall-monitor-dmesg-marker
		rm -f /tmp/firewall-dmesg-current.tmp

		# Restart monitor (it will process last 200 lines on startup)
		$0 stop
		sleep 1
		$0 start

		echo "Monitor restarted and reprocessing recent log entries"
		;;

	*)
		echo "Firewall Monitor - Connection Attempt Logger"
		echo ""
		echo "Usage: $0 {start|stop|status|clear-log|rotate-log|show-log|stats|reprocess}"
		echo ""
		echo "  start      - Start monitoring (logs attempts, does NOT block)"
		echo "  stop       - Stop monitoring"
		echo "  status     - Show monitor status"
		echo "  clear-log  - Clear the log file"
		echo "  rotate-log - Rotate log file (save to .1, .2, .3)"
		echo "  show-log   - Display full log"
		echo "  stats      - Show statistics"
		echo "  reprocess  - Reprocess recent syslog entries (last 200 lines)"
		echo ""
		exit 0
esac

exit 0
