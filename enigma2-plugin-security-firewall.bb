DESCRIPTION = "Firewall Security Manager with GUI - Hardened whitelist-first protection"

require conf/license/openpli-gplv2.inc

# CRITICAL: Cannot coexist with WireGuard plugin (conflicting security models)
RCONFLICTS:${PN} = "enigma2-plugin-extensions-wireguard-tnap"

# Core dependencies that work across all kernel versions (5.x+)
RDEPENDS:${PN} = "iptables \
                  conntrack-tools \
                  python3-core \
                  kernel-module-nf-conntrack \
                  kernel-module-ip-tables \
                  kernel-module-iptable-filter \
                  kernel-module-xt-conntrack \
                  kernel-module-xt-limit \
                  kernel-module-nf-nat \
                  kernel-module-ip6-tables \
                  kernel-module-ip6table-filter \
                  kernel-module-nf-reject-ipv4 \
                  kernel-module-nf-reject-ipv6 \
                  kernel-module-xt-recent \
                 "

# Kernel 4.x specific modules (removed/merged in 5.x+)
# These modules don't exist in kernel 5.15+
RDEPENDS:${PN} += "${@bb.utils.contains('PREFERRED_VERSION_linux-uclan', '4.4.35', 'kernel-module-nf-conntrack-ipv4', '', d)}"
RDEPENDS:${PN} += "${@bb.utils.contains('PREFERRED_VERSION_linux-uclan', '4.4.35', 'kernel-module-xt-state', '', d)}"
RDEPENDS:${PN} += "${@bb.utils.contains('PREFERRED_VERSION_linux-uclan', '4.4.35', 'kernel-module-ipt-reject', '', d)}"
RDEPENDS:${PN} += "${@bb.utils.contains('PREFERRED_VERSION_linux-uclan', '4.4.35', 'kernel-module-nf-nat-ipv4', '', d)}"
RDEPENDS:${PN} += "${@bb.utils.contains('PREFERRED_VERSION_linux-uclan', '4.4.35', 'kernel-module-nf-nat-masquerade-ipv4', '', d)}"
RDEPENDS:${PN} += "${@bb.utils.contains('PREFERRED_VERSION_linux-uclan', '4.4.35', 'kernel-module-ipt-masquerade', '', d)}"
RDEPENDS:${PN} += "${@bb.utils.contains('PREFERRED_VERSION_linux-uclan', '4.4.35', 'kernel-module-iptable-nat', '', d)}"
RDEPENDS:${PN} += "${@bb.utils.contains('PREFERRED_VERSION_linux-uclan', '4.4.35', 'kernel-module-nf-log-ipv4', '', d)}"
RDEPENDS:${PN} += "${@bb.utils.contains('PREFERRED_VERSION_linux-uclan', '4.4.35', 'kernel-module-nf-reject-ipv4', '', d)}"

# Similar check for Octagon machines (4.4.35)
RDEPENDS:${PN} += "${@bb.utils.contains('PREFERRED_VERSION_linux-octagon', '4.4.35', 'kernel-module-nf-conntrack-ipv4', '', d)}"
RDEPENDS:${PN} += "${@bb.utils.contains('PREFERRED_VERSION_linux-octagon', '4.4.35', 'kernel-module-xt-state', '', d)}"
RDEPENDS:${PN} += "${@bb.utils.contains('PREFERRED_VERSION_linux-octagon', '4.4.35', 'kernel-module-ipt-reject', '', d)}"
RDEPENDS:${PN} += "${@bb.utils.contains('PREFERRED_VERSION_linux-octagon', '4.4.35', 'kernel-module-nf-nat-ipv4', '', d)}"
RDEPENDS:${PN} += "${@bb.utils.contains('PREFERRED_VERSION_linux-octagon', '4.4.35', 'kernel-module-nf-nat-masquerade-ipv4', '', d)}"
RDEPENDS:${PN} += "${@bb.utils.contains('PREFERRED_VERSION_linux-octagon', '4.4.35', 'kernel-module-ipt-masquerade', '', d)}"
RDEPENDS:${PN} += "${@bb.utils.contains('PREFERRED_VERSION_linux-octagon', '4.4.35', 'kernel-module-iptable-nat', '', d)}"
RDEPENDS:${PN} += "${@bb.utils.contains('PREFERRED_VERSION_linux-octagon', '4.4.35', 'kernel-module-nf-log-ipv4', '', d)}"
RDEPENDS:${PN} += "${@bb.utils.contains('PREFERRED_VERSION_linux-octagon', '4.4.35', 'kernel-module-nf-reject-ipv4', '', d)}"

# Similar check for Qviart machines (4.4.35)
RDEPENDS:${PN} += "${@bb.utils.contains('PREFERRED_VERSION_linux-qviart', '4.4.35', 'kernel-module-nf-conntrack-ipv4', '', d)}"
RDEPENDS:${PN} += "${@bb.utils.contains('PREFERRED_VERSION_linux-qviart', '4.4.35', 'kernel-module-xt-state', '', d)}"
RDEPENDS:${PN} += "${@bb.utils.contains('PREFERRED_VERSION_linux-qviart', '4.4.35', 'kernel-module-ipt-reject', '', d)}"
RDEPENDS:${PN} += "${@bb.utils.contains('PREFERRED_VERSION_linux-qviart', '4.4.35', 'kernel-module-nf-nat-ipv4', '', d)}"
RDEPENDS:${PN} += "${@bb.utils.contains('PREFERRED_VERSION_linux-qviart', '4.4.35', 'kernel-module-nf-nat-masquerade-ipv4', '', d)}"
RDEPENDS:${PN} += "${@bb.utils.contains('PREFERRED_VERSION_linux-qviart', '4.4.35', 'kernel-module-ipt-masquerade', '', d)}"
RDEPENDS:${PN} += "${@bb.utils.contains('PREFERRED_VERSION_linux-qviart', '4.4.35', 'kernel-module-iptable-nat', '', d)}"
RDEPENDS:${PN} += "${@bb.utils.contains('PREFERRED_VERSION_linux-qviart', '4.4.35', 'kernel-module-nf-log-ipv4', '', d)}"
RDEPENDS:${PN} += "${@bb.utils.contains('PREFERRED_VERSION_linux-qviart', '4.4.35', 'kernel-module-nf-reject-ipv4', '', d)}"

# Optional modules (RRECOMMENDS) - not required but enhance functionality
# xt-tcpudp: For WireGuard port matching (firewall has fallback)
# nf-conntrack-ipv6: For IPv6 connection tracking (kernel 4.x only, merged in 5.x)
RRECOMMENDS:${PN} = "kernel-module-xt-tcpudp \
                    "
# IPv6 connection tracking for kernel 4.x (merged into nf-conntrack in 5.x)
RRECOMMENDS:${PN} += "${@bb.utils.contains('PREFERRED_VERSION_linux-uclan', '4.4.35', 'kernel-module-nf-conntrack-ipv6', '', d)}"
RRECOMMENDS:${PN} += "${@bb.utils.contains('PREFERRED_VERSION_linux-octagon', '4.4.35', 'kernel-module-nf-conntrack-ipv6', '', d)}"
RRECOMMENDS:${PN} += "${@bb.utils.contains('PREFERRED_VERSION_linux-qviart', '4.4.35', 'kernel-module-nf-conntrack-ipv6', '', d)}"

# Conflicts with WireGuard plugins (both provide port protection)
RCONFLICTS:${PN} = "enigma2-plugin-extensions-wireguard-tnap enigma2-plugin-extensions-wireguard"

SRC_URI = "file://firewall.sh \
           file://firewall-monitor.sh \
           file://firewall.users \
           file://plugin.py \
           file://__init__.py \
          "

PV = "3.3"
PR = "r0"

S = "${WORKDIR}"

INITSCRIPT_NAME = "firewall"
INITSCRIPT_PARAMS = "start 02 2 3 4 5 . stop 01 0 1 6 ."

inherit update-rc.d

PLUGIN_INSTALL_PATH = "${libdir}/enigma2/python/Plugins/Extensions/FirewallSecurity"

do_install() {
	# Install init scripts and configuration
	install -d ${D}${sysconfdir}/init.d
	install -m 0755 ${WORKDIR}/firewall.sh ${D}${sysconfdir}/init.d/firewall
	install -m 0755 ${WORKDIR}/firewall-monitor.sh ${D}${sysconfdir}/init.d/firewall-monitor
	install -d ${D}${sysconfdir}
	install -m 0644 ${WORKDIR}/firewall.users ${D}${sysconfdir}/firewall.users

	# Install Python plugin
	install -d ${D}${PLUGIN_INSTALL_PATH}
	install -m 0644 ${WORKDIR}/plugin.py ${D}${PLUGIN_INSTALL_PATH}/plugin.py
	install -m 0644 ${WORKDIR}/__init__.py ${D}${PLUGIN_INSTALL_PATH}/__init__.py

	# Compile Python files
	python3 -m compileall ${D}${PLUGIN_INSTALL_PATH}
}

FILES:${PN} = "${sysconfdir}/init.d/firewall \
               ${sysconfdir}/init.d/firewall-monitor \
               ${sysconfdir}/firewall.users \
               ${PLUGIN_INSTALL_PATH} \
              "

# Mark firewall.users as a conffile to preserve user modifications across upgrades
CONFFILES:${PN} = "${sysconfdir}/firewall.users"

pkg_preinst:${PN}() {
#!/bin/sh
# Pre-installation script - runs before new package files are installed
# Perform clean upgrade: stop services, backup config, flush old rules

if [ -z "$D" ]; then
	# Running on target device (not during image build)
	echo "Preparing Firewall Security plugin installation..."

	# Backup firewall.users if it exists (will be restored by CONFFILES mechanism)
	if [ -f /etc/firewall.users ]; then
		echo "Backing up firewall.users configuration..."
		cp -f /etc/firewall.users /etc/firewall.users.upgrade-backup
	fi

	# Stop services if running
	if [ -f /etc/init.d/firewall-monitor ]; then
		echo "Stopping firewall-monitor service..."
		/etc/init.d/firewall-monitor stop 2>/dev/null || true
	fi

	if [ -f /etc/init.d/firewall ]; then
		echo "Stopping firewall service..."
		/etc/init.d/firewall stop 2>/dev/null || true
	fi

	# Flush all iptables rules to ensure clean slate
	if [ -x "$(which iptables)" ]; then
		echo "Flushing old firewall rules..."
		iptables -P INPUT ACCEPT 2>/dev/null || true
		iptables -P OUTPUT ACCEPT 2>/dev/null || true
		iptables -P FORWARD ACCEPT 2>/dev/null || true
		iptables -F 2>/dev/null || true
		iptables -X 2>/dev/null || true
	fi

	if [ -x "$(which ip6tables)" ]; then
		ip6tables -P INPUT ACCEPT 2>/dev/null || true
		ip6tables -P OUTPUT ACCEPT 2>/dev/null || true
		ip6tables -P FORWARD ACCEPT 2>/dev/null || true
		ip6tables -F 2>/dev/null || true
		ip6tables -X 2>/dev/null || true
	fi

	# Clean up old PID files
	rm -f /var/run/firewall-monitor.pid 2>/dev/null || true

	echo "System prepared for clean firewall installation."
fi
}

pkg_postinst:${PN}() {
#!/bin/sh
# Post-installation script - runs after new package files are installed
# Start firewall with new rules and verify configuration

if [ -z "$D" ]; then
	# Running on target device (not during image build)
	echo "==================================="
	echo "Firewall Security Plugin Installation"
	echo "==================================="

	# Verify firewall.users was preserved/restored
	if [ ! -f /etc/firewall.users ]; then
		echo "WARNING: /etc/firewall.users not found!"
		if [ -f /etc/firewall.users.upgrade-backup ]; then
			echo "Restoring from backup..."
			cp -f /etc/firewall.users.upgrade-backup /etc/firewall.users
		else
			echo "ERROR: No backup found. You may need to reconfigure whitelist!"
		fi
	fi

	# Clean up backup
	rm -f /etc/firewall.users.upgrade-backup 2>/dev/null || true

	# Ensure kernel modules are indexed (critical for first-time install)
	echo "Indexing kernel modules..."
	depmod -a 2>/dev/null || true

	# Wait for module database to be fully written (critical!)
	echo "Waiting for module database to be written..."
	sleep 5

	# Start firewall service with new rules
	echo "Starting firewall service with updated rules..."
	if /etc/init.d/firewall start; then
		echo "✓ Firewall started successfully"

		# Verify rules are loaded correctly
		RULE_COUNT=$(iptables -L INPUT -n | grep -c "^[A-Z]" || echo "0")
		if [ "$RULE_COUNT" -gt 10 ]; then
			echo "✓ Firewall rules loaded correctly ($RULE_COUNT rules)"
		else
			echo "⚠ WARNING: Firewall may not have loaded correctly (only $RULE_COUNT rules)"
		fi
	else
		echo "✗ ERROR: Firewall failed to start!"
		echo "   Please check /var/log/messages for errors"
	fi

	# Extract version from script
	VERSION=$(grep '^# Version:' /etc/init.d/firewall | head -n 1 | sed 's/.*Version: //' | cut -d' ' -f1)

	echo "==================================="
	echo "Installation Complete"
	echo "Version: $VERSION"
	echo "==================================="
	echo ""
	echo "IMPORTANT: System will reboot in 5 seconds..."
	echo ""
	echo "After reboot:"
	echo "  1. Plugin will appear in Extensions menu"
	echo "  2. Firewall will auto-start with self-healing"
	echo "  3. Check whitelist: cat /etc/firewall.users"
	echo "  4. Add networks if needed (VPN, cellular)"
	echo ""
	echo "Rebooting in 5 seconds..."
	sleep 5
	reboot
fi
}

pkg_prerm:${PN}() {
#!/bin/sh
# Pre-removal script - runs before package files are deleted
# Stop services and clean up firewall rules

echo "Stopping Firewall Security plugin..."

# Stop firewall-monitor service if running
if [ -f /etc/init.d/firewall-monitor ]; then
	/etc/init.d/firewall-monitor stop 2>/dev/null || true
fi

# Stop firewall service and flush rules
if [ -f /etc/init.d/firewall ]; then
	/etc/init.d/firewall stop 2>/dev/null || true
fi

# Ensure iptables rules are flushed (in case stop didn't work)
if [ -x "$(which iptables)" ]; then
	iptables -P INPUT ACCEPT 2>/dev/null || true
	iptables -P OUTPUT ACCEPT 2>/dev/null || true
	iptables -P FORWARD ACCEPT 2>/dev/null || true
	iptables -F 2>/dev/null || true
	iptables -X 2>/dev/null || true
	echo "Firewall rules flushed."
fi

# Kill any remaining firewall-monitor processes
if [ -f /var/run/firewall-monitor.pid ]; then
	kill $(cat /var/run/firewall-monitor.pid) 2>/dev/null || true
fi
pkill -f "firewall-monitor.sh" 2>/dev/null || true

echo "Firewall Security services stopped."
}

pkg_postrm:${PN}() {
#!/bin/sh
# Post-removal script - runs after package files are deleted
# Clean up init script symlinks and runtime files

echo "Cleaning up Firewall Security plugin..."

# Remove init script symlinks (update-rc.d removes creates these)
# We need to manually clean them up
rm -f /etc/rc0.d/*firewall* 2>/dev/null || true
rm -f /etc/rc1.d/*firewall* 2>/dev/null || true
rm -f /etc/rc2.d/*firewall* 2>/dev/null || true
rm -f /etc/rc3.d/*firewall* 2>/dev/null || true
rm -f /etc/rc4.d/*firewall* 2>/dev/null || true
rm -f /etc/rc5.d/*firewall* 2>/dev/null || true
rm -f /etc/rc6.d/*firewall* 2>/dev/null || true
rm -f /etc/rcS.d/*firewall* 2>/dev/null || true

# Remove runtime files
rm -f /var/log/firewall-attempts.log 2>/dev/null || true
rm -f /var/log/firewall-attempts.log.1 2>/dev/null || true
rm -f /var/log/firewall-attempts.log.2 2>/dev/null || true
rm -f /var/log/firewall-attempts.log.3 2>/dev/null || true
rm -f /var/run/firewall-monitor.pid 2>/dev/null || true

# Remove Python cache files (if any remain)
rm -rf /usr/lib/enigma2/python/Plugins/Extensions/FirewallSecurity/__pycache__ 2>/dev/null || true
rm -f /usr/lib/enigma2/python/Plugins/Extensions/FirewallSecurity/*.pyc 2>/dev/null || true
rm -f /usr/lib/enigma2/python/Plugins/Extensions/FirewallSecurity/*.pyo 2>/dev/null || true

# Remove plugin directory if empty (FILES:${PN} should have removed content, but just in case)
rmdir /usr/lib/enigma2/python/Plugins/Extensions/FirewallSecurity 2>/dev/null || true

echo "Firewall Security plugin cleanup complete."
echo "NOTE: /etc/firewall.users has been preserved with your configuration."
echo "      Backup is available at /etc/firewall.users.bak if needed."
}

do_package_qa() {
}

