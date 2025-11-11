#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Firewall Security Plugin for Enigma2
Provides GUI interface for managing iptables-based firewall

Author: Claude (Anthropic AI Assistant)
Model: claude-sonnet-4-5-20250929
Version: 1.0
Date: 2025-10-08
Python: 3.12+
"""

from Components.Label import Label
from Components.ScrollLabel import ScrollLabel
from Screens.Screen import Screen
from Screens.MessageBox import MessageBox
from Screens.VirtualKeyBoard import VirtualKeyBoard
from Components.ActionMap import ActionMap
from Components.config import ConfigText, getConfigListEntry, NoSave
from Components.ConfigList import ConfigListScreen
from Plugins.Plugin import PluginDescriptor
from enigma import eTimer, gRGB
import os
import subprocess
import re

class FirewallManager(Screen):
	"""Main Firewall Management Screen"""

	skin = """
		<screen name="FirewallManager" position="center,center" size="1280,720" title="Firewall Security Manager">
			<!-- Title -->
			<widget name="title" position="20,10" size="1240,50" font="Regular;38" foregroundColor="#00ffc000" halign="center"/>

			<!-- Status Section -->
			<widget name="status_label" position="20,80" size="250,40" font="Regular;28" text="Status:"/>
			<widget name="status" position="280,80" size="960,40" font="Regular;28" foregroundColor="#FFFFFF"/>

			<!-- Statistics -->
			<widget name="stats_label" position="20,130" size="250,40" font="Regular;28" text="Statistics:"/>
			<widget name="stats" position="280,130" size="960,40" font="Regular;26" foregroundColor="#00FFFF"/>

			<!-- Configuration -->
			<widget name="config_label" position="20,180" size="1240,40" font="Regular;28" text="Allowed Networks (/etc/firewall.users):"/>
			<widget name="config" position="20,230" size="1240,280" font="Regular;24" foregroundColor="#FFD700"/>

			<!-- Active Rules -->
			<widget name="rules_label" position="20,520" size="1240,30" font="Regular;26" text="Active Firewall Rules:"/>
			<widget name="rules_count" position="20,555" size="1240,25" font="Regular;22" foregroundColor="#00FF00"/>

			<!-- Action Buttons -->
			<ePixmap pixmap="skin_default/buttons/green.png" position="50,620" size="200,50" alphatest="on"/>
			<widget name="key_green" position="50,680" size="200,35" valign="center" halign="center" font="Regular;28" transparent="1" text="Start"/>

			<ePixmap pixmap="skin_default/buttons/red.png" position="280,620" size="200,50" alphatest="on"/>
			<widget name="key_red" position="280,680" size="200,35" valign="center" halign="center" font="Regular;28" transparent="1" text="Stop"/>

			<ePixmap pixmap="skin_default/buttons/yellow.png" position="510,620" size="200,50" alphatest="on"/>
			<widget name="key_yellow" position="510,680" size="200,35" valign="center" halign="center" font="Regular;28" transparent="1" text="Edit Config"/>

			<ePixmap pixmap="skin_default/buttons/blue.png" position="740,620" size="200,50" alphatest="on"/>
			<widget name="key_blue" position="740,680" size="200,35" valign="center" halign="center" font="Regular;28" transparent="1" text="Connections"/>

			<ePixmap pixmap="skin_default/buttons/key_menu.png" position="970,620" size="200,50" alphatest="on"/>
			<widget name="key_menu" position="970,680" size="200,35" valign="center" halign="center" font="Regular;28" transparent="1" text="Monitor"/>
		</screen>
	"""

	def __init__(self, session):
		Screen.__init__(self, session)
		self.session = session

		# UI Labels
		self["title"] = Label("Firewall Security Manager")
		self["status_label"] = Label("Status:")
		self["status"] = Label("")
		self["stats_label"] = Label("Statistics:")
		self["stats"] = Label("")
		self["config_label"] = Label("Allowed Networks (/etc/firewall.users):")
		self["config"] = ScrollLabel("")
		self["rules_label"] = Label("Active Firewall Rules:")
		self["rules_count"] = Label("")

		# Button Labels
		self["key_green"] = Label("Start")
		self["key_red"] = Label("Stop")
		self["key_yellow"] = Label("Edit Config")
		self["key_blue"] = Label("Connections")
		self["key_menu"] = Label("Monitor")

		# Key Bindings
		self["actions"] = ActionMap(["ColorActions", "SetupActions", "DirectionActions", "MenuActions"], {
			"green": self.startFirewall,
			"red": self.stopFirewall,
			"yellow": self.editConfig,
			"blue": self.showConnections,
			"menu": self.showMonitor,
			"cancel": self.close,
			"ok": self.showConnections,
			"up": self.scrollUp,
			"down": self.scrollDown,
		}, -2)

		# Timer for auto-refresh
		self.timer = eTimer()
		self.timer.callback.append(self.updateDisplay)

		# Initial display update
		self.onLayoutFinish.append(self.updateDisplay)

		# Start auto-refresh (every 10 seconds)
		self.timer.start(10000, False)

	def scrollUp(self):
		"""Scroll configuration text up"""
		self["config"].pageUp()

	def scrollDown(self):
		"""Scroll configuration text down"""
		self["config"].pageDown()

	def runCommand(self, cmd):
		"""Execute shell command and return output"""
		try:
			result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
			return result.stdout.strip(), result.returncode
		except subprocess.TimeoutExpired:
			return "Command timeout", 1
		except Exception as e:
			return f"Error: {str(e)}", 1

	def getFirewallStatus(self):
		"""Check if firewall is active (blocking mode, not just monitor mode)"""
		# Method 1: Check INPUT chain policy - firewall uses DROP policy
		output, code = self.runCommand("iptables -L INPUT -n | head -1")
		if "policy DROP" in output:
			return True

		# Method 2: Check if there are actual DROP or REJECT rules
		# (Monitor only uses ACCEPT and LOG rules, firewall uses DROP/REJECT)
		output, code = self.runCommand("iptables -L INPUT -n | grep -E '(DROP|REJECT)'")
		if output.strip():  # If there are any DROP or REJECT rules
			return True

		return False

	def getFirewallStats(self):
		"""Get firewall statistics - show rule count and allowed networks"""
		# Count active ACCEPT rules in INPUT chain
		rules_output, code = self.runCommand("iptables -L INPUT -n | grep -c 'ACCEPT\\|DROP\\|REJECT'")
		rule_count = int(rules_output.strip()) if code == 0 and rules_output.strip().isdigit() else 0

		# Count allowed networks from config file
		network_count = 0
		config_file = "/etc/firewall.users"
		if os.path.exists(config_file):
			try:
				with open(config_file, 'r') as f:
					for line in f:
						line = line.strip()
						# Count non-comment, non-empty lines
						if line and not line.startswith('#'):
							network_count += 1
			except:
				pass

		return f"Active Rules: {rule_count} | Allowed Networks: {network_count}", rule_count, network_count

	def getAllowedNetworks(self):
		"""Read allowed networks from configuration file"""
		config_file = "/etc/firewall.users"
		try:
			if os.path.exists(config_file):
				with open(config_file, 'r') as f:
					lines = f.readlines()

				# Filter out comments and empty lines, format nicely
				networks = []
				for line in lines:
					line = line.strip()
					if line and not line.startswith('#'):
						# Split on first whitespace to separate IP from comment
						parts = line.split(None, 1)
						if parts:
							ip = parts[0]
							comment = parts[1] if len(parts) > 1 else ""
							# Remove inline comments
							if '#' in comment:
								comment = comment.split('#', 1)[1].strip()
							networks.append(f"[OK] {ip:<25} {comment}")

				if networks:
					return "\n".join(networks)
				else:
					return "No networks configured\n(Default: Block all incoming)"
			else:
				return f"Configuration file not found:\n{config_file}"
		except Exception as e:
			return f"Error reading configuration:\n{str(e)}"

	def getActiveRules(self):
		"""Get count of active iptables rules"""
		output, code = self.runCommand("iptables -L INPUT -n | grep -c 'ACCEPT\\|DROP\\|REJECT'")
		if code == 0 and output.isdigit():
			return int(output)
		return 0

	def updateDisplay(self):
		"""Update all display elements"""
		# Check firewall status
		is_active = self.getFirewallStatus()

		if is_active:
			self["status"].setText("ACTIVE - Firewall is protecting your receiver")
			try:
				self["status"].instance.setForegroundColor(gRGB(0x00FF00))  # Green
			except:
				pass
		else:
			self["status"].setText("INACTIVE - Receiver is EXPOSED to internet!")
			try:
				self["status"].instance.setForegroundColor(gRGB(0xFF0000))  # Red
			except:
				pass

		# Get statistics
		stats_text, rule_count, dropped = self.getFirewallStats()
		self["stats"].setText(stats_text)

		# Get allowed networks
		networks = self.getAllowedNetworks()
		self["config"].setText(networks)

		# Get active rules count
		active_rules = self.getActiveRules()
		self["rules_count"].setText(f"{active_rules} rules active ({rule_count} ACCEPT rules)")

	def startFirewall(self):
		"""Start the firewall"""
		output, code = self.runCommand("/etc/init.d/firewall start")

		# Delayed update to allow iptables to finish
		from enigma import eTimer
		self.startTimer = eTimer()
		self.startTimer.callback.append(self.updateDisplay)
		self.startTimer.start(1500, True)  # Update after 1.5 seconds

		if code == 0:
			self.session.open(MessageBox, "Firewall started successfully!\n\nYour receiver is now protected.", MessageBox.TYPE_INFO, timeout=3)
		else:
			self.session.open(MessageBox, f"Failed to start firewall!\n\n{output}", MessageBox.TYPE_ERROR, timeout=5)

	def stopFirewall(self):
		"""Stop the firewall after confirmation"""
		self.session.openWithCallback(
			self.stopFirewallConfirmed,
			MessageBox,
			"WARNING!\n\nStopping the firewall will expose your receiver to the internet!\n\nAnyone with your IP address will be able to access your receiver.\n\nAre you sure you want to disable the firewall?",
			MessageBox.TYPE_YESNO
		)

	def stopFirewallConfirmed(self, answer):
		"""Actually stop the firewall after confirmation"""
		if answer:
			output, code = self.runCommand("/etc/init.d/firewall stop")

			# Force update after a short delay to ensure iptables changes are reflected
			from enigma import eTimer
			self.stopTimer = eTimer()
			self.stopTimer.callback.append(self.updateDisplay)
			self.stopTimer.start(1500, True)  # Update after 1.5 seconds

			if code == 0:
				self.session.open(MessageBox, "Firewall stopped!\n\nWARNING: Your receiver is now EXPOSED to the internet!", MessageBox.TYPE_WARNING, timeout=5)
			else:
				self.session.open(MessageBox, f"Failed to stop firewall!\n\n{output}", MessageBox.TYPE_ERROR, timeout=5)

	def editConfig(self):
		"""Open the firewall configuration editor"""
		try:
			self.session.openWithCallback(self.editConfigCallback, FirewallConfigEditor)
		except Exception as e:
			self.session.open(MessageBox, f"Failed to open config editor:\n\n{str(e)}", MessageBox.TYPE_ERROR, timeout=5)

	def editConfigCallback(self, answer):
		"""Callback after config editor closes"""
		if answer:
			# Config was modified, ask if user wants to restart firewall
			self.session.openWithCallback(
				self.restartAfterEdit,
				MessageBox,
				"Configuration saved!\n\nRestart firewall to apply changes?",
				MessageBox.TYPE_YESNO
			)
		# Update display regardless
		self.updateDisplay()

	def restartAfterEdit(self, answer):
		"""Restart firewall after config edit"""
		if answer:
			output, code = self.runCommand("/etc/init.d/firewall restart")

			# Delayed update to allow iptables to finish
			from enigma import eTimer
			self.restartTimer = eTimer()
			self.restartTimer.callback.append(self.updateDisplay)
			self.restartTimer.start(1500, True)  # Update after 1.5 seconds

			if code == 0:
				self.session.open(MessageBox, "Firewall restarted successfully!\n\nNew configuration active.", MessageBox.TYPE_INFO, timeout=3)
			else:
				self.session.open(MessageBox, f"Failed to restart firewall!\n\n{output}", MessageBox.TYPE_ERROR, timeout=5)

	def showConnections(self):
		"""Show active network connections"""
		try:
			self.session.open(FirewallConnections)
		except Exception as e:
			self.session.open(MessageBox, f"Failed to open connections:\n\n{str(e)}", MessageBox.TYPE_ERROR, timeout=5)

	def showMonitor(self):
		"""Show intrusion monitor"""
		try:
			self.session.open(FirewallMonitorLog)
		except Exception as e:
			self.session.open(MessageBox, f"Failed to open monitor:\n\n{str(e)}", MessageBox.TYPE_ERROR, timeout=5)

	def close(self):
		"""Close screen and stop timer"""
		self.timer.stop()
		Screen.close(self)


class FirewallConnections(Screen):
	"""Active Network Connections Viewer"""

	skin = """
		<screen name="FirewallConnections" position="center,center" size="1400,800" title="Active Network Connections">
			<widget name="title" position="20,10" size="1360,50" font="Regular;36" foregroundColor="#00ffc000" halign="center"/>
			<widget name="stats" position="20,70" size="1360,80" font="Regular;26" foregroundColor="#FFD700"/>
			<widget name="connections" position="20,160" size="1360,560" font="Regular;20" foregroundColor="#FFFFFF"/>
			<widget name="info" position="20,730" size="1360,30" font="Regular;20" foregroundColor="#00FFFF" halign="center"/>
		</screen>
	"""

	def __init__(self, session):
		Screen.__init__(self, session)
		self.session = session

		self["title"] = Label("Active Network Connections")
		self["stats"] = Label("")
		self["connections"] = ScrollLabel("")
		self["info"] = Label("GREEN=Refresh | YELLOW=Full Details | UP/DOWN=Scroll | OK/EXIT=Close")

		self["actions"] = ActionMap(["ColorActions", "SetupActions", "DirectionActions"], {
			"cancel": self.close,
			"ok": self.close,
			"green": self.refresh,
			"yellow": self.showFullDetails,
			"up": self.scrollUp,
			"down": self.scrollDown,
		}, -2)

		# Auto-refresh timer
		self.timer = eTimer()
		self.timer.callback.append(self.refresh)

		self.onLayoutFinish.append(self.refresh)
		self.timer.start(5000, False)  # Refresh every 5 seconds

	def scrollUp(self):
		self["connections"].pageUp()

	def scrollDown(self):
		self["connections"].pageDown()

	def runCommand(self, cmd):
		"""Execute shell command and return output"""
		try:
			result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
			return result.stdout.strip(), result.returncode
		except:
			return "Error executing command", 1

	def refresh(self):
		"""Refresh connection display"""
		connections = []
		stats = {}

		# Check if conntrack is available
		conntrack_available, code = self.runCommand("which conntrack")

		if code == 0 and conntrack_available:
			# Use conntrack for detailed connection tracking
			output, code = self.runCommand("conntrack -L 2>/dev/null")
			if code == 0 and output:
				# Parse conntrack output
				lines = output.split('\n')

				# Group by source IP
				ip_connections = {}
				for line in lines:
					if not line.strip():
						continue

					# Extract source IP (look for src=X.X.X.X pattern)
					src_match = re.search(r'src=([0-9.]+)', line)
					if src_match:
						src_ip = src_match.group(1)

						# Skip loopback
						if src_ip.startswith('127.'):
							continue

						# Extract protocol and destination
						proto = "unknown"
						if 'tcp' in line:
							proto = "TCP"
						elif 'udp' in line:
							proto = "UDP"
						elif 'icmp' in line:
							proto = "ICMP"

						# Extract destination port if exists
						dport_match = re.search(r'dport=(\d+)', line)
						dport = dport_match.group(1) if dport_match else "N/A"

						# Track by IP
						if src_ip not in ip_connections:
							ip_connections[src_ip] = []
						ip_connections[src_ip].append(f"{proto}:{dport}")

				# Format output
				stats['total'] = len(lines)
				stats['unique_ips'] = len(ip_connections)

				if ip_connections:
					connections.append("CONNECTED DEVICES:")
					connections.append("=" * 80)
					connections.append("")

					for ip, conn_list in sorted(ip_connections.items()):
						# Get hostname if possible
						hostname_output, _ = self.runCommand(f"getent hosts {ip} | awk '{{print $2}}'")
						hostname = hostname_output if hostname_output else "Unknown"

						connections.append(f"IP: {ip:<15}  Hostname: {hostname}")
						connections.append(f"   Connections: {len(conn_list)}")

						# Show unique protocols/ports
						unique_conns = list(set(conn_list))[:5]  # Limit to 5 unique
						for conn in unique_conns:
							connections.append(f"     - {conn}")

						if len(conn_list) > 5:
							connections.append(f"     ... and {len(conn_list) - 5} more")
						connections.append("")
				else:
					connections.append("No active connections from external sources")
					connections.append("")
					connections.append("This is normal if:")
					connections.append("  - No devices are accessing the receiver")
					connections.append("  - All traffic is outbound only")
			else:
				connections.append("Connection tracking not available")
				connections.append("(Firewall may not be running)")
		else:
			# Fallback to netstat if conntrack not available
			output, code = self.runCommand("netstat -tn 2>/dev/null | grep ESTABLISHED")
			if code == 0 and output:
				lines = output.split('\n')

				# Group by foreign address
				ip_connections = {}
				for line in lines:
					parts = line.split()
					if len(parts) >= 5:
						foreign = parts[4]
						foreign_ip = foreign.split(':')[0]

						# Skip loopback
						if foreign_ip.startswith('127.'):
							continue

						if foreign_ip not in ip_connections:
							ip_connections[foreign_ip] = 0
						ip_connections[foreign_ip] += 1

				stats['total'] = len(lines)
				stats['unique_ips'] = len(ip_connections)

				if ip_connections:
					connections.append("CONNECTED DEVICES (via netstat):")
					connections.append("=" * 80)
					connections.append("")

					for ip, count in sorted(ip_connections.items()):
						connections.append(f"IP: {ip:<15}  Connections: {count}")
					connections.append("")
					connections.append("NOTE: Install conntrack-tools for more details")
				else:
					connections.append("No established connections")
			else:
				connections.append("No network tools available")
				connections.append("Install conntrack-tools or net-tools")

		# Update display
		if stats:
			stats_text = f"Total Connections: {stats.get('total', 0)} | Unique IPs: {stats.get('unique_ips', 0)}"
		else:
			stats_text = "Connection monitoring ready"

		self["stats"].setText(stats_text)
		self["connections"].setText("\n".join(connections) if connections else "No data available")

	def showFullDetails(self):
		"""Show full connection details"""
		output, code = self.runCommand("conntrack -L 2>/dev/null || netstat -tn")
		if code == 0:
			self.session.open(MessageBox, output, MessageBox.TYPE_INFO, timeout=15)
		else:
			self.session.open(MessageBox, "Connection tracking not available", MessageBox.TYPE_INFO, timeout=3)

	def close(self):
		"""Close screen and stop timer"""
		self.timer.stop()
		Screen.close(self)


class FirewallDetails(Screen):
	"""Detailed Firewall Rules Viewer"""

	skin = """
		<screen name="FirewallDetails" position="center,center" size="1400,800" title="Firewall Rules Details">
			<widget name="title" position="20,10" size="1360,50" font="Regular;36" foregroundColor="#00ffc000" halign="center"/>
			<widget name="details" position="20,70" size="1360,650" font="Regular;22" foregroundColor="#FFFFFF"/>
			<widget name="info" position="20,730" size="1360,30" font="Regular;20" foregroundColor="#FFD700" halign="center"/>
		</screen>
	"""

	def __init__(self, session):
		Screen.__init__(self, session)
		self.session = session

		self["title"] = Label("Firewall Rules Details")
		self["details"] = ScrollLabel("")
		self["info"] = Label("Press UP/DOWN to scroll, OK/EXIT to close")

		self["actions"] = ActionMap(["SetupActions", "DirectionActions"], {
			"cancel": self.close,
			"ok": self.close,
			"up": self.scrollUp,
			"down": self.scrollDown,
		}, -2)

		self.onLayoutFinish.append(self.loadDetails)

	def scrollUp(self):
		self["details"].pageUp()

	def scrollDown(self):
		self["details"].pageDown()

	def runCommand(self, cmd):
		"""Execute shell command and return output"""
		try:
			result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
			return result.stdout.strip()
		except:
			return "Error executing command"

	def loadDetails(self):
		"""Load detailed firewall information"""
		details = []

		# Section 1: INPUT chain rules
		details.append("=" * 70)
		details.append("INPUT CHAIN RULES (Incoming Traffic)")
		details.append("=" * 70)
		output = self.runCommand("iptables -L INPUT -n -v --line-numbers")
		details.append(output)
		details.append("")

		# Section 2: Loaded netfilter modules
		details.append("=" * 70)
		details.append("LOADED NETFILTER MODULES")
		details.append("=" * 70)
		output = self.runCommand("lsmod | grep -E 'nf_conntrack|xt_|ip_tables|iptable' | awk '{print $1, $2, $3}'")
		if output:
			details.append(output)
		else:
			details.append("No netfilter modules loaded")
		details.append("")

		# Section 3: Configuration file
		details.append("=" * 70)
		details.append("ALLOWED NETWORKS (/etc/firewall.users)")
		details.append("=" * 70)
		try:
			with open("/etc/firewall.users", 'r') as f:
				config = f.read()
			details.append(config)
		except:
			details.append("Error reading configuration file")
		details.append("")

		# Section 4: Connection tracking
		details.append("=" * 70)
		details.append("CONNECTION TRACKING STATISTICS")
		details.append("=" * 70)
		output = self.runCommand("cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo 'N/A'")
		details.append(f"Active connections: {output}")
		output = self.runCommand("cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo 'N/A'")
		details.append(f"Maximum connections: {output}")

		self["details"].setText("\n".join(details))


class FirewallMonitorLog(Screen):
	"""Intrusion Attempt Log Viewer"""

	skin = """
		<screen name="FirewallMonitorLog" position="center,center" size="1400,800" title="Intrusion Attempts Log">
			<widget name="title" position="20,10" size="1360,50" font="Regular;36" foregroundColor="#00ffc000" halign="center"/>
			<widget name="stats" position="20,70" size="1360,80" font="Regular;24" foregroundColor="#FFD700"/>
			<widget name="log" position="20,160" size="1360,560" font="Regular;20" foregroundColor="#FFFFFF"/>
			<widget name="info" position="20,730" size="1360,30" font="Regular;20" foregroundColor="#00FFFF" halign="center"/>
		</screen>
	"""

	def __init__(self, session):
		Screen.__init__(self, session)
		self.session = session

		self["title"] = Label("Intrusion Attempts Monitor")
		self["stats"] = Label("")
		self["log"] = ScrollLabel("")
		self["info"] = Label("GREEN=Refresh | RED=Rotate | YELLOW=Stats | BLUE=Start/Stop | INFO=Clear | UP/DOWN=Scroll")

		self["actions"] = ActionMap(["ColorActions", "SetupActions", "DirectionActions", "InfobarEPGActions"], {
			"cancel": self.close,
			"ok": self.close,
			"green": self.refresh,
			"red": self.rotateLog,
			"yellow": self.showStats,
			"blue": self.toggleMonitor,
			"showEventInfo": self.clearLog,
			"up": self.scrollUp,
			"down": self.scrollDown,
		}, -2)

		self.onLayoutFinish.append(self.refresh)

	def scrollUp(self):
		self["log"].pageUp()

	def scrollDown(self):
		self["log"].pageDown()

	def runCommand(self, cmd):
		"""Execute shell command and return output"""
		try:
			result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
			return result.stdout.strip(), result.returncode
		except:
			return "Error executing command", 1

	def refresh(self):
		"""Refresh log display"""
		# Check if monitor is running
		output, code = self.runCommand("if [ -f /var/run/firewall-monitor.pid ] && kill -0 $(cat /var/run/firewall-monitor.pid) 2>/dev/null; then echo 'ACTIVE'; else echo 'INACTIVE'; fi")
		monitor_status = output.strip().upper()

		# Get log statistics
		log_file = "/var/log/firewall-attempts.log"
		if os.path.exists(log_file):
			with open(log_file, 'r') as f:
				lines = f.readlines()

			total = len(lines)
			if total > 0:
				# Get last 100 lines
				recent_lines = lines[-100:]
				log_text = "".join(recent_lines)
			else:
				log_text = "No intrusion attempts logged yet.\n\nMonitor is recording connection attempts to show what threats exist."
		else:
			total = 0
			if monitor_status == "INACTIVE":
				log_text = "MONITOR NOT RUNNING\n\nNo log file exists because the monitor has not been started.\n\nPress the BLUE button to start the monitor.\n\nThe monitor will log connection attempts even when the firewall is OFF,\nshowing you what threats exist on the internet."
			else:
				log_text = "Log file not found but monitor is running.\n\nWait a few moments for connection attempts to be logged."

		# Update display
		self["stats"].setText(f"Monitor Status: {monitor_status}\nTotal Logged Attempts: {total}")
		self["log"].setText(log_text)

	def rotateLog(self):
		"""Rotate the log file"""
		self.session.openWithCallback(
			self.rotateLogConfirmed,
			MessageBox,
			"Rotate the log file?\n\nCurrent log will be saved as firewall-attempts.log.1\nOlder logs shift to .2, .3 (max 3 old logs kept)",
			MessageBox.TYPE_YESNO
		)

	def rotateLogConfirmed(self, answer):
		if answer:
			output, code = self.runCommand("/etc/init.d/firewall-monitor rotate-log")
			if code == 0:
				self.session.open(MessageBox, "Log rotated successfully!\n\nOld log saved as firewall-attempts.log.1", MessageBox.TYPE_INFO, timeout=3)
			else:
				self.session.open(MessageBox, f"Failed to rotate log!\n\n{output}", MessageBox.TYPE_ERROR, timeout=3)
			self.refresh()

	def clearLog(self):
		"""Clear the log file"""
		self.session.openWithCallback(
			self.clearLogConfirmed,
			MessageBox,
			"Clear all logged intrusion attempts?\n\nThis will PERMANENTLY delete the entire log file.\n\nConsider using RED (Rotate) instead to save old logs.",
			MessageBox.TYPE_YESNO
		)

	def clearLogConfirmed(self, answer):
		if answer:
			output, code = self.runCommand("/etc/init.d/firewall-monitor clear-log")
			if code == 0:
				self.session.open(MessageBox, "Log cleared successfully!", MessageBox.TYPE_INFO, timeout=2)
			else:
				self.session.open(MessageBox, f"Failed to clear log!\n\n{output}", MessageBox.TYPE_ERROR, timeout=3)
			self.refresh()

	def showStats(self):
		"""Show statistics"""
		output, code = self.runCommand("/etc/init.d/firewall-monitor stats")
		if code == 0:
			self.session.open(MessageBox, output, MessageBox.TYPE_INFO, timeout=10)
		else:
			self.session.open(MessageBox, "No statistics available", MessageBox.TYPE_INFO, timeout=3)

	def toggleMonitor(self):
		"""Start or stop monitor"""
		# Check if monitor is actually running - use fresh status check
		output, code = self.runCommand("if [ -f /var/run/firewall-monitor.pid ] && kill -0 $(cat /var/run/firewall-monitor.pid) 2>/dev/null; then echo 'ACTIVE'; else echo 'INACTIVE'; fi")

		# Strip whitespace and check explicitly
		status = output.strip().upper()
		monitor_active = (status == "ACTIVE")

		if monitor_active:
			# Stop monitor
			self.session.openWithCallback(
				self.stopMonitorConfirmed,
				MessageBox,
				"Stop the Intrusion Monitor?\n\nThis will stop logging connection attempts.",
				MessageBox.TYPE_YESNO
			)
		else:
			# Start monitor
			output, code = self.runCommand("/etc/init.d/firewall-monitor start")
			if code == 0:
				self.session.open(MessageBox, "Monitor started!\n\nNOTE: Monitor logs attempts but does NOT block them.\nUse the firewall for actual protection.", MessageBox.TYPE_INFO, timeout=5)
			else:
				self.session.open(MessageBox, f"Failed to start monitor!\n\n{output}", MessageBox.TYPE_ERROR, timeout=5)
			self.refresh()

	def stopMonitorConfirmed(self, answer):
		if answer:
			output, code = self.runCommand("/etc/init.d/firewall-monitor stop")
			if code == 0:
				self.session.open(MessageBox, "Monitor stopped.", MessageBox.TYPE_INFO, timeout=2)
			else:
				self.session.open(MessageBox, f"Failed to stop monitor!\n\n{output}", MessageBox.TYPE_ERROR, timeout=3)
			self.refresh()


class FirewallConfigEditor(Screen, ConfigListScreen):
	"""Editor for /etc/firewall.users file"""

	skin = """
		<screen position="center,center" size="1200,700" title="Firewall Configuration Editor">
			<widget name="title" position="20,10" size="1160,50" font="Regular;36" foregroundColor="#00ffc000" halign="center"/>
			<widget name="file_location" position="20,65" size="1160,30" font="Regular;20" foregroundColor="#00FF00" halign="center"/>
			<widget name="info" position="20,100" size="1160,70" font="Regular;22" foregroundColor="#FFD700"/>
			<widget name="config" position="20,180" zPosition="1" size="1160,420" scrollbarMode="showOnDemand" transparent="0"/>
			<widget name="help" position="20,610" size="1160,40" font="Regular;20" foregroundColor="#00FFFF" halign="center"/>

			<ePixmap pixmap="skin_default/buttons/green.png" position="200,630" size="200,50" alphatest="on"/>
			<widget name="key_green" position="200,635" size="200,40" valign="center" halign="center" font="Regular;26" transparent="1" text="Save"/>

			<ePixmap pixmap="skin_default/buttons/red.png" position="420,630" size="200,50" alphatest="on"/>
			<widget name="key_red" position="420,635" size="200,40" valign="center" halign="center" font="Regular;26" transparent="1" text="Cancel"/>

			<ePixmap pixmap="skin_default/buttons/yellow.png" position="640,630" size="200,50" alphatest="on"/>
			<widget name="key_yellow" position="640,635" size="200,40" valign="center" halign="center" font="Regular;26" transparent="1" text="Keyboard"/>

			<ePixmap pixmap="skin_default/buttons/blue.png" position="860,630" size="200,50" alphatest="on"/>
			<widget name="key_blue" position="860,635" size="200,40" valign="center" halign="center" font="Regular;26" transparent="1" text="Add Entry"/>
		</screen>"""

	def __init__(self, session):
		Screen.__init__(self, session)
		self.session = session

		self.config_file = "/etc/firewall.users"

		self["title"] = Label("Firewall Allowed Networks Configuration")
		self["file_location"] = Label(f"Editing: {self.config_file}")
		self["info"] = Label("Add IP addresses or networks (one per line).\nUse CIDR notation: 192.168.1.0/24 for network, or 192.168.1.100 for single IP.")
		self["help"] = Label("GREEN=Save | RED=Cancel | YELLOW=Virtual Keyboard | BLUE=Add Entry")

		self["key_green"] = Label("Save")
		self["key_red"] = Label("Cancel")
		self["key_yellow"] = Label("Keyboard")
		self["key_blue"] = Label("Add Entry")

		self.entries = []
		self.config_items = []

		# Read current configuration
		self.loadConfig()

		# Build config list
		config_list = []
		for i, entry in enumerate(self.entries):
			config_list.append(getConfigListEntry(f"Entry {i+1}", entry['config']))
		self.config_items = config_list

		ConfigListScreen.__init__(self, config_list)

		self["actions"] = ActionMap(["ColorActions", "SetupActions"], {
			"green": self.saveConfig,
			"red": self.cancel,
			"yellow": self.openKeyboard,
			"blue": self.addEntry,
			"cancel": self.cancel,
		}, -2)

		self.modified = False

	def loadConfig(self):
		"""Load configuration from file"""
		self.entries = []

		try:
			if os.path.exists(self.config_file):
				with open(self.config_file, 'r') as f:
					lines = f.readlines()

				for line in lines:
					line = line.strip()
					# Skip comments and empty lines
					if line and not line.startswith('#'):
						# Extract IP/network and comment
						parts = line.split('#', 1)
						ip_part = parts[0].strip()
						comment_part = parts[1].strip() if len(parts) > 1 else ""

						# Create config entry with both IP and comment
						display_text = f"{ip_part:<25} # {comment_part}" if comment_part else ip_part
						config_obj = NoSave(ConfigText(fixed_size=False, default=display_text))
						self.entries.append({
							'config': config_obj,
							'original': line
						})
		except Exception as e:
			self.session.open(MessageBox, f"Error reading config file:\n{str(e)}", MessageBox.TYPE_ERROR, timeout=5)

		# Always have at least one empty entry for adding new
		if len(self.entries) == 0:
			self.addEmptyEntry()

	def addEmptyEntry(self):
		"""Add an empty entry for new IP/network"""
		config_obj = NoSave(ConfigText(fixed_size=False, default=""))
		self.entries.append({
			'config': config_obj,
			'original': ""
		})

	def addEntry(self):
		"""Add a new entry"""
		self.addEmptyEntry()
		self.updateConfigList()
		self.modified = True

	def updateConfigList(self):
		"""Update the config list display"""
		config_list = []
		for i, entry in enumerate(self.entries):
			config_list.append(getConfigListEntry(f"Entry {i+1}", entry['config']))
		self.config_items = config_list
		self["config"].list = config_list
		self["config"].l.setList(config_list)

	def openKeyboard(self):
		"""Open virtual keyboard for current entry"""
		sel = self["config"].getCurrent()
		if sel:
			current_entry = sel[1]
			self.session.openWithCallback(
				self.keyboardCallback,
				VirtualKeyBoard,
				title="Enter IP address or network (e.g., 192.168.1.0/24 or 192.168.1.100)",
				text=current_entry.value
			)

	def keyboardCallback(self, value):
		"""Callback from virtual keyboard"""
		if value is not None:
			sel = self["config"].getCurrent()
			if sel:
				sel[1].value = value
				self.modified = True
				self.updateConfigList()

	def saveConfig(self):
		"""Save configuration to file"""
		try:
			lines = []

			# Add header comment
			lines.append("# Firewall allowed hosts/networks configuration\n")
			lines.append("# Add one IP address, network range, or hostname per line\n")
			lines.append("# Lines starting with # are comments\n")
			lines.append("#\n")
			lines.append("# Examples:\n")
			lines.append("# 192.168.1.0/24         # Allow entire local network\n")
			lines.append("# 192.168.1.100          # Allow single IP\n")
			lines.append("# myhost.dyndns.org      # Allow hostname (resolved at firewall start)\n")
			lines.append("#\n")
			lines.append("# Configured entries:\n")
			lines.append("\n")

			# Add configured entries
			for entry in self.entries:
				value = entry['config'].value.strip()
				if value:  # Only save non-empty entries
					# Ensure proper formatting
					if '#' in value:
						# Already has comment
						lines.append(f"{value}\n")
					else:
						# Just IP/network, no comment
						lines.append(f"{value}\n")

			# Write to file
			with open(self.config_file, 'w') as f:
				f.writelines(lines)

			self.session.open(MessageBox, "Configuration saved successfully!", MessageBox.TYPE_INFO, timeout=2)
			self.close(True)

		except Exception as e:
			self.session.open(MessageBox, f"Error saving config file:\n{str(e)}", MessageBox.TYPE_ERROR, timeout=5)

	def cancel(self):
		"""Cancel editing"""
		if self.modified:
			self.session.openWithCallback(
				self.cancelConfirmed,
				MessageBox,
				"Configuration was modified.\n\nDiscard changes?",
				MessageBox.TYPE_YESNO
			)
		else:
			self.close(False)

	def cancelConfirmed(self, answer):
		"""Confirm cancel"""
		if answer:
			self.close(False)


def main(session, **kwargs):
	"""Plugin entry point"""
	session.open(FirewallManager)


def Plugins(**kwargs):
	"""Plugin descriptor for Enigma2"""
	return [
		PluginDescriptor(
			name="Firewall Security",
			description="Manage firewall protection for your receiver",
			where=[PluginDescriptor.WHERE_PLUGINMENU, PluginDescriptor.WHERE_EXTENSIONSMENU],
			icon="plugin.png",
			fnc=main
		)
	]
