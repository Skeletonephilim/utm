# Securing Devices and Home Network Using Kali Linux in a Compromised Environment

**A Forensic-Grade Recovery Guide for Mini PC Deployments**

---

## Table of Contents

1. [Introduction](#introduction)
2. [Threat Assessment](#threat-assessment)
3. [Kali Linux Deployment: VM vs. Mini PC](#kali-linux-deployment-vm-vs-mini-pc)
4. [Secure Kali Linux Setup](#secure-kali-linux-setup)
5. [GL.iNet Router Hardening](#glinet-router-hardening)
6. [TP-Link Mesh Router Hardening](#tp-link-mesh-router-hardening)
7. [Network Isolation Strategy](#network-isolation-strategy)
8. [macOS Forensics & Kext Detection](#macos-forensics--kext-detection)
9. [Packet Capture & Analysis](#packet-capture--analysis)
10. [MacBook Remediation](#macbook-remediation)
11. [Email & Yubico Key Setup](#email--yubico-key-setup)
12. [Cleanup and Account Security](#cleanup-and-account-security)
13. [Removable Media Safety](#removable-media-safety)
14. [Rebuilding Trusted Environment](#rebuilding-trusted-environment)
15. [Tools Reference](#tools-reference)
16. [UTM Integration Guide](#utm-integration-guide)

---

## Introduction

This guide provides a comprehensive, beginner-friendly roadmap for recovering from a heavily compromised home environment. It addresses:

- Persistent malware and rootkits
- Kernel-level rootkits/kexts on macOS
- Breached accounts and credentials
- Router and network compromise
- Identity theft scenarios

**Target Setup:**
- GL.iNet router
- MacBook (potentially compromised)
- Mini PC (deployment target for clean Kali Linux)
- Monitor, USB/SD/SIM media
- Two Yubico security keys
- Starlink internet connection

**Goal:** Rebuild a trusted digital environment from scratch while maintaining forensic soundness and chain-of-custody documentation.

---

## Threat Assessment

### Critical Threats

#### 1. Rootkits and Kernel-Level Compromise
- **macOS Kernel Extensions (kexts):** Malicious kernel extensions can hide processes, intercept system calls, and persist through reboots
- **Firmware-level persistence:** UEFI/BIOS rootkits survive OS reinstalls
- **Boot sector malware:** MBR/GPT tampering can load malware before the OS

#### 2. Network and Router Compromise
- **DNS hijacking:** Redirecting traffic to malicious servers
- **Firmware backdoors:** Compromised router firmware with persistent access
- **Man-in-the-middle attacks:** Intercepting and modifying traffic
- **Lateral movement:** Attackers using compromised router to target all connected devices

#### 3. Credential Theft
- **Password database compromise:** All stored passwords may be stolen
- **Session token theft:** Active sessions hijacked
- **2FA bypass:** SIM swapping, social engineering, or malware intercepting codes

#### 4. Removable Media Infection
- **USB-borne malware:** BadUSB, firmware-level infections
- **SD card exploits:** Malicious file systems or autorun payloads
- **SIM card compromise:** Cloning, data exfiltration

### Response Strategy

1. **Assume total compromise** - treat all devices as untrusted
2. **Build clean foundation first** - deploy isolated Kali system before analysis
3. **Maintain air-gaps** - physical network isolation during critical phases
4. **Document everything** - forensic chain-of-custody for potential legal action
5. **Never trust, always verify** - validate all downloads, firmware, and software

---

## Kali Linux Deployment: VM vs. Mini PC

### Comparison Matrix

| Factor | Bare-Metal Mini PC | Virtual Machine |
|--------|-------------------|-----------------|
| **Security Isolation** | ✅ Complete isolation from compromised systems | ⚠️ Depends on host OS trustworthiness |
| **Hardware Access** | ✅ Direct access to network cards, USB | ❌ Limited, requires passthrough |
| **Performance** | ✅ Full hardware resources | ⚠️ Shared resources, overhead |
| **Network Analysis** | ✅ Promiscuous mode, raw packet access | ⚠️ Depends on VM network configuration |
| **Forensic Soundness** | ✅ Clean chain-of-custody | ❌ Host compromise could taint analysis |
| **Boot Trust** | ✅ Control full boot process | ❌ Relies on compromised host |
| **Persistence Risk** | ✅ Isolated from infected systems | ⚠️ VM escape vulnerabilities exist |
| **Cost** | ~$200-400 for mini PC | ~$0 (uses existing hardware) |

### Recommendation

**Use bare-metal mini PC for compromised environments:**

In a hostile environment where rootkits and kernel-level compromise are suspected:

1. **Virtual machines are NOT safe** - the host OS may be compromised, allowing attackers to:
   - Monitor VM activity
   - Modify VM memory
   - Escape VM isolation
   - Tamper with forensic evidence

2. **Bare-metal provides:**
   - Hardware-level isolation
   - Trustworthy boot process
   - Direct network hardware access for analysis
   - Clean forensic foundation

**Use VM only for:**
- Learning and practice on trusted systems
- Post-recovery analysis in controlled environment
- Testing configurations before deployment

---

## Secure Kali Linux Setup

### Prerequisites

- Clean network for initial download (use public WiFi or cellular, NOT compromised home network)
- USB drive (8GB+) for installation media
- Mini PC with UEFI boot support

### Step 1: Obtain Kali Linux ISO

**From a trusted network location (NOT your compromised home network):**

```bash
# Download from official source
wget https://cdimage.kali.org/kali-2024.4/kali-linux-2024.4-installer-amd64.iso

# Download SHA256 checksum
wget https://cdimage.kali.org/kali-2024.4/SHA256SUMS

# Verify integrity
sha256sum -c SHA256SUMS 2>&1 | grep OK
```

**Verification is critical** - compromised ISOs are a common attack vector.

### Step 2: Create Bootable USB

**On Linux/macOS:**
```bash
# Identify USB device (be VERY careful - wrong device = data loss)
lsblk  # or diskutil list on macOS

# Write ISO to USB (replace /dev/sdX with your USB device)
sudo dd if=kali-linux-2024.4-installer-amd64.iso of=/dev/sdX bs=4M status=progress && sync
```

**On Windows:**
- Use Rufus (https://rufus.ie/)
- Select ISO
- Use DD mode
- Write to USB

**Alternative:** Use Etcher (https://etcher.balena.io/) - cross-platform, user-friendly

### Step 3: BIOS/UEFI Configuration

1. **Enter BIOS setup** (typically F2, F10, F12, or Del during boot)
2. **Disable Secure Boot** - required for Kali Linux
3. **Set boot priority** - USB first
4. **Enable virtualization** (VT-x/AMD-V) if available
5. **Save and reboot**

### Step 4: Install Kali Linux

**Installation Options:**

1. **Graphical Install** (recommended for beginners)
2. **Standard partition layout** or **Full Disk Encryption (LUKS)**

**Full Disk Encryption (Recommended):**
- Protects data at rest
- Requires passphrase on each boot
- Essential if device might be stolen

**Installation Steps:**

1. Boot from USB
2. Select "Graphical Install"
3. Choose language, location, keyboard layout
4. Configure network (or skip if air-gapping initially)
5. Set hostname: `kali-forensic` (or similar)
6. Set domain: leave blank or use `.local`
7. **Set root password:** Use strong, unique password
8. **Create non-root user:** Essential for security
9. Partition disks:
   - Use entire disk
   - All files in one partition (simplest)
   - Or use LVM with encryption (recommended)
10. Select software: Desktop environment + default tools
11. Install GRUB bootloader to primary drive
12. Complete installation and reboot

### Step 5: Initial Hardening

**After first boot, as root or with sudo:**

```bash
# Update system
apt update && apt upgrade -y

# Install security updates
apt dist-upgrade -y

# Create non-root user (if not done during install)
useradd -m -s /bin/bash -G sudo forensic
passwd forensic

# Disable root SSH login
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config
systemctl restart sshd

# Enable UFW firewall
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp  # Only if you need SSH
ufw enable

# Install essential tools (if not already present)
apt install -y nmap wireshark tcpdump rkhunter chkrootkit lynis

# Configure automatic security updates (optional)
apt install -y unattended-upgrades
dpkg-reconfigure -plow unattended-upgrades
```

### Step 6: Advanced Hardening (Optional)

#### Rootkit Detection

```bash
# Install and run rootkit scanners
apt install -y rkhunter chkrootkit lynis

# Update rkhunter database
rkhunter --update
rkhunter --propupd

# Scan system
rkhunter --check --skip-keypress

# Check for rootkits with chkrootkit
chkrootkit

# Comprehensive system audit with lynis
lynis audit system
```

#### Audit Logging

```bash
# Install auditd for comprehensive logging
apt install -y auditd audispd-plugins

# Enable and start auditd
systemctl enable auditd
systemctl start auditd

# View audit logs
ausearch -m avc -ts recent
```

#### Application Sandboxing

```bash
# Install Firejail for application sandboxing
apt install -y firejail

# Run applications in sandbox
firejail firefox
firejail wireshark
```

#### File Integrity Monitoring

```bash
# Install AIDE (Advanced Intrusion Detection Environment)
apt install -y aide

# Initialize AIDE database
aideinit

# Move database to active location
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Check for changes
aide --check

# Alternative: Install Tripwire
# apt install -y tripwire
```

---

## GL.iNet Router Hardening

### Initial Setup

**Important:** Perform factory reset if router was previously connected to compromised network.

#### Factory Reset Procedure

1. Power off router
2. Hold reset button
3. Power on while holding reset
4. Wait 10 seconds
5. Release reset button
6. Wait for router to reboot (2-3 minutes)

### Basic Security Configuration

#### 1. Change Default Credentials

```
Default access: http://192.168.8.1
Default password: (printed on router label or "goodlife")
```

**Set strong admin password:**
- Minimum 20 characters
- Mix of uppercase, lowercase, numbers, symbols
- Store in password manager (not browser)

#### 2. Firmware Update

1. Download latest firmware from https://dl.gl-inet.com/
2. **Verify checksum** - critical for security
3. Access router admin panel → Upgrade
4. Upload firmware file
5. Wait for update and reboot (do NOT interrupt)
6. Verify version after reboot

#### 3. Disable Unnecessary Services

- **Remote Access:** Disable unless absolutely required
  - `System → Admin Panel Access → Uncheck "Enable remote access"`
- **UPnP:** Disable to prevent automatic port forwarding
  - `Network → Firewall → Disable UPnP`
- **WPS:** Disable - known security vulnerability
  - `Wireless → Disable WPS`

#### 4. Wireless Security

**2.4 GHz and 5 GHz Networks:**

- **Encryption:** WPA3 only (or WPA2/WPA3 mixed if devices don't support WPA3)
- **Password:** 20+ character passphrase
- **SSID:** Change default name (don't include router model or "GL-iNet")
- **Hide SSID:** Optional security through obscurity (disable broadcast)

```
Wireless → Wireless Settings
- Security: WPA3-SAE or WPA2/WPA3-SAE Mixed
- Password: [Strong passphrase]
- SSID: [Non-identifying name]
```

#### 5. MAC Address Filtering

**Whitelist approach:**

```
Wireless → MAC Filter
- Enable MAC filtering
- Policy: Allow listed only
- Add MAC addresses of trusted devices only
```

**Get MAC addresses:**
- macOS: `System Settings → Network → WiFi → Details → Hardware`
- iPhone: `Settings → General → About → WiFi Address`
- Linux: `ip link show`

### Advanced Configuration

#### VLAN Segmentation

**Network segments:**

1. **Trusted VLAN (VLAN 10):** MacBook, iPhone, Mini PC
2. **IoT VLAN (VLAN 20):** Smart home devices, cameras
3. **Guest VLAN (VLAN 30):** Untrusted devices
4. **Quarantine VLAN (VLAN 40):** Devices under analysis

**Configuration:**

```
Network → LAN → VLAN Settings
- Create VLAN 10 (Trusted): 192.168.10.0/24
- Create VLAN 20 (IoT): 192.168.20.0/24
- Create VLAN 30 (Guest): 192.168.30.0/24
- Create VLAN 40 (Quarantine): 192.168.40.0/24
```

#### Firewall Rules

**Block inter-VLAN traffic by default:**

```
Network → Firewall → Custom Rules

# Block IoT from accessing Trusted VLAN
iptables -I FORWARD -s 192.168.20.0/24 -d 192.168.10.0/24 -j DROP

# Block Guest from accessing Trusted VLAN
iptables -I FORWARD -s 192.168.30.0/24 -d 192.168.10.0/24 -j DROP

# Block Quarantine from accessing all other VLANs
iptables -I FORWARD -s 192.168.40.0/24 -j DROP
iptables -I FORWARD -d 192.168.40.0/24 -j DROP

# Allow Trusted to access IoT (for management)
iptables -I FORWARD -s 192.168.10.0/24 -d 192.168.20.0/24 -j ACCEPT
```

#### DNS Configuration

**Use secure DNS providers:**

```
Network → DNS → Custom DNS Servers
- Primary: 1.1.1.1 (Cloudflare)
- Secondary: 1.0.0.1 (Cloudflare)
- Or use: 9.9.9.9 (Quad9 - includes malware blocking)
```

**Enable DNS over TLS/HTTPS:**
```
Network → DNS → Enable DoT/DoH
```

#### Logging

**Enable comprehensive logging:**

```
System → Log → Log Settings
- Enable system log
- Log level: Notice or Info
- Enable remote syslog (send to Kali mini PC)
- Remote server: [Kali IP address]
- Port: 514
```

**On Kali, configure rsyslog to receive:**
```bash
# Edit /etc/rsyslog.conf
sudo vi /etc/rsyslog.conf

# Uncomment UDP syslog reception
module(load="imudp")
input(type="imudp" port="514")

# Restart rsyslog
sudo systemctl restart rsyslog

# Logs will appear in /var/log/syslog
```

---

## TP-Link Mesh Router Hardening

If you're using TP-Link Deco, Omada, or other TP-Link mesh systems instead of or in addition to GL.iNet:

### Factory Reset Procedure

**TP-Link Deco Mesh:**

1. Locate reset button (usually on bottom)
2. While powered on, press and hold reset button for 10 seconds
3. LED will turn red, then flash, then restart
4. Wait 2-3 minutes for complete reset
5. Reconfigure using Deco app

**TP-Link Omada:**

1. Access web interface (usually http://tplinkwifi.net or http://192.168.0.1)
2. Login with default credentials (admin/admin)
3. Go to System Tools → Factory Defaults → Reset
4. Or use hardware reset button (10 seconds)

### Basic Security Configuration

#### 1. Change Default Credentials

```
Default access:
- Deco App: Download from App Store
- Web: http://tplinkwifi.net or http://192.168.0.1
Default username: admin
Default password: admin (or password on device label)
```

**⚠️ CRITICAL SECURITY WARNING:** These default credentials are publicly known. Change them IMMEDIATELY upon first login to prevent unauthorized access.

**Set strong admin password:**
- Minimum 20 characters
- Store in password manager
- Change both web interface AND app password

#### 2. Firmware Update

**Via Deco App:**
1. Open Deco app
2. Tap on the menu icon
3. Go to "System" → "Firmware Update"
4. If update available, tap "Update"
5. **Do not interrupt during update** (15-20 minutes)

**Via Web Interface (Omada):**
1. Login to web interface
2. System Tools → Firmware Upgrade
3. Download latest from https://www.tp-link.com/support/
4. Verify checksum if provided
5. Upload and upgrade

#### 3. Disable Unnecessary Services

**In Deco App:**
- More → Advanced → NAT Forwarding → Disable if not needed
- More → Advanced → UPnP → Disable (security risk)
- IPv6 → Disable if not required (reduces attack surface)

**In Web Interface (Omada):**
- Settings → Services → Disable UPnP
- Settings → Remote Management → Disable
- Settings → WPS → Disable

#### 4. Wireless Security

**Encryption Settings:**
- Security: WPA2/WPA3-Personal (or WPA3-Personal only if all devices support)
- Password: 20+ character passphrase
- Guest Network: Separate password, isolation enabled

**In Deco App:**
```
Home → [Select Main Network] → Network Settings
- Security: WPA2/WPA3
- Password: [Strong password]
- Fast Roaming: Enable (for mesh handoff)
- Beamforming: Enable
```

#### 5. Guest Network Isolation

**Critical for compromised device quarantine:**

1. Enable Guest Network:
   - More → Guest Network → Enable
   - Set strong password
   - Set usage time limit if desired

2. **Enable Guest Network Isolation:**
   - Prevents guest devices from accessing main network
   - Prevents device-to-device communication
   - Deco App: This is automatic
   - Omada: Settings → Guest Network → Enable "Allow guests to access each other: No"

#### 6. Advanced TP-Link Mesh Configuration

**QoS (Quality of Service):**
```
More → QoS → Enable
- High Priority: Video calls, work devices (MacBook)
- Standard Priority: iPhone, general browsing
- Low Priority: IoT devices, smart home
```

**Parental Controls (for device filtering):**
```
More → Parental Controls
- Create profile for each device type
- Set content filters
- Use to temporarily isolate suspicious devices
```

**Network Optimization:**
```
More → Advanced → Network Optimization
- Run optimization weekly
- Helps identify compromised devices (unusual bandwidth usage)
```

#### 7. TP-Link Cloud Disable (Optional)

**For maximum security, disable cloud management:**

**Deco:**
- This is harder on Deco as it's cloud-focused
- Consider using local-only mode in advanced settings
- Or switch to Omada for local management

**Omada:**
- Settings → Cloud Access → Disable
- Use local controller only
- Access via LAN only

#### 8. VLAN Support (Omada Only)

**TP-Link Omada supports VLANs similar to GL.iNet:**

```
Settings → Wired Networks → LAN
- Create VLAN 10 (Trusted): 192.168.10.0/24
- Create VLAN 20 (IoT): 192.168.20.0/24
- Create VLAN 30 (Guest): 192.168.30.0/24
- Create VLAN 40 (Quarantine): 192.168.40.0/24

Settings → Wireless Networks
- Assign each SSID to appropriate VLAN
- Enable inter-VLAN isolation rules
```

**Note:** Deco mesh does NOT support VLANs. For VLAN segmentation with Deco, you need:
- TP-Link managed switch with VLAN support
- Or upgrade to Omada system

#### 9. Logging and Monitoring

**Enable comprehensive logging:**

**Deco App:**
```
More → Advanced → System → System Log
- Enable logging
- Check regularly for suspicious connections
```

**Omada:**
```
Settings → System → Log Settings
- Enable system log
- Set log level: Informational
- Enable remote syslog (send to Kali mini PC):
  - Server: [Kali IP]
  - Port: 514
```

### TP-Link Security Best Practices

**Do:**
- ✅ Update firmware monthly
- ✅ Use WPA3 if all devices support it
- ✅ Enable guest network isolation
- ✅ Disable cloud access (Omada)
- ✅ Change admin password every 90 days
- ✅ Review connected devices weekly

**Don't:**
- ❌ Use default credentials
- ❌ Enable UPnP
- ❌ Enable WPS
- ❌ Share admin access
- ❌ Skip firmware updates
- ❌ Ignore suspicious devices in device list

### Hybrid Setup: TP-Link + GL.iNet

If using both routers:

**Option 1: TP-Link Primary, GL.iNet Secondary**
- TP-Link Mesh: Main network for home
- GL.iNet: Secure network for clean devices only
- Connected via ethernet to TP-Link LAN port
- GL.iNet operates in "Router Mode" not "AP Mode"

**Option 2: GL.iNet Primary, TP-Link Mesh Secondary**
- GL.iNet: Primary with VLANs and security
- TP-Link in AP Mode: Extends WiFi coverage
- Configure TP-Link as Access Point only
- All routing/security handled by GL.iNet

**Recommended:** Option 2 for maximum security control

---

## Network Isolation Strategy

### Isolation Levels

#### Level 1: VLAN Segmentation
- Logical separation on same physical network
- Router enforces inter-VLAN rules
- **Use for:** Normal device separation

#### Level 2: Physical Air-Gap
- Complete physical disconnection from network
- No wireless, no ethernet
- **Use for:** Forensic analysis, malware examination

#### Level 3: Quarantine Network
- Separate physical network segment
- No internet access
- Monitored ingress/egress
- **Use for:** Suspicious device analysis

### Implementation

#### Air-Gapped Kali Analysis

**When to use:**
- Analyzing malware samples
- Examining compromised devices
- Extracting forensic images
- Reviewing sensitive data

**Procedure:**
1. Disable all network interfaces on Kali:
   ```bash
   sudo nmcli networking off
   sudo ifconfig wlan0 down
   sudo ifconfig eth0 down
   ```
2. Verify no connectivity:
   ```bash
   ping -c 1 8.8.8.8  # Should fail
   ip addr  # All interfaces down except lo
   ```
3. Perform analysis
4. Before reconnecting, scan all files:
   ```bash
   clamscan -r /home/forensic/analysis/
   ```

#### Guest Network Setup

**For untrusted devices:**

1. Create separate SSID on VLAN 30
2. No access to local network
3. Internet only
4. Short DHCP lease times (1 hour)
5. Rate limiting

```
Wireless → Guest Network
- Enable guest network
- SSID: [Guest WiFi Name]
- Isolation: Enabled
- Bandwidth limit: 10 Mbps (optional)
```

#### Device Quarantine Procedure

**For compromised or suspicious devices:**

1. Move device to VLAN 40 (Quarantine)
2. Block all internet access
3. Enable full packet capture:
   ```bash
   sudo tcpdump -i eth0 -w /forensics/quarantine-$(date +%Y%m%d-%H%M%S).pcap
   ```
4. Monitor for beaconing, C2 communication
5. Analyze before moving to trusted VLAN

---

## macOS Forensics & Kext Detection

### Kernel Extension Detection

**Kernel extensions (kexts) are powerful and can:**
- Hide processes and files
- Intercept system calls
- Monitor all system activity
- Persist through reboots

#### List All Loaded Kexts

```bash
# On compromised macOS system
kextstat | less

# Look for suspicious entries:
# - Unknown developers
# - Generic names (e.g., "driver", "system", "kernel")
# - Unusual bundle identifiers
```

**Typical legitimate kexts:**
- `com.apple.*` - Apple's own kexts
- `com.intel.*` - Intel drivers
- `com.nvidia.*` - NVIDIA drivers
- `com.vmware.*` - VMware tools (if installed)

**Red flags:**
- Bundle IDs not matching known vendors
- Kexts loaded from unusual paths (not `/System/Library/Extensions/` or `/Library/Extensions/`)
- Recently loaded kexts (check timestamps)

#### System Extension Detection (macOS 10.15+)

**Modern macOS uses system extensions instead of kexts:**

```bash
# List all system extensions
systemextensionsctl list

# Check for:
# - Unknown developers
# - Unexpected security/network extensions
```

#### Process Analysis

```bash
# List all running processes
ps aux | less

# Sort by CPU usage
ps aux --sort=-%cpu | head -20

# Sort by memory usage
ps aux --sort=-%mem | head -20

# Check for suspicious processes:
# - High CPU/memory with unknown names
# - Processes running as root unexpectedly
# - Processes with unusual parent processes
```

#### Network Connections

```bash
# List all network connections
sudo lsof -i -P -n | less

# Check for:
# - Connections to unknown IPs
# - Unexpected ports
# - Processes maintaining persistent connections
```

#### Launch Agents and Daemons

**Persistence mechanisms:**

```bash
# System-wide launch daemons (run as root)
ls -la /Library/LaunchDaemons/
ls -la /System/Library/LaunchDaemons/

# User launch agents
ls -la ~/Library/LaunchAgents/
ls -la /Library/LaunchAgents/
ls -la /System/Library/LaunchAgents/

# Check each plist file for suspicious entries
cat /Library/LaunchDaemons/com.example.suspicious.plist
```

**Red flags:**
- `.plist` files with generic names
- Programs launching from `/tmp`, `/var/tmp`, or hidden directories
- `RunAtLoad` set to `true` with unknown programs
- `KeepAlive` set to `true` for unknown services

#### Log Review

```bash
# System logs (macOS 10.12+)
log show --predicate 'eventMessage contains "error"' --last 1h

# Security logs
log show --predicate 'subsystem == "com.apple.securityd"' --last 1d

# Kernel logs
log show --predicate 'messageType == error' --last 1h | grep kernel

# Login attempts
log show --predicate 'eventMessage contains "authentication"' --last 7d
```

### Forensic Imaging (Recommended Before Remediation)

**Create complete disk image for evidence preservation:**

#### Using dd (on Kali Linux with macOS drive connected)

```bash
# Identify macOS drive
lsblk

# Create forensic image (write-protected source recommended)
sudo dd if=/dev/sdX of=/forensics/macbook-$(date +%Y%m%d).img bs=4M status=progress

# Create hash for chain-of-custody
sha256sum /forensics/macbook-$(date +%Y%m%d).img > /forensics/macbook-$(date +%Y%m%d).img.sha256

# Compress image
gzip /forensics/macbook-$(date +%Y%m%d).img
```

#### Using macOS Disk Utility (less forensically sound)

```bash
# Create encrypted disk image of data
hdiutil create -encryption -srcfolder ~/Documents -format UDZO ~/forensic-backup.dmg
```

---

## Packet Capture & Analysis

### Tools Overview

#### tcpdump
- Command-line packet analyzer
- Lightweight, efficient
- Built into most Linux/Unix systems

#### Wireshark
- GUI packet analyzer
- Deep protocol inspection
- Extensive filtering and analysis features

#### HabeshNet Net Tool (Mobile)
- iOS network analysis app
- On-device packet capture
- Good for mobile device analysis

### Basic Packet Capture

#### Using tcpdump

```bash
# Capture all traffic on interface
sudo tcpdump -i eth0 -w capture.pcap

# Capture with verbose output
sudo tcpdump -i eth0 -v

# Capture specific host
sudo tcpdump -i eth0 host 192.168.1.100

# Capture specific port
sudo tcpdump -i eth0 port 443

# Capture DNS queries
sudo tcpdump -i eth0 port 53

# Capture and display HTTP headers
sudo tcpdump -i eth0 -A port 80

# Capture with packet count limit
sudo tcpdump -i eth0 -c 1000 -w capture.pcap
```

#### Using Wireshark

**GUI Method:**
1. Launch Wireshark: `sudo wireshark`
2. Select network interface
3. Click "Start" to begin capture
4. Apply filters as needed
5. Stop capture when done
6. Save as `.pcap` file

**Useful Display Filters:**
```
# Show only DNS traffic
dns

# Show only HTTP traffic
http

# Show traffic to/from specific IP
ip.addr == 192.168.1.100

# Show only TCP handshakes (SYN)
tcp.flags.syn == 1

# Show only failed connections
tcp.flags.reset == 1

# Show suspicious ports
tcp.port == 4444 || tcp.port == 5555 || tcp.port == 6666
```

### Analyzing Encrypted Traffic

**With HTTPS/TLS, you cannot see payload contents, but you can analyze:**

#### Connection Metadata
- Source and destination IPs
- Connection timing and frequency
- TLS handshake details
- Certificate information
- SNI (Server Name Indication)

#### Detection Patterns

```bash
# Using Wireshark filters

# Detect beaconing (periodic C2 communication)
# Look for regular connection intervals - e.g., every 60 seconds
Statistics → Conversations → Sort by packets

# Identify suspicious TLS certificates
tls.handshake.type == 11

# Find connections to unusual ports
tcp.port > 1024 and tcp.port < 5000

# Detect unusual DNS queries
dns.qry.name contains "unusual-domain"
```

### Suspicious Traffic Indicators

#### Command and Control (C2) Communication
- **Beaconing:** Regular, periodic connections at fixed intervals
- **Unusual ports:** Non-standard ports for HTTP/HTTPS traffic
- **High-entropy domains:** Randomly generated domain names (DGAs)
- **Fast flux:** Rapidly changing IPs for same domain

#### Data Exfiltration
- **Large outbound transfers:** Especially during off-hours
- **Unusual protocols:** DNS tunneling, ICMP tunneling
- **Encrypted channels:** TLS to unusual destinations
- **Continuous small uploads:** Keylogger data, screenshots

#### DNS Analysis

```bash
# Extract DNS queries from pcap
tcpdump -r capture.pcap -n port 53 | grep "A?"

# Look for:
# - DGA (Domain Generation Algorithm) domains
# - DNS tunneling (unusually long queries)
# - Frequent NXDOMAIN responses
# - Queries to suspicious TLDs (.tk, .ml, .ga)
```

### Network Baseline

**Establish normal behavior:**

1. **Capture clean traffic:**
   ```bash
   # Capture 24 hours of "normal" traffic after remediation
   sudo tcpdump -i eth0 -w baseline-$(date +%Y%m%d).pcap -G 3600 -W 24
   ```

2. **Document normal connections:**
   - Operating system updates
   - Application telemetry
   - Legitimate cloud services
   - Email/calendar synchronization

3. **Create whitelist of known-good:**
   - Apple's IP ranges
   - Microsoft's IP ranges
   - Google services
   - CDNs (Cloudflare, Akamai)

4. **Ongoing monitoring:**
   ```bash
   # Compare new traffic against baseline
   # Flag any connections not in whitelist
   ```

---

## MacBook Remediation

### Preparation Phase

#### 1. Backup Critical Data

**On clean Kali system with external drive:**

```bash
# Mount MacBook drive (connected via USB adapter or target disk mode)
sudo mkdir /mnt/macbook
sudo mount /dev/sdX2 /mnt/macbook  # Adjust device as needed

# Create backup directory
mkdir -p /forensics/macbook-backup

# Copy documents (NOT applications or system files)
rsync -av /mnt/macbook/Users/[username]/Documents/ /forensics/macbook-backup/Documents/
rsync -av /mnt/macbook/Users/[username]/Desktop/ /forensics/macbook-backup/Desktop/
rsync -av /mnt/macbook/Users/[username]/Pictures/ /forensics/macbook-backup/Pictures/

# Scan backup for malware
clamscan -r /forensics/macbook-backup/

# Unmount
sudo umount /mnt/macbook
```

**Important:** Do NOT restore applications, browser extensions, or system files - these may be compromised.

#### 2. Create Recovery Media

**Download macOS installer:**
- Use clean system or public network
- Download from App Store or Apple's website
- Verify download integrity (check SHA hash if available)

**Create bootable USB (on macOS):**
```bash
# For macOS Sonoma (adjust for your version)
sudo /Applications/Install\ macOS\ Sonoma.app/Contents/Resources/createinstallmedia --volume /Volumes/MyVolume
```

### Secure Wipe Process

#### Method 1: Using macOS Recovery (Recommended)

1. **Boot into Recovery Mode:**
   - **Intel Mac:** Hold `Command + R` during boot
   - **Apple Silicon:** Hold power button until "Loading options" appears

2. **Access Disk Utility**

3. **Erase disk with secure options:**
   - Select main drive (typically "Macintosh HD")
   - Click "Erase"
   - Format: APFS (encrypted) or APFS
   - Security Options: Most Secure (multiple pass overwrite)
   - Click "Erase"

4. **For SSDs:** Single pass is sufficient due to wear-leveling
5. **For HDDs:** Use 7-pass erase for high security

#### Method 2: Using FileVault + Crypto-Erase

**Faster method using encryption:**

1. Enable FileVault (if not already enabled)
2. Let full encryption complete
3. Securely delete encryption key
4. Format drive

**This makes data mathematically unrecoverable without years of computation.**

#### Method 3: External Wipe from Kali

```bash
# Connect Mac drive to Kali system
# CAUTION: Triple-check device identifier!

# Secure wipe with shred
sudo shred -vfz -n 7 /dev/sdX

# Or use dd with random data (faster for SSDs)
sudo dd if=/dev/urandom of=/dev/sdX bs=4M status=progress

# TRIM for SSDs (releases all blocks)
sudo blkdiscard /dev/sdX
```

### Clean macOS Installation

#### 1. Install macOS

1. Boot from recovery media
2. Select "Install macOS"
3. Follow installation prompts
4. **Do NOT sign in with Apple ID yet**
5. **Do NOT restore from backup**
6. Create new local user account

#### 2. Initial Security Configuration

**Before connecting to internet or signing in:**

```bash
# Enable FileVault (full disk encryption)
System Settings → Privacy & Security → FileVault → Turn On

# Enable Firewall
System Settings → Network → Firewall → Turn On

# Disable remote access services
System Settings → General → Sharing → Disable all

# Require password immediately after sleep/screen saver
System Settings → Lock Screen → Require password: Immediately

# Enable Find My Mac (after signing in with Apple ID)
System Settings → Apple ID → iCloud → Find My Mac

# Disable automatic login
System Settings → Users & Groups → Automatic login: Off
```

#### 3. Install Minimal Software

**Only install essential, trusted applications:**

```bash
# Use official sources only:
# - Mac App Store
# - Homebrew (for command-line tools)
# - Official vendor websites (verify HTTPS and signatures)

# Install Homebrew
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install essential tools
brew install --cask firefox  # Or your preferred browser
brew install gnupg  # For encryption
```

#### 4. Browser Hardening

**Firefox configuration:**

1. Settings → Privacy & Security
   - Enhanced Tracking Protection: Strict
   - Send websites "Do Not Track": Always
   - HTTPS-Only Mode: Enable in all windows
   - DNS over HTTPS: Enable (use Cloudflare or NextDNS)

2. Install privacy extensions:
   - uBlock Origin
   - Privacy Badger
   - HTTPS Everywhere (if not using Firefox built-in HTTPS-only)

3. **Do NOT reinstall old browser extensions** - potential compromise vector

#### 5. Network Connection

**Connect to hardened GL.iNet router:**

1. Join trusted VLAN WiFi network
2. Verify connection is using WPA3
3. Check IP address is in trusted subnet (192.168.10.x)

#### 6. macOS Updates

```bash
# Check for updates
System Settings → General → Software Update

# Enable automatic updates
- Install macOS updates: On
- Install app updates from App Store: On
- Install security responses and system files: On
```

---

## Email & Yubico Key Setup

### ProtonMail Account Creation

**Why ProtonMail:**
- End-to-end encryption
- Zero-access architecture
- Based in Switzerland (strong privacy laws)
- No personal information required
- Built-in 2FA support

#### Create New ProtonMail Account

**From clean MacBook:**

1. Navigate to https://proton.me/mail
2. Click "Create a free account"
3. Choose plan (Free or paid)
4. Select username: **Choose NEW username, never used before**
5. Use strong password (generate with password manager)
6. **Do NOT use old email for recovery** - creates link to compromised account
7. Complete phone/email verification if required
8. Save recovery kit

#### Account Security Settings

1. **Enable 2FA with Yubico key** (instructions below)
2. **Recovery email:** Use separate, new secure email (not old compromised account)
3. **Recovery phrase:** Store securely in password manager
4. **Trusted devices:** Only add devices after remediation

### Yubico Key Setup

**You have two keys - use this redundancy strategy:**
- **Key 1 (Primary):** Daily use, keep with you
- **Key 2 (Backup):** Secure location (safe, safety deposit box)

#### Initialize Yubico Keys

**On clean MacBook:**

1. **Install YubiKey Manager:**
   ```bash
   brew install --cask yubico-yubikey-manager
   ```

2. **Update firmware (if needed):**
   - Open YubiKey Manager
   - Connect key
   - Check for firmware updates
   - Follow update instructions

3. **Set PIN (if using PIV or FIDO2 PIN):**
   - YubiKey Manager → Applications → FIDO2
   - Set PIN (6-8 digits recommended)
   - **Record PIN in password manager**

#### Register Keys with ProtonMail

1. **Log into ProtonMail**
2. Go to Settings → Security and privacy → Two-factor authentication
3. Click "Add security key"
4. Insert Key 1
5. Touch key when prompted
6. Give it a name: "YubiKey Primary"
7. **Repeat for Key 2:** "YubiKey Backup"

**Test both keys:**
- Log out
- Log back in
- Verify both keys work for authentication

#### Register Keys with Other Services

**Priority services to secure with Yubico keys:**

1. **Apple ID:**
   - appleid.apple.com → Security → Security Keys
   - Add both keys

2. **Google Account (if used):**
   - myaccount.google.com → Security → 2-Step Verification
   - Security keys → Add security key
   - Add both keys

3. **GitHub (if used for development):**
   - github.com → Settings → Password and authentication
   - Security keys → Register new security key
   - Add both keys

4. **Password Manager:**
   - Add security key as 2FA method
   - Register both keys

5. **Banking/Financial Services:**
   - Check if they support FIDO2/WebAuthn
   - Register both keys if supported

#### Key Management Best Practices

**Do:**
- ✅ Register both keys on every account
- ✅ Test both keys periodically
- ✅ Store backup key securely offsite
- ✅ Attach key to keychain or lanyard
- ✅ Enable biometric unlock on device for convenience

**Don't:**
- ❌ Lend key to anyone
- ❌ Leave key in unlocked device
- ❌ Store both keys in same location
- ❌ Skip registering backup key
- ❌ Forget key when traveling

#### FIDO2 vs. OTP vs. PIV

**Your Yubico key supports multiple protocols:**

1. **FIDO2/WebAuthn (Preferred):**
   - Most secure
   - Phishing-resistant
   - No shared secrets
   - Use for: ProtonMail, Google, Microsoft, GitHub

2. **TOTP (Time-based One-Time Password):**
   - Compatible with more services
   - Generates 6-digit codes
   - Use for: Services without FIDO2 support

3. **PIV (Personal Identity Verification):**
   - Certificate-based authentication
   - Use for: Enterprise systems, SSH

**Prefer FIDO2 whenever available.**

---

## Cleanup and Account Security

### UTM Data and Configuration Cleanup

If you've been using UTM and need to ensure all data is removed from compromised VMs:

#### Remove All UTM VMs and Data

**On macOS:**

```bash
# Close UTM application first
killall UTM 2>/dev/null

# Remove all UTM VMs and data
rm -rf ~/Library/Containers/com.utmapp.UTM
rm -rf ~/Library/Group\ Containers/*.com.utmapp.UTM
rm -rf ~/Documents/UTM

# Remove UTM preferences
defaults delete com.utmapp.UTM

# Remove UTM application cache
rm -rf ~/Library/Caches/com.utmapp.UTM

# Verify removal (checks home directory only for safety)
find ~ -name "*UTM*" -o -name "*utm*" 2>/dev/null | grep -v "Application Support" | grep -v ".Trash"

# If any files remain, review them before deletion
```

#### Reset UTM to Factory Settings

If you're keeping UTM but want to start fresh:

1. Open UTM
2. Delete all existing VMs:
   - Right-click each VM → Delete
   - Confirm deletion and select "Delete all files"
3. Quit UTM
4. Run cleanup commands above
5. Reinstall UTM from https://mac.getutm.app/

### SSH Key Invalidation

**Revoke all SSH keys from compromised systems:**

#### 1. Identify All SSH Keys

```bash
# List all SSH keys on macOS
ls -la ~/.ssh/

# Common key files:
# - id_rsa / id_rsa.pub (RSA keys)
# - id_ed25519 / id_ed25519.pub (Ed25519 keys)
# - id_ecdsa / id_ecdsa.pub (ECDSA keys)
```

#### 2. Remove SSH Keys from Remote Servers

**For GitHub:**

**⚠️ Before starting:** Verify your 2FA (Yubico key or authenticator) is working to avoid account lockout.

1. Visit https://github.com/settings/keys (requires 2FA)
2. Review all SSH keys listed
3. Click "Delete" next to each key from compromised devices
4. Confirm deletion

**For GitLab, Bitbucket, etc.:**

Similar process in account settings → SSH Keys section

**For personal servers:**

```bash
# Connect to each server and remove from authorized_keys
ssh user@server

# Edit authorized_keys file
nano ~/.ssh/authorized_keys

# Remove all entries from compromised devices
# Save and exit

# Set correct permissions
chmod 600 ~/.ssh/authorized_keys
```

#### 3. Generate New SSH Keys

**On clean MacBook after remediation:**

```bash
# Generate new Ed25519 key (recommended)
ssh-keygen -t ed25519 -C "your-new-email@protonmail.com"

# Or RSA 4096-bit (if Ed25519 not supported)
ssh-keygen -t rsa -b 4096 -C "your-new-email@protonmail.com"

# Set passphrase when prompted (store in password manager)

# Add to ssh-agent
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519

# Copy public key
cat ~/.ssh/id_ed25519.pub
```

#### 4. Add New Keys to Services

Re-add the new public keys to:
- GitHub (https://github.com/settings/keys)
- GitLab, Bitbucket, etc.
- Personal servers' `~/.ssh/authorized_keys`

### macOS Cleanup: xtrace and $PATH

#### Remove xtrace Debugging

If `xtrace` was enabled for debugging or maliciously:

```bash
# Check if xtrace is set
echo $-

# Remove from shell configuration files
sed -i.bak '/set -x/d' ~/.zshrc ~/.bash_profile ~/.bashrc 2>/dev/null
sed -i.bak '/set -o xtrace/d' ~/.zshrc ~/.bash_profile ~/.bashrc 2>/dev/null

# Check for xtrace in system launch items
sudo grep -r "xtrace" /Library/LaunchDaemons/ /Library/LaunchAgents/ ~/Library/LaunchAgents/

# Remove any suspicious entries found
```

#### Clean $PATH Variable

**Inspect and clean $PATH:**

```bash
# View current PATH
echo $PATH | tr ':' '\n'

# Look for suspicious entries:
# - /tmp or /var/tmp directories
# - Hidden directories (starting with .)
# - Unusual locations
# - Non-standard /usr/local subdirectories
```

**Reset $PATH to default:**

```bash
# Backup current shell configs
cp ~/.zshrc ~/.zshrc.backup 2>/dev/null
cp ~/.bash_profile ~/.bash_profile.backup 2>/dev/null

# For zsh (macOS default)
cat > ~/.zshrc << 'EOF'
# Clean PATH
export PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin

# Add Homebrew if installed
if [ -f /opt/homebrew/bin/brew ]; then
    eval "$(/opt/homebrew/bin/brew shellenv)"
fi

# Add user bin if exists
[ -d "$HOME/bin" ] && export PATH="$HOME/bin:$PATH"
EOF

# Source new config
source ~/.zshrc

# Verify clean PATH
echo $PATH | tr ':' '\n'
```

**Remove malicious PATH entries from system-wide configs:**

```bash
# Check system-wide PATH configurations
sudo cat /etc/paths
sudo ls -la /etc/paths.d/

# Remove suspicious files in paths.d
sudo rm /etc/paths.d/suspicious-entry

# Reset /etc/paths to default (macOS)
cat <<EOF | sudo tee /etc/paths
/usr/local/bin
/usr/bin
/bin
/usr/sbin
/sbin
EOF

# Note: If you use Xcode, homebrew, or other dev tools, you may need to:
# - Re-run: xcode-select --install
# - Re-run: eval "$(/opt/homebrew/bin/brew shellenv)"
# - Test system functionality after this change
```

#### macOS Recovery Mode Cleanup

**Access Recovery Mode for deep cleanup:**

1. **Boot into Recovery:**
   - Intel Mac: Restart, hold `Command + R`
   - Apple Silicon: Shutdown, hold power button until "Options" appears

2. **Open Terminal** (from Utilities menu)

3. **Remove remote management profiles:**
   ```bash
   # List profiles
   profiles list
   
   # Remove specific profile
   profiles remove -identifier com.example.profile
   
   # Remove all profiles
   profiles remove -all
   ```

4. **Check for persistence mechanisms:**
   ```bash
   # Mount main drive
   diskutil list
   diskutil mount /dev/disk1s1  # Adjust as needed
   
   # Check launch items
   ls -la /Volumes/Macintosh\ HD/Library/LaunchDaemons/
   ls -la /Volumes/Macintosh\ HD/Library/LaunchAgents/
   
   # Remove suspicious items
   rm /Volumes/Macintosh\ HD/Library/LaunchDaemons/com.suspicious.plist
   ```

5. **Reset NVRAM/PRAM:**
   - Shutdown
   - Turn on and immediately hold: `Option + Command + P + R`
   - Release after second startup chime (Intel) or Apple logo appears/disappears twice (Apple Silicon)

### Google Account Access Cleanup

**Comprehensive Google account security audit:**

#### 1. Review Account Access

Visit https://myaccount.google.com/permissions (requires 2FA with Yubico key)

**Actions:**

1. **Third-party app access:**
   - Review all apps with account access
   - Remove any unrecognized or unnecessary apps
   - Click "Remove Access" for each

2. **Connected apps and sites:**
   - Go to https://myaccount.google.com/connections
   - Remove all apps you don't actively use
   - Prioritize removing apps installed before compromise

#### 2. Review Devices and Activity

**Check signed-in devices:**

1. Visit https://myaccount.google.com/device-activity
2. Review all devices with access
3. Click "Sign out" on any:
   - Unrecognized devices
   - Devices from before remediation
   - Compromised MacBook/iPhone (before cleanup)

**Review recent activity:**

1. Visit https://myaccount.google.com/notifications
2. Check for suspicious sign-ins
3. Document any anomalies for forensic record

#### 3. Contacts Cleanup

**Remove potentially compromised contacts:**

1. Visit https://contacts.google.com/
2. Review all contacts
3. Look for:
   - Contacts you don't recognize
   - Suspicious email addresses
   - Contacts added during compromise period

4. Delete suspicious entries:
   - Select contact
   - Click "Delete" (trash icon)
   - Confirm deletion

5. **Export clean contacts for backup:**
   ```
   More → Export → Select format (Google CSV)
   ```

#### 4. Google Drive Access

**Audit shared files and folders:**

1. Visit https://drive.google.com/
2. Click "Shared with me"
3. Review all shared items
4. Remove access to suspicious files:
   - Right-click → "Remove"

5. Check "Shared by me":
   - Review what you've shared
   - Remove sharing from sensitive files
   - Click file → Share → Remove people

#### 5. Gmail Cleanup

**Remove forwarding and delegates:**

1. Gmail Settings → "Forwarding and POP/IMAP"
2. Disable any forwarding addresses you didn't set up
3. Click "Delete" next to suspicious forwarding addresses

4. Check "Accounts and Import" → "Grant access to your account"
5. Remove any delegate access you didn't authorize

**Check filters for data exfiltration:**

1. Settings → "Filters and Blocked Addresses"
2. Review all filters
3. Delete suspicious filters that:
   - Forward emails automatically
   - Delete emails automatically
   - Apply unusual labels

#### 6. Chrome Sync Cleanup

**If you use Chrome:**

1. Visit https://chrome.google.com/sync
2. Click "Reset Sync"
3. This removes:
   - Browsing history
   - Bookmarks (backup first if needed)
   - Passwords (you're resetting these anyway)
   - Extensions (reinstall clean versions)

#### 7. Android Device Cleanup

**If you have Android devices:**

1. Visit https://myaccount.google.com/find-your-phone
2. Review all linked Android devices
3. Remove old/compromised devices:
   - Click device → "Sign out"
   - For stolen/lost: Click "Secure device" or "Erase device"

#### 8. Google Account Recovery Options

**Secure recovery methods:**

1. Visit https://myaccount.google.com/recovery
2. Update recovery email to your new ProtonMail
3. Update recovery phone to new SIM (after carrier security setup)
4. Add Yubico keys as backup method (already done in Yubico section)

### API Key Security and Access Management

**Critical for preventing unauthorized access to AI services, communication APIs, and other cloud platforms.**

#### Understanding API Key Risks

When your computer is compromised, API keys stored in:
- Environment variables
- Configuration files
- Application data
- Browser storage
- Keychain/credential managers

Can be exposed, allowing attackers to:
- Use your paid services (OpenAI, ElevenLabs, Twilio)
- Access your data and conversations
- Impersonate your applications
- Rack up charges on your accounts

#### API Key Inventory

**Services to audit based on your setup:**

1. **AI Services:**
   - OpenAI (ChatGPT API)
   - X.AI (Grok API)
   - ElevenLabs (voice synthesis)
   - Anthropic (Claude API)
   
2. **Communication Services:**
   - Twilio (SMS/Voice)
   - SendGrid (email)
   
3. **Authentication Services:**
   - Authy (backup codes, not API keys)
   - Google Authenticator (local only, no API keys)

#### 1. OpenAI API Key Security

**Revoke and rotate all OpenAI API keys:**

1. **Visit OpenAI API Keys page:**
   - Direct link: https://platform.openai.com/api-keys
   - Requires 2FA authentication

2. **Review all API keys:**
   - Check "Last used" timestamp
   - Look for keys used during compromise period
   - Note any unrecognized key names

3. **Revoke ALL existing keys:**
   - Click "Revoke" next to each key
   - Confirm revocation
   - **Do this even if keys appear unused** - better safe than sorry

4. **Create new API key** (only on clean computer):
   ```
   - Click "Create new secret key"
   - Name it clearly: "MacBook-Clean-2024"
   - Copy the key IMMEDIATELY (shown only once)
   - Store in password manager, NOT in code
   ```

5. **Verify access restrictions:**
   - Settings → Organization → Members
   - Ensure only your account has access
   - Remove any suspicious members

6. **Enable usage limits:**
   - Settings → Billing → Usage limits
   - Set monthly spending limit
   - Enable email notifications for usage

**Prevent Google/X.AI from accessing OpenAI:**
- OpenAI API keys are independent - Google and X.AI cannot access them unless you explicitly shared the keys
- Review OAuth connections at https://platform.openai.com/account/api-keys
- Remove any third-party OAuth applications you don't recognize

#### 2. X.AI (Grok) API Key Security

**Revoke and rotate X.AI API keys:**

1. **Visit X.AI Console:**
   - https://console.x.ai/ (or X.AI developer portal)
   - Authenticate with your X (Twitter) account + 2FA

2. **API Key Management:**
   - Navigate to API Keys section
   - List all active keys
   - Revoke keys from compromised period
   - Generate new key only on clean system

3. **Prevent OpenAI from accessing X.AI:**
   - X.AI and OpenAI are separate platforms
   - They cannot access each other's APIs
   - No cross-platform access unless you wrote code that shares data

#### 3. ElevenLabs API Key Security

**For ElevenLabs on different iCloud account:**

1. **Sign in to ElevenLabs:**
   - https://elevenlabs.io/
   - Use the credentials from the OTHER iCloud account
   - Enable 2FA if available

2. **Access API settings:**
   - Profile → API Keys
   - Or: https://elevenlabs.io/settings/api-keys

3. **Revoke all keys:**
   - Click "Delete" on each API key
   - Confirm deletion

4. **Generate new key** (on clean device only):
   - Click "Generate new API key"
   - Name it: "Clean-Device-2024"
   - Copy and store in password manager (for the OTHER iCloud account)

5. **Account security:**
   - Change password to new strong password
   - Enable 2FA if available
   - Review connected applications

#### 4. Twilio API Key Security

**For Twilio on different iCloud account:**

1. **Sign in to Twilio Console:**
   - https://console.twilio.com/ (requires 2FA)
   - Use credentials from OTHER iCloud account

2. **Navigate to API Keys:**
   - Account → API Keys & Tokens
   - Or: https://console.twilio.com/us1/account/keys-credentials/api-keys

3. **Review and revoke:**
   - Main auth token: **Rotate immediately**
     - Click "View" next to Auth Token
     - Click "Rotate"
     - Confirm rotation
   - API Keys: Delete all keys
     - Click "Delete" next to each API key
     - Confirm deletion

4. **Create new API key** (clean device only):
   - Click "Create new API Key"
   - Friendly name: "Clean-MacBook-2024"
   - Key type: Standard
   - Save SID and Secret in password manager

5. **Additional Twilio security:**
   - Review Account → Phone Numbers → Active Numbers
   - Check for unauthorized numbers
   - Review Usage → Triggers → Create alerts for unusual usage

#### 5. Isolating API Keys to One Application

**Strategy: Environment-based isolation**

**Option 1: Use separate macOS user accounts** (Recommended)

```bash
# Create dedicated user for API-enabled app
sudo dscl . -create /Users/apiuser
sudo dscl . -create /Users/apiuser UserShell /bin/zsh
sudo dscl . -create /Users/apiuser RealName "API User"
sudo dscl . -create /Users/apiuser UniqueID 503
sudo dscl . -create /Users/apiuser PrimaryGroupID 20
sudo dscl . -create /Users/apiuser NFSHomeDirectory /Users/apiuser
sudo dscl . -passwd /Users/apiuser [password]

# Create home directory
sudo createhomedir -c -u apiuser

# Store API keys only in this user's environment
# Switch to this user only when using the API app
su - apiuser
```

**Option 2: Use application-specific keychains**

```bash
# Create isolated keychain for API app
security create-keychain -p [password] api-keys.keychain

# Store API key in isolated keychain
security add-generic-password -a "OpenAI" -s "api-key" \
  -w "sk-your-api-key-here" api-keys.keychain

# Lock keychain when not in use
security lock-keychain api-keys.keychain

# Only unlock when running specific app
security unlock-keychain api-keys.keychain
```

**Option 3: Use .env files with strict permissions**

```bash
# Create .env file for single app
cd /path/to/your/app
touch .env

# Add API keys
echo "OPENAI_API_KEY=sk-your-key-here" >> .env
echo "ELEVENLABS_API_KEY=your-key-here" >> .env

# Set strict permissions (only you can read)
chmod 600 .env

# Verify permissions
ls -la .env
# Should show: -rw------- (read/write for owner only)

# Add to .gitignore to prevent accidental commit
echo ".env" >> .gitignore
```

**Option 4: Use Docker container isolation**

```bash
# Run app in isolated Docker container
docker run -it --rm \
  -e OPENAI_API_KEY="sk-your-key-here" \
  -v /path/to/app:/app \
  your-app-image

# API keys only exist in container
# Not accessible from host system
```

#### 6. Managing APIs Across Multiple iCloud Accounts

**Your scenario: Some services (ElevenLabs, Twilio) on different iCloud account**

**Organization strategy:**

1. **Document which services use which account:**
   ```
   iCloud Account 1 (Primary - clean):
   - OpenAI
   - X.AI
   - Authy
   - Google Authenticator
   
   iCloud Account 2 (Secondary):
   - ElevenLabs
   - Twilio
   ```

2. **Use separate browsers/profiles:**
   
   **Safari:**
   - Use Safari for iCloud Account 1
   - Use Firefox or Chrome for iCloud Account 2
   - Or use Safari Private Window for Account 2
   
   **Chrome/Firefox profiles:**
   ```bash
   # Chrome: Create separate profiles
   # Chrome → Profiles → Add Profile
   # Name: "iCloud Account 1 - API Services"
   # Name: "iCloud Account 2 - Communication APIs"
   
   # Each profile has separate:
   # - Cookies
   # - Saved passwords
   # - Extensions
   # - API credentials
   ```

3. **Password manager organization:**
   
   In your password manager (Bitwarden/1Password):
   ```
   Folder: "API Keys - Account 1"
   - OpenAI API Key
   - X.AI API Key
   
   Folder: "API Keys - Account 2"
   - ElevenLabs API Key
   - Twilio API Keys (SID + Auth Token)
   
   Folder: "2FA - Account 1"
   - Authy backup codes
   - Google Auth recovery codes
   ```

4. **Session isolation:**
   - Never sign into both iCloud accounts on same device simultaneously
   - Use "Sign Out" between switching accounts
   - Use different devices if possible (MacBook for Account 1, Mini PC for Account 2)

#### 7. Verify No Cross-Service Access

**Ensure Google cannot access OpenAI:**

1. **Check Google account third-party access:**
   - https://myaccount.google.com/permissions
   - Look for "OpenAI" or "ChatGPT"
   - If found: Click "Remove Access"

2. **Check OpenAI account OAuth:**
   - https://platform.openai.com/account/api-keys
   - No "Sign in with Google" should be active
   - No Google OAuth connections

**Ensure X.AI cannot access OpenAI:**

1. **Check X.AI account connections:**
   - https://console.x.ai/ → Settings → Connected Accounts
   - Remove any OpenAI connections

2. **Check OpenAI account:**
   - https://platform.openai.com/account/api-keys
   - No X.AI or Twitter/X OAuth connections

**General rule:**
- API keys are SERVICE-SPECIFIC and cannot be accessed by other services
- Only OAuth connections allow cross-service access
- Remove all OAuth connections in compromised scenario

#### 8. Authy and Google Authenticator Security

**Important clarification:**
- Authy and Google Authenticator do NOT use API keys
- They generate time-based codes (TOTP) stored locally
- No cloud API access involved

**Securing Authy:**

1. **If Authy was on compromised device:**
   - Download Authy on clean device
   - Sign in with your phone number
   - Approve from another trusted device
   - Backups are encrypted, but rotate all 2FA codes anyway

2. **Disable multi-device (after recovery):**
   - Authy → Settings → Devices → Disable "Allow Multi-device"
   - Prevents new devices from accessing your codes

**Securing Google Authenticator:**

1. **If Google Authenticator was on compromised device:**
   - **You must re-register with each service**
   - Google Authenticator has no cloud backup (by design)
   - Visit each service and set up new 2FA

2. **Services to re-register:**
   - GitHub: Settings → Password and authentication → Remove old, add new
   - Google Account: myaccount.google.com/signinoptions/two-step-verification
   - Any other services using Google Authenticator

#### 9. Emergency API Key Rotation Checklist

**If you suspect active compromise:**

- [ ] **Immediately rotate all API keys** (OpenAI, X.AI, ElevenLabs, Twilio)
- [ ] **Review API usage logs** for unauthorized calls
- [ ] **Check billing** for unexpected charges
- [ ] **Enable spending limits** on all services
- [ ] **Set up usage alerts** (email notifications)
- [ ] **Remove all OAuth connections** from all services
- [ ] **Change passwords** for all API service accounts
- [ ] **Enable 2FA** on all API service accounts (if not already)
- [ ] **Document API key rotation** in forensic log
- [ ] **Store new keys in password manager** only (not in code/config files)
- [ ] **Use environment variables** or keychains for apps
- [ ] **Never commit API keys to Git** (check .gitignore, use git-secrets)

#### 10. Preventing Future API Key Exposure

**Best practices:**

1. **Never hardcode API keys:**
   ```python
   # BAD:
   api_key = "sk-proj-abc123..."
   
   # GOOD:
   import os
   api_key = os.environ.get('OPENAI_API_KEY')
   ```

2. **Use git-secrets to prevent commits:**
   ```bash
   # Install git-secrets
   brew install git-secrets
   
   # Add to repository
   cd /path/to/repo
   git secrets --install
   git secrets --register-aws
   
   # Add custom patterns
   git secrets --add 'sk-[a-zA-Z0-9]{32,}'  # OpenAI keys
   git secrets --add 'Bearer [a-zA-Z0-9]+'   # Bearer tokens
   ```

3. **Rotate keys regularly:**
   - Monthly rotation for high-value APIs
   - Quarterly rotation for less critical APIs
   - Immediate rotation after any security incident

4. **Monitor usage:**
   - Set up usage dashboards
   - Enable billing alerts
   - Review API logs weekly

5. **Principle of least privilege:**
   - Create separate API keys for each app/environment
   - Use read-only keys when possible
   - Restrict key permissions to minimum needed

### Mini PC Data Cleanup

**If your mini PC was previously used in compromised environment:**

#### 1. Secure Wipe and Reinstall Kali

**Complete reinstall (recommended):**

```bash
# Boot from Kali USB installer
# Select "Install Kali Linux" (not rescue mode)
# During partitioning:
# - Select "Guided - use entire disk and set up encrypted LVM"
# - This will securely overwrite all data
# - Follow installation steps from "Secure Kali Linux Setup" section
```

#### 2. If Keeping Existing Installation - Deep Clean

**Remove all user data and SSH keys:**

```bash
# Backup any needed files first to encrypted external drive

# Remove SSH keys
rm -rf ~/.ssh/
mkdir ~/.ssh
chmod 700 ~/.ssh

# Clear bash/zsh history
cat /dev/null > ~/.bash_history
cat /dev/null > ~/.zsh_history
history -c

# Remove any UTM-related files (if mini PC had UTM installed)
# SAFE: Only search user directories, not entire filesystem
find ~/ /opt /usr/local -name "*utm*" -o -name "*UTM*" 2>/dev/null

# Review output, then manually remove if safe:
# rm -rf /path/to/utm/file

# Clear system logs
sudo journalctl --vacuum-time=1s

# Remove old user accounts (if any suspicious accounts exist)
# List only usernames (more secure than full passwd file)
cut -d: -f1 /etc/passwd | grep -v "^_" | grep -v "nobody\|root\|daemon\|sync"
# For each suspicious user:
sudo userdel -r suspicious_username

# Clear temp directories
sudo rm -rf /tmp/*
sudo rm -rf /var/tmp/*

# Remove package cache
sudo apt clean
sudo apt autoclean
```

#### 3. Reset Network Configuration

```bash
# Remove old network connections
sudo rm -rf /etc/NetworkManager/system-connections/*

# Restart NetworkManager
sudo systemctl restart NetworkManager

# Reconfigure for trusted network only
sudo nmcli connection add type wifi con-name "Trusted-Network" \
  ssid "YourSecureSSID" \
  wifi-sec.key-mgmt wpa-psk \
  wifi-sec.psk "YourSecurePassword"
```

#### 4. Regenerate Host Keys

**SSH server host keys may be compromised:**

```bash
# Remove old SSH host keys
sudo rm /etc/ssh/ssh_host_*

# Regenerate new keys
sudo dpkg-reconfigure openssh-server

# Restart SSH service
sudo systemctl restart sshd

# Verify new keys generated
sudo ls -la /etc/ssh/ssh_host_*
```

#### 5. Update and Harden

```bash
# Full system update
sudo apt update && sudo apt upgrade -y && sudo apt dist-upgrade -y

# Re-run hardening steps from "Secure Kali Linux Setup" section
sudo rkhunter --update
sudo rkhunter --propupd
sudo rkhunter --check --skip-keypress

# Update AIDE database
sudo aideinit
sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
```

#### 6. Remove Persistence Mechanisms

**Check for rootkits and persistence:**

```bash
# Check systemd services
sudo systemctl list-unit-files --type=service --state=enabled

# Look for suspicious services
sudo systemctl list-units --type=service --all | grep -i "suspicious\|unknown"

# Check cron jobs
sudo crontab -l
sudo cat /etc/crontab
sudo ls -la /etc/cron.d/
sudo ls -la /etc/cron.daily/
sudo ls -la /etc/cron.hourly/
sudo ls -la /etc/cron.monthly/
sudo ls -la /etc/cron.weekly/

# Remove suspicious entries
sudo crontab -r  # Remove root crontab if compromised
```

#### 7. Verify Boot Integrity

```bash
# Check boot configuration
sudo ls -la /boot/
sudo cat /boot/grub/grub.cfg | grep -v "^#" | head -20

# Verify no unauthorized kernel modules
lsmod | grep -v "^Module"

# Check for rootkit kernel modules
sudo rkhunter --check --enable hidden_procs,hidden_ports

# If rootkits found, reinstall is strongly recommended
```

#### 8. Document Clean State

**After cleanup, document baseline:**

```bash
# Create system snapshot information
echo "=== Mini PC Clean State ===" > ~/mini-pc-baseline.txt
echo "Date: $(date)" >> ~/mini-pc-baseline.txt
echo "" >> ~/mini-pc-baseline.txt

# Document installed packages
dpkg -l >> ~/mini-pc-baseline.txt

# Document running services
systemctl list-units --type=service --state=running >> ~/mini-pc-baseline.txt

# Document network configuration
ip addr >> ~/mini-pc-baseline.txt

# Store securely
chmod 600 ~/mini-pc-baseline.txt
```

---

## Removable Media Safety

### Threat Model

**Removable media can harbor:**
- Firmware-level infections (BadUSB)
- Malicious file systems
- Autorun exploits
- Data exfiltration implants
- Persistent malware

### USB Devices

#### Write Blockers (Hardware)

**Recommended hardware:**
- Tableau T8-R2 Forensic USB Bridge
- CRU WiebeTech USB WriteBlocker
- Protect IQ Lab

**Purpose:** Prevents any write operations to USB device, ensuring forensic soundness.

#### Software Write Protection (Linux)

```bash
# List block devices
lsblk

# Set block device to read-only
sudo blockdev --setro /dev/sdX

# Verify read-only status
sudo blockdev --getro /dev/sdX  # Should return 1

# Mount read-only
sudo mount -o ro /dev/sdX1 /mnt/usb

# When done
sudo umount /mnt/usb
sudo blockdev --setrw /dev/sdX  # Re-enable writes if needed
```

#### Scanning USB Media

**On isolated Kali system:**

```bash
# Mount read-only
sudo mkdir /mnt/suspect-usb
sudo mount -o ro /dev/sdX1 /mnt/suspect-usb

# Scan with ClamAV
clamscan -r -i /mnt/suspect-usb

# Check for hidden files
ls -la /mnt/suspect-usb
find /mnt/suspect-usb -name ".*"

# Look for suspicious file types
find /mnt/suspect-usb -type f -name "*.exe" -o -name "*.dll" -o -name "*.scr"

# Check for autorun
cat /mnt/suspect-usb/autorun.inf 2>/dev/null

# Unmount
sudo umount /mnt/suspect-usb
```

### SD Cards

**Same procedures as USB devices, plus:**

#### Forensic Imaging

```bash
# Create bit-for-bit copy
sudo dd if=/dev/sdX of=/forensics/sdcard-$(date +%Y%m%d).img bs=4M

# Verify integrity
sudo dd if=/dev/sdX | sha256sum
sha256sum /forensics/sdcard-$(date +%Y%m%d).img
```

#### SD Card-Specific Risks

- Hidden partitions
- Controller firmware exploits
- Fake capacity cards (report larger size than actual)

### SIM Cards

#### Risks

- Cloning attacks
- Over-the-air updates (potentially malicious)
- Contact list exfiltration
- SMS intercept

#### SIM Card Analysis

**On Kali with SIM card reader:**

```bash
# Install pySIM tools
pip install pySIM

# Read SIM card (requires reader)
# Basic information
pySIM-read

# Look for:
# - Unusual IMSI changes
# - Unexpected STK (SIM Toolkit) applications
# - Unknown installed applets
```

#### SIM Protection

**Request new SIM from carrier:**
- Do NOT transfer data from old SIM
- Verify carrier account security
- Enable SIM PIN/PUK protection
- Enable carrier-level port-out protection

### Decontamination Hardware

**For high-security environments:**

#### CIRCLean (USB Sanitizer)

- Hardware-based USB sanitization
- Converts documents to safe PDFs
- Removes active content, macros, scripts
- ~$250
- https://www.circl.lu/services/circlean/

#### Tyrex CDS-150 (Media Sanitization)

- Degausses and physically destroys drives
- Meets DoD 5220.22-M standards
- For complete media destruction
- ~$5,000+

### Safe Media Workflow

1. **Quarantine:** Treat all removable media as hostile
2. **Analysis:** Use isolated, air-gapped Kali system
3. **Scan:** Multiple AV engines, manual inspection
4. **Extract:** Copy only needed files (not executables)
5. **Re-scan:** Scan extracted files again
6. **Transfer:** Move to trusted system only after verification
7. **Sanitize:** Wipe original media or destroy if compromised

---

## Rebuilding Trusted Environment

### Password Management

#### Reset All Passwords

**Assume all passwords are compromised.**

**Priority order:**

1. **New ProtonMail** (already done)
2. **Password manager master password**
3. **Apple ID**
4. **Banking and financial accounts**
5. **Social media accounts**
6. **Email accounts** (consider abandoning compromised accounts)
7. **Shopping accounts**
8. **Utility accounts**
9. **Other online services**

#### Password Manager Setup

**Recommended options:**
- 1Password (cloud-based, good UI)
- Bitwarden (open source, self-hostable)
- KeePassXC (local, open source)

**Setup procedure:**

```bash
# Install (example: Bitwarden)
brew install --cask bitwarden

# Or for KeePassXC
brew install --cask keepassxc
```

**Configuration:**

1. **Create new vault** (do NOT import old passwords)
2. **Set strong master password:**
   - 20+ characters
   - Passphrase method: "correct horse battery staple"
   - Or random generated: "X8$mK9#pL2@nQ5&rT7"
3. **Enable 2FA with Yubico key**
4. **Enable auto-lock:** 5-15 minutes idle
5. **Enable clipboard clear:** 30 seconds

### Full Disk Encryption

**All devices should use encryption:**

#### macOS (FileVault)
- Already enabled during remediation
- Verify: System Settings → Privacy & Security → FileVault

#### Kali Linux (LUKS)
- Enabled during installation (if selected)
- Verify: `lsblk -f` (look for crypto_LUKS)

#### External Drives

```bash
# Encrypt external drive (macOS)
diskutil apfs enableFileVault /Volumes/ExternalDrive

# Encrypt external drive (Linux with LUKS)
sudo cryptsetup luksFormat /dev/sdX
sudo cryptsetup open /dev/sdX encrypted_drive
sudo mkfs.ext4 /dev/mapper/encrypted_drive
```

### Secure Communication

#### Encrypted Messaging

**Recommended apps:**
- Signal (mobile and desktop)
- Wire (for group/business communication)
- Element (Matrix protocol, self-hostable)

**Setup Signal:**

1. Install on iPhone:
   - App Store → Signal → Install
2. Register with phone number
3. Enable screen security (Settings → Privacy → Screen Security)
4. Enable registration lock (Settings → Account → Registration Lock)
5. Set disappearing messages default (Settings → Privacy → Disappearing Messages)
6. Verify safety numbers with contacts

#### VPN (Optional)

**Consider VPN for additional privacy:**

- Mullvad (privacy-focused, anonymous payment)
- ProtonVPN (from ProtonMail team)
- IVPN (no-logs, open source apps)

**Configuration:**
```bash
# Install Mullvad (example)
brew install --cask mullvad-vpn

# Configure:
# - Kill switch: Enable
# - DNS: Use Mullvad DNS
# - Protocol: WireGuard
```

### Data Restoration

#### What to Restore

**Safe to restore:**
- ✅ Documents (after scanning)
- ✅ Photos (after scanning)
- ✅ Videos (after scanning)
- ✅ Music (from original sources, not backed up files)

**Never restore:**
- ❌ Applications (reinstall from official sources)
- ❌ Browser profiles/extensions
- ❌ System files
- ❌ Configuration files (may contain persistence mechanisms)
- ❌ Executable files

#### Restoration Procedure

```bash
# On Kali, scan backup again
clamscan -r /forensics/macbook-backup/

# Transfer clean files to MacBook (via network or external drive)
rsync -av --exclude="*.exe" --exclude="*.app" --exclude=".*" \
  /forensics/macbook-backup/Documents/ \
  /Volumes/MacBookDrive/Users/username/Documents/
```

### Ongoing Monitoring

#### Scheduled Security Checks

**Weekly tasks:**
```bash
# On Kali
sudo rkhunter --check --skip-keypress
sudo aide --check

# On macOS
# Review login history
last | head -20

# Check for unexpected system extensions
systemextensionsctl list

# Review installed applications
ls -la /Applications
```

**Monthly tasks:**
- Review account logins for all services
- Check for unusual account activity
- Update all passwords older than 6 months (high-security)
- Review firewall/router logs
- Test backups

#### Network Monitoring

**Continuous monitoring on Kali:**

```bash
# Set up continuous packet capture (rotating logs)
sudo tcpdump -i eth0 -w /var/log/captures/capture-%Y%m%d-%H%M%S.pcap \
  -G 3600 -W 24 -Z root

# Periodic analysis
# - Check for beaconing
# - Verify no connections to blacklisted IPs
# - Monitor for data exfiltration patterns
```

### Forensic Documentation

**Maintain chain-of-custody logs:**

#### Document Template

```
INCIDENT LOG

Date: [Date]
Time: [Time]
Investigator: [Your Name]
Case ID: [Unique Identifier]

EVENT:
[Description of what happened]

EVIDENCE COLLECTED:
1. [Description of evidence - e.g., "Disk image of MacBook SSD"]
   - File: /forensics/macbook-20231201.img
   - Hash: [SHA256 hash]
   - Size: [Size in bytes]

ANALYSIS PERFORMED:
[What analysis was done]

FINDINGS:
[What was discovered]

ACTIONS TAKEN:
[Remediation steps]

CHAIN OF CUSTODY:
[Date/Time] - [Action] - [Person] - [Location]

NOTES:
[Additional observations]
```

#### Storage

- Keep logs in encrypted container
- Store offline backup in secure location
- Consider legal advice if evidence of identity theft

### Reporting Incidents

#### When to Report

**Report to authorities if:**
- Identity theft occurred
- Financial fraud detected
- Evidence of stalking/harassment
- Corporate/employer systems compromised
- Suspected nation-state actor
- Child exploitation material discovered

#### How to Report

**United States:**
- FBI Internet Crime Complaint Center: https://www.ic3.gov/
- FTC Identity Theft: https://www.identitytheft.gov/
- Local police department (for physical threats)

**Prepare before reporting:**
- Forensic documentation
- Timeline of events
- Financial impact assessment
- Evidence preservation (don't modify)

---

## Tools Reference

### Kali Linux Tools

#### Security Scanners

```bash
# rkhunter - Rootkit detection
sudo rkhunter --update
sudo rkhunter --check

# chkrootkit - Alternative rootkit scanner
sudo chkrootkit

# lynis - System auditing
sudo lynis audit system

# ClamAV - Antivirus
sudo freshclam  # Update signatures
clamscan -r /path/to/scan
```

#### Network Tools

```bash
# nmap - Network scanner
nmap -sV -sC 192.168.10.0/24  # Service and version detection
nmap -p- 192.168.10.100       # All ports scan

# Wireshark - Packet analyzer
sudo wireshark

# tcpdump - Command-line packet capture
sudo tcpdump -i eth0 -w capture.pcap

# netstat - Network connections
netstat -tupln  # Show listening ports
```

#### Integrity Monitoring

```bash
# AIDE - File integrity monitoring
sudo aideinit
sudo aide --check

# Tripwire - Alternative to AIDE
sudo tripwire --init
sudo tripwire --check
```

#### Logging and Auditing

```bash
# auditd - Linux audit daemon
sudo auditctl -l  # List rules
sudo ausearch -m avc  # Search audit logs

# rsyslog - System logging
tail -f /var/log/syslog
```

### Third-Party Tools

#### KaliHarden

**Automated hardening script:**

```bash
# Install
git clone https://github.com/lavabit/kaliharden.git
cd kaliharden

# Run (review script first!)
sudo ./kaliharden.sh
```

#### Lynis

**Security auditing and hardening:**

```bash
# Install (usually pre-installed on Kali)
apt install lynis

# Run audit
sudo lynis audit system

# Review recommendations
cat /var/log/lynis.log
```

### Hardware Tools

#### Network
- GL.iNet travel router (~$50-150)
- Managed switch with VLAN support
- Hardware firewall (optional)

#### Forensics
- USB write blockers ($50-500)
- SIM card reader (~$20)
- Multiple USB drives (for segregated storage)
- External drive enclosures

#### Security Keys
- Yubico YubiKey 5 NFC (~$50 each)
- Minimum 2 keys per person

### Online Resources

#### Security
- https://kali.org/ - Kali Linux official site
- https://privacyguides.org/ - Privacy tool recommendations
- https://www.eff.org/deeplinks - Electronic Frontier Foundation news

#### Threat Intelligence
- https://otx.alienvault.com/ - Open Threat Exchange
- https://www.virustotal.com/ - Multi-engine malware scanner
- https://www.hybrid-analysis.com/ - Malware analysis

#### Learning
- https://tryhackme.com/ - Cybersecurity training
- https://www.hackthebox.com/ - Penetration testing practice
- https://overthewire.org/wargames/ - Security games

---

## UTM Integration Guide

### Using UTM for Kali Linux Deployment

While this guide primarily recommends **bare-metal Kali Linux on a mini PC** for maximum security, UTM can be valuable for:

1. **Learning and practice** (on trusted systems)
2. **Post-recovery testing** (in controlled environment)
3. **Isolated malware analysis** (with precautions)

### Installing Kali Linux in UTM

#### Prerequisites

- UTM installed on Mac (https://mac.getutm.app/)
- Kali Linux ISO downloaded and verified
- At least 4GB RAM allocated to VM
- At least 20GB disk space for VM

#### Step-by-Step Installation

1. **Create New VM:**
   - Open UTM
   - Click "Create a New Virtual Machine"
   - Select "Virtualize" (for ARM Macs) or "Emulate" (for Intel Macs)

2. **Configure VM:**
   - Operating System: Linux
   - Boot ISO: Select Kali Linux ISO
   - Memory: 4GB (4096 MB) minimum
   - CPU Cores: 2-4 cores
   - Storage: 20GB minimum (thin provisioned)

3. **Network Configuration:**
   - **Bridged Mode:** For network analysis (gives VM direct network access)
   - **Shared Network:** For safer, NAT'd access
   - **Host Only:** For isolated testing

4. **Install Kali:**
   - Start VM
   - Follow installation steps (same as bare-metal)
   - Install VMware/QEMU guest tools if prompted

5. **Post-Installation:**
   - Take snapshot before making changes
   - Update system: `sudo apt update && sudo apt upgrade -y`
   - Install UTM guest tools for better integration

### UTM Security Considerations

#### VM Isolation

**UTM VMs are NOT completely isolated:**
- ⚠️ VM can potentially access host file system (via shared folders)
- ⚠️ VM escape vulnerabilities exist (though rare)
- ⚠️ Host OS compromise could affect VM

**Best practices:**
- Disable shared folders when analyzing untrusted content
- Don't run VM on compromised host
- Use snapshots for rollback capability

#### Network Analysis in UTM

**Bridged networking allows:**
- Direct access to physical network
- Promiscuous mode for packet capture
- Network scanning capabilities

**Configuration:**
```bash
# In UTM VM settings:
Network Mode: Bridged
Bridge Interface: en0 (or your active interface)

# In Kali VM:
sudo ip link set eth0 promisc on
sudo tcpdump -i eth0
```

#### USB Passthrough

**For USB device analysis:**

1. UTM → VM Settings → Devices
2. Click "New Drive"
3. Select "USB"
4. Connect physical USB device
5. Pass through to VM

**Security warning:** USB passthrough can expose host to USB-based attacks. Only use with trusted devices or in air-gapped scenarios.

### Snapshots and Forensics

**Use snapshots for clean states:**

```
# Snapshot workflow:
1. Create "Clean Base" snapshot after installation
2. Create "Pre-Analysis" snapshot before examining suspect files
3. Perform analysis
4. Revert to "Pre-Analysis" if VM compromised
5. Create new snapshot after successful analysis
```

### When to Use UTM vs. Bare-Metal

**Use UTM for:**
- ✅ Learning Kali Linux on trusted Mac
- ✅ Testing configurations before deploying to bare-metal
- ✅ Running one-off analysis tasks (after environment secured)
- ✅ Demonstrating security concepts

**Use bare-metal mini PC for:**
- ✅ Initial compromise recovery (when host is untrusted)
- ✅ Long-term security monitoring
- ✅ Forensic-grade analysis requiring chain-of-custody
- ✅ Network analysis requiring direct hardware access
- ✅ High-assurance security operations

### Hybrid Approach

**Recommended workflow:**

1. **Recovery Phase:** Use bare-metal Kali mini PC
   - Air-gapped analysis of compromised devices
   - Network security assessment
   - Initial forensics

2. **Post-Recovery:** Transition to UTM on secured Mac
   - Ongoing security monitoring
   - Development and testing
   - Learning new tools

3. **Keep mini PC available:** For future incident response or periodic security audits

---

## Conclusion

### Key Takeaways

1. **Start with a clean foundation:**
   - Deploy Kali Linux on bare-metal mini PC for maximum security
   - Never trust compromised systems for security analysis

2. **Isolate everything:**
   - Air-gap during critical analysis phases
   - Use VLANs for network segmentation
   - Quarantine suspicious devices

3. **Rebuild from scratch:**
   - New accounts (ProtonMail, etc.)
   - Fresh OS installations
   - Don't restore potentially compromised files

4. **Use hardware security:**
   - Yubico keys for 2FA
   - Full disk encryption
   - Router hardening and segmentation

5. **Document everything:**
   - Forensic chain-of-custody
   - Incident timeline
   - Evidence preservation

### Recovery Checklist

- [ ] Deploy Kali Linux on bare-metal mini PC
- [ ] Factory reset and harden GL.iNet router
- [ ] Configure VLAN segmentation
- [ ] Analyze compromised MacBook (air-gapped)
- [ ] Create forensic images of all devices
- [ ] Secure wipe and reinstall macOS
- [ ] Create new ProtonMail account
- [ ] Register Yubico keys on all accounts
- [ ] Reset all passwords with password manager
- [ ] Scan and restore clean data only
- [ ] Set up ongoing monitoring
- [ ] Document incident for authorities (if needed)

### Ongoing Security

**This is not a one-time event:**

- Weekly security scans
- Monthly password rotation (for sensitive accounts)
- Continuous network monitoring
- Regular threat intelligence review
- Periodic security audits

### Additional Resources

- **This Guide:** `/Documentation/SecuringDevicesWithKaliLinux.md`
- **Kali Documentation:** https://www.kali.org/docs/
- **Privacy Guides:** https://privacyguides.org/
- **EFF Security Guides:** https://ssd.eff.org/

### Support and Community

**Need help?**
- r/Kalilinux subreddit
- Kali Linux forums: https://forums.kali.org/
- Local cybersecurity meetups
- Professional incident response services (for serious breaches)

---

**Remember:** Security is a continuous process, not a destination. Stay vigilant, keep learning, and maintain good security hygiene.

**Stay safe!**
