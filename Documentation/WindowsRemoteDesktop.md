# Windows Remote Desktop Setup Guide

This guide provides instructions for setting up remote desktop access on a clean Windows installation, particularly useful when you're using borrowed hardware (screen and keyboard) and need remote access.

## Quick Answer

For a clean Windows installation on a mini PC, install one of the following:

**Recommended Option 1: Microsoft Remote Desktop (Built-in)**
- No installation needed - already included in Windows
- Enable Remote Desktop in Windows Settings
- Access from any device using Microsoft Remote Desktop client

**Recommended Option 2: AnyDesk**
- Free for personal use
- Works through firewalls/NAT automatically
- No complex network configuration needed

**Recommended Option 3: Chrome Remote Desktop**
- Free with Google account
- Works through browser
- Cross-platform support

## Detailed Setup Instructions

### Option 1: Microsoft Remote Desktop (RDP)

Microsoft Remote Desktop Protocol (RDP) is built into Windows and provides excellent performance for local network access.

#### Requirements
- Windows 10/11 Pro, Enterprise, or Education (NOT Home edition)
- Same network or VPN connection
- Port 3389 accessible (requires router configuration for remote access)

#### Enable Remote Desktop

1. **Open Windows Settings:**
   - Press `Win + I` to open Settings
   - Navigate to **System** → **Remote Desktop**

2. **Enable Remote Desktop:**
   - Toggle **Enable Remote Desktop** to **On**
   - Note the PC name shown (e.g., "DESKTOP-ABC123")
   - Click **Confirm** when prompted

3. **Configure User Access:**
   - Click **Select users that can remotely access this PC**
   - Add users who need access (administrators have access by default)

4. **Network Configuration:**
   - Note your PC's IP address: Open Command Prompt and type `ipconfig`
   - Look for "IPv4 Address" (e.g., 192.168.1.100)

#### Connect from Another Device

**From Windows:**
1. Open **Remote Desktop Connection** (type "mstsc" in Run dialog)
2. Enter the PC name or IP address
3. Enter username and password when prompted

**From macOS:**
1. Download Microsoft Remote Desktop from Mac App Store
2. Add new PC with IP address or hostname
3. Enter credentials and connect

**From iOS/Android:**
1. Install Microsoft Remote Desktop app
2. Add new PC
3. Enter connection details and credentials

#### Security Recommendations
- Use strong passwords for all user accounts
- Consider using Network Level Authentication (NLA)
- For internet access, use VPN instead of exposing port 3389
- Enable Windows Firewall
- Keep Windows updated

### Option 2: AnyDesk

AnyDesk is excellent for remote access without complex network configuration.

#### Installation

1. **Download AnyDesk:**
   - Open browser and go to https://anydesk.com
   - Click **Download Now**
   - Run the downloaded installer

2. **Setup:**
   - Choose "Install AnyDesk on this computer"
   - Complete installation wizard
   - Note your AnyDesk ID (9-digit number)

3. **Configure Unattended Access:**
   - Click **Settings** (hamburger menu)
   - Go to **Security** tab
   - Set a password for unattended access
   - Enable **Allow unattended access**

4. **Optional: Set up Auto-Start:**
   - In Settings, go to **General**
   - Enable **Start AnyDesk with Windows**

#### Connecting from Another Device

1. Install AnyDesk on the device you want to connect from
2. Enter the 9-digit AnyDesk ID of your mini PC
3. Click **Connect**
4. Enter the password you set for unattended access

#### Advantages
- Works through NAT/firewalls automatically
- No router configuration needed
- Free for personal use
- Cross-platform (Windows, Mac, Linux, iOS, Android)
- Fast and responsive

### Option 3: Chrome Remote Desktop

Chrome Remote Desktop is a free option that works through the browser.

#### Setup on Windows PC

1. **Install Google Chrome:**
   - Download from https://www.google.com/chrome
   - Install if not already present

2. **Set up Chrome Remote Desktop:**
   - Open Chrome browser
   - Go to https://remotedesktop.google.com/access
   - Sign in with Google account
   - Click **Download** under "Set up Remote Access"
   - Install Chrome Remote Desktop extension
   - Click **Turn On**

3. **Configure:**
   - Choose a name for your PC
   - Create a PIN (at least 6 digits)
   - Click **Start**

#### Connecting from Another Device

1. Go to https://remotedesktop.google.com/access
2. Sign in with the same Google account
3. Click on your PC name
4. Enter the PIN you created

#### Advantages
- Free
- Works through browser (no app installation needed on client)
- Simple setup
- Google account integration

### Option 4: TeamViewer

TeamViewer is another popular option with more features.

#### Installation

1. **Download TeamViewer:**
   - Go to https://www.teamviewer.com
   - Download TeamViewer for Windows
   - Run the installer

2. **Setup:**
   - Choose "Install to access this computer remotely"
   - Complete installation
   - Create TeamViewer account (free for personal use)
   - Set up unattended access

3. **Configuration:**
   - Set a personal password for unattended access
   - Note your TeamViewer ID
   - Enable auto-start with Windows

#### Connecting
1. Install TeamViewer on remote device
2. Enter TeamViewer ID
3. Enter password
4. Connect

### Option 5: VNC (TightVNC/RealVNC)

VNC is an open protocol for remote desktop access.

#### Installation (TightVNC)

1. **Download TightVNC:**
   - Go to https://www.tightvnc.com
   - Download TightVNC for Windows
   - Run installer

2. **Setup:**
   - Choose both Server and Viewer during installation
   - Set password for remote access
   - Configure to run as service

3. **Configuration:**
   - Open TightVNC Server configuration
   - Set passwords (primary and view-only optional)
   - Configure access rights

#### Connecting
1. Install VNC Viewer on client device
2. Enter IP address:port (default is 5900)
3. Enter password
4. Connect

## Comparison Table

| Solution | Cost | Ease of Setup | Network Config | Performance | Platform Support |
|----------|------|---------------|----------------|-------------|------------------|
| Microsoft RDP | Free (Windows Pro+) | Easy | Required | Excellent | Windows, macOS, iOS, Android |
| AnyDesk | Free (personal) | Very Easy | None | Excellent | All platforms |
| Chrome Remote Desktop | Free | Very Easy | None | Good | Browser-based |
| TeamViewer | Free (personal) | Easy | None | Very Good | All platforms |
| TightVNC | Free | Moderate | Required | Good | All platforms |

## Recommendation for Your Scenario

**For a clean Windows install with borrowed screen/keyboard:**

### If you have Windows 10/11 Pro or higher:
1. **First choice: Enable built-in Remote Desktop (RDP)**
   - Already installed, no download needed
   - Best performance on local network
   - Professional solution

### If you have Windows 10/11 Home:
1. **First choice: Install AnyDesk**
   - Quick to install
   - No network configuration needed
   - Free for personal use
   - Works from anywhere

### Alternative approach:
1. **Install Chrome Remote Desktop**
   - If you already use Google services
   - Simplest setup
   - Access from any browser

## Step-by-Step for Complete Beginners

### Using AnyDesk (Recommended for simplicity)

**On the mini PC (using borrowed screen/keyboard):**

1. Connect screen and keyboard to mini PC
2. Turn on mini PC and complete Windows setup if needed
3. Connect to WiFi or ethernet
4. Open Microsoft Edge browser (pre-installed on Windows)
5. Go to: `anydesk.com`
6. Click "Download Now"
7. Click the downloaded file to install
8. Click "Install AnyDesk on this computer"
9. Click through the installation
10. **IMPORTANT:** Write down the 9-digit number you see (this is your AnyDesk ID)
11. Click the three lines menu (☰) → Settings
12. Click "Security" on the left
13. Under "Unattended Access", click "Set password"
14. Create a strong password and write it down
15. Check "Allow unattended access"
16. Click "Apply"
17. Close Settings

**On your personal device:**

1. Install AnyDesk from anydesk.com
2. Open AnyDesk
3. Enter the 9-digit ID you wrote down
4. Click "Connect"
5. Enter the password you created
6. You can now control the mini PC remotely!

**You can now return the borrowed screen and keyboard** - you have full remote access to your mini PC.

## Firewall Configuration

Most solutions above work automatically through firewalls. If using RDP or VNC over the internet:

1. **Port Forwarding (Router):**
   - Access your router settings (usually at 192.168.1.1)
   - Find Port Forwarding section
   - Forward port 3389 (RDP) or 5900 (VNC) to your PC's local IP
   - **Security Warning:** Only do this with VPN or strong security

2. **Better Alternative: Use VPN**
   - Install Tailscale (https://tailscale.com) on both devices
   - Provides secure encrypted connection
   - No port forwarding needed
   - Access your PC securely from anywhere

## Security Best Practices

1. **Use strong passwords:**
   - Minimum 12 characters
   - Mix of letters, numbers, and symbols
   - Don't use common words

2. **Keep Windows updated:**
   - Enable automatic updates
   - Install security patches promptly

3. **Use Windows Defender:**
   - Enable real-time protection
   - Keep definitions updated

4. **Limit user access:**
   - Only give remote access to users who need it
   - Use separate accounts with appropriate permissions

5. **Consider VPN for internet access:**
   - Never expose RDP directly to internet
   - Use VPN like Tailscale or WireGuard
   - Or use solutions with built-in NAT traversal (AnyDesk, TeamViewer)

6. **Monitor access:**
   - Check Event Viewer for remote access logs
   - Review unusual login attempts

7. **Enable screen lock:**
   - Set automatic lock after inactivity
   - Require password on wake

## Troubleshooting

### Can't connect to Remote Desktop
- Verify Remote Desktop is enabled in Settings
- Check Windows Firewall isn't blocking RDP
- Verify you're using correct IP address or PC name
- Ensure both devices are on same network (or VPN)

### AnyDesk connection fails
- Check internet connection on both devices
- Verify AnyDesk ID is correct
- Ensure AnyDesk service is running
- Check if antivirus is blocking AnyDesk

### Slow performance
- Close unnecessary applications on the PC
- Use wired ethernet instead of WiFi if possible
- Lower display quality settings in remote desktop client
- Check network bandwidth

### Can't enable Remote Desktop (Windows Home)
- Remote Desktop server is not available in Windows Home
- Use alternative solutions like AnyDesk or Chrome Remote Desktop
- Or upgrade to Windows Pro

## Integration with UTM

If you're running UTM virtual machines and want to access them remotely:

1. **Set up remote access to the host mini PC** using methods above
2. **Connect to the mini PC** remotely
3. **Open UTM** through the remote desktop session
4. **Control your VMs** as if you were sitting at the PC

### Alternative: Direct VM Access

For more advanced users, you can set up direct remote access to VMs:

1. **Configure VM networking** in UTM for bridged or shared network
2. **Install remote desktop software** inside the VM (RDP for Windows VMs, VNC for Linux)
3. **Access VM directly** over network without going through host

See [UTM Network Configuration](https://docs.getutm.app/settings/network/) for details.

## Additional Resources

- [Microsoft Remote Desktop Documentation](https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/)
- [AnyDesk Knowledge Base](https://anydesk.com/en/knowledge)
- [Chrome Remote Desktop Help](https://support.google.com/chrome/answer/1649523)
- [Tailscale Documentation](https://tailscale.com/kb/)
- [UTM Documentation](https://docs.getutm.app/)

## Summary

For a clean Windows installation on your mini PC with borrowed peripherals:

1. **Simplest solution:** Install AnyDesk - works in 5 minutes, no configuration
2. **Best for local network:** Enable Windows Remote Desktop (if you have Windows Pro)
3. **Best for simplicity + Google users:** Chrome Remote Desktop

After setup, you can return the borrowed screen and keyboard and access your mini PC from your phone, tablet, or laptop from anywhere with internet access.
