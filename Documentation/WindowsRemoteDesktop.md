# Windows Remote Desktop Setup Guide

This guide provides instructions for setting up remote desktop access on a clean Windows installation, including headless setup options (without screen or keyboard access).

## Quick Answer

### If You Have NO Screen/Keyboard Access:

**See the [Headless Setup section](#headless-setup-no-screen-or-keyboard)** below for options to:
- Find your mini PC's IP address via your router
- Set up remote access using USB drive methods  
- Locate your device on the network

**Most practical solution:** Borrow a screen/keyboard for 10-15 minutes to install AnyDesk, then return them and have permanent remote access.

### If You Have Temporary Screen/Keyboard Access:

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

## Headless Setup (No Screen or Keyboard)

If you don't have a screen or keyboard for your mini PC, you have several options to set up remote access:

### Option A: Find Your Mini PC on the Network

If Windows is already installed and connected to your network:

1. **Find the IP address using your router:**
   - Open your router's admin panel (usually at 192.168.1.1, 192.168.0.1, or 10.0.0.1)
   - Log in with your router credentials
   - Look for "Connected Devices", "Device List", or "DHCP Clients"
   - Find your mini PC by looking for:
     - Device name (might be "DESKTOP-XXXXX" or "MINISFORUM" or similar)
     - MAC address (physical address printed on the mini PC or box)
   - Note the IP address (e.g., 192.168.1.100)

2. **Check if Remote Desktop is already enabled:**
   - Try connecting with Remote Desktop Connection (if you have Windows Pro)
   - On your main computer, open Remote Desktop Connection (type `mstsc` in Run)
   - Enter the IP address and try to connect
   - If it connects, you're done! If not, continue to Option B

### Option B: Use a USB Installation Drive with Auto-Setup

Create a USB drive that automatically installs remote access software on first boot:

**Requirements:**
- USB flash drive (8GB+)
- Another computer to prepare the USB drive
- Windows installation media or existing Windows on the mini PC

**Steps:**

1. **Create an AutoRun USB drive:**
   - Download AnyDesk from https://anydesk.com/en/downloads/windows
   - Get the standalone executable (the direct .exe file, not the installer that opens a wizard)
   - Create a folder on your USB drive called `RemoteSetup`
   - Copy the AnyDesk.exe into this folder and rename it to `AnyDesk.exe` if needed
   - Create a batch file named `setup.bat` in the same folder with this content:

```batch
@echo off
echo Setting up remote access...
cd %~dp0
:: Install AnyDesk and configure auto-start
start AnyDesk.exe --install "%ProgramFiles%\AnyDesk" --start-with-win --create-shortcuts
timeout /t 5
echo Setup complete. AnyDesk ID will be shown on screen.
pause
```

2. **Prerequisites (if you have brief initial access):**
   - **Important:** Auto-login should be configured during initial Windows setup
   - Press Win+R, type `netplwiz`, press Enter
   - Uncheck "Users must enter a username and password"
   - Apply and enter your password
   - This allows the PC to boot to desktop automatically

3. **Boot the mini PC and run the setup:**
   - Insert the USB drive into the mini PC
   - Boot or restart the PC
   - Navigate to the USB drive and run `setup.bat`
   - **Note:** This method still requires brief manual access to run the batch file
   - **This is primarily useful for reducing setup time, not for completely headless setup**


### Option C: Network Boot (Advanced)

If the mini PC supports PXE boot, you can set up network installation, but this requires advanced networking knowledge and a PXE server.

### Option D: Temporary Access Method

**The practical solution for most users:**

If you can borrow peripherals temporarily (even for 15 minutes):

1. **Borrow the peripherals temporarily** (even for 15 minutes)
2. **Install AnyDesk** following the quick setup below
3. **Return the peripherals** - you'll have permanent remote access

This is the fastest and most reliable method. The setup takes less than 10 minutes.

## Finding Your Mini PC's IP and MAC Address

### From Your Router

1. Access your router's web interface:
   - Common addresses: `192.168.1.1`, `192.168.0.1`, `10.0.0.1`, `192.168.254.254`
   - Try typing these in your browser
   - Default credentials are often `admin/admin` or `admin/password` (check router label)

2. Navigate to device list:
   - Look for sections named:
     - "Connected Devices"
     - "Device List"  
     - "DHCP Clients"
     - "LAN Status"
     - "Attached Devices"

3. Identify your mini PC:
   - Look for device names containing: DESKTOP, MINISFORUM, MINIPC, or your PC model
   - Check the MAC address (format: XX:XX:XX:XX:XX:XX)
   - The MAC address is usually on a sticker on your mini PC

4. Note the IP address for remote connection

### Using Network Scanning Tools

If you can't access the router, use a network scanner from another device on the same network:

**On Windows:**
- Download Advanced IP Scanner (free): https://www.advanced-ip-scanner.com/
- Run scan on your network range (usually 192.168.1.1-254)
- Look for your mini PC in the results

**On macOS:**
- Use LAN Scan from the App Store (free)
- Scan your network
- Look for Windows devices

**On Linux:**
```bash
# Network scan - use responsibly and only on networks you own/manage
sudo nmap -sn 192.168.1.0/24
```
**Note:** Network scanning should only be performed on networks you own or have permission to scan.

**On Android/iOS:**
- Install "Fing" app
- Scan network
- Look for your device

## Installing VS Code

Once you have remote access to your Windows mini PC (or if you can access it with borrowed peripherals):

### Method 1: Download and Install (Windows)

1. **Access the mini PC remotely** (using AnyDesk, RDP, etc.) or with peripherals

2. **Download VS Code:**
   - Open browser (Edge is pre-installed on Windows)
   - Go to: https://code.visualstudio.com/
   - Click "Download for Windows"
   - Choose "User Installer" (recommended) or "System Installer"

3. **Install:**
   - Run the downloaded installer (`VSCodeUserSetup-x64-*.exe`)
   - Accept the license agreement
   - Choose installation location (default is fine)
   - **Important: Check these options:**
     - ✅ Add "Open with Code" action to context menu
     - ✅ Add to PATH (important for command line access)
     - ✅ Create desktop icon (if desired)
   - Click Install
   - Launch VS Code when installation completes

4. **Verify installation:**
   - VS Code should open automatically
   - Or press Win key and type "Visual Studio Code"

### Method 2: Install via Command Line (Windows)

If you have command line access via remote desktop:

1. **Using winget (Windows 10/11 with App Installer):**
```cmd
winget install Microsoft.VisualStudioCode
```

2. **Using Chocolatey** (if installed):
```cmd
choco install vscode
```

3. **Download via PowerShell and install:**
```powershell
# Download installer
Invoke-WebRequest -Uri "https://code.visualstudio.com/sha/download?build=stable&os=win32-x64-user" -OutFile "$env:TEMP\VSCodeSetup.exe"

# Run installer silently with recommended options
# addcontextmenufiles:    adds "Open with Code" to file right-click menu
# addcontextmenufolders:  adds "Open with Code" to folder right-click menu  
# addtopath:              adds VS Code to system PATH for command-line access
Start-Process -FilePath "$env:TEMP\VSCodeSetup.exe" -ArgumentList "/VERYSILENT /MERGETASKS=addcontextmenufiles,addcontextmenufolders,addtopath" -Wait
```

### Method 3: Portable Version (No Installation Required)

If you want VS Code on a USB drive or without admin rights:

1. Go to https://code.visualstudio.com/
2. Click "Download" → "Windows" → "zip" (under "Other downloads")
3. Extract the .zip file to your desired location
4. Run `Code.exe` from the extracted folder

### VS Code on Linux (Kali Linux in VirtualBox)

If you're running Kali Linux in VirtualBox on your mini PC:

1. **Access your Kali Linux VM**

2. **Download and install VS Code:**
```bash
# Download VS Code .deb package
wget -O vscode.deb 'https://code.visualstudio.com/sha/download?build=stable&os=linux-deb-x64'

# Install VS Code
sudo apt install ./vscode.deb

# Or use snap (if available)
sudo snap install --classic code
```

3. **Launch VS Code:**
```bash
code
```

### Essential VS Code Extensions for Beginners

After installing VS Code, install these helpful extensions:

1. **Open Extensions panel:** Press `Ctrl+Shift+X`

2. **Recommended extensions:**
   - **Python** (if learning Python)
   - **Live Server** (for web development)
   - **GitLens** (for Git integration)
   - **Remote - SSH** (to connect to remote Linux systems)
   - **Docker** (if using containers)
   - **Markdown All in One** (for documentation)

3. **Search for each extension** and click Install

### Configuring VS Code for Remote Development

If you want to code on your mini PC from another device:

1. **Install "Remote - SSH" extension** in VS Code
2. Press `Ctrl+Shift+P` and type "Remote-SSH: Connect to Host"
3. Enter: `username@mini-pc-ip-address`
4. You can now edit files on your mini PC from any device running VS Code

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
    - **Tip:** You can always find this ID later in the AnyDesk main window title bar or under Settings → General
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

---

**✅ Success! You can now return the borrowed screen and keyboard** - you have full remote access to your mini PC from any device.

---

## Firewall Configuration

Most solutions above work automatically through firewalls. If using RDP or VNC over the internet:

1. **Port Forwarding (Router):**
   - Access your router settings (commonly at 192.168.1.1, 192.168.0.1, or 10.0.0.1)
   - **Tip:** Find your router IP with `ipconfig` in Command Prompt - look for "Default Gateway"
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
