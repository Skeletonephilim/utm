# Organizing Storage Devices and Hardware for UTM

This guide provides best practices for organizing and managing storage devices, security hardware, and peripherals when working with UTM virtualization environments.

## Storage Media Organization

### SD Cards and Adapters

**Micro SD Cards with Adapters**
- Label each card with its purpose (e.g., "VM Images", "Backups", "Portable OS")
- Store in protective cases when not in use
- Keep adapters with their corresponding cards
- Consider capacity tiers:
  - 32-64GB: Individual VM images
  - 128GB: Multiple VMs or large disk images
  - 256GB+: Full backup solutions

**Best Practices:**
- Use waterproof labels or permanent marker on the card surface
- Maintain an inventory spreadsheet with card ID, capacity, and contents
- Test cards regularly for corruption (especially before storing critical data)
- Keep write-protect switches in the locked position when storing read-only content

### USB Devices

**Organization System:**
1. **Categorize by Function:**
   - Boot drives (Tails, live Linux)
   - VM storage and disk images
   - Shared directories for VMs
   - Backup and archival
   - Hardware security keys (YubiKeys)

2. **Labeling Strategy:**
   - Use color-coded labels or USB tags
   - Include:
     - Device name/purpose
     - Date of last update
     - Encryption status (if applicable)
     - Owner/project

3. **Physical Storage:**
   - Use organizer boxes with compartments
   - Keep frequently used devices easily accessible
   - Store security keys separately from general storage
   - Protect devices from static, moisture, and extreme temperatures

## Hardware Organization

### Network Equipment

**WiFi Adapters and Antennas**
- **Brostrend USB WiFi Adapter:** Label with supported standards (e.g., "WiFi 6", "2.4/5GHz")
- **GLiNet X3000:** Document configuration settings and admin passwords
- **TP-Link Mesh 1500:** Create network diagram showing node placement
- Keep ethernet cables organized by length and purpose
- Use cable management solutions to prevent tangling

**Network Documentation:**
- Maintain a network map with IP addresses
- Document port forwarding rules for VM access
- Keep backup configurations for all network devices
- Note MAC addresses for hardware pass-through to VMs

### Computing Hardware

**Mini PC (Alder Lake N95, 16GB RAM)**
- Document current RAM configuration
- Note available expansion slots and compatibility
- Keep original packaging for transport
- Create system specification document including:
  - CPU model and generation
  - RAM specifications (speed, type, slots)
  - Storage interfaces (SATA, NVMe slots)
  - USB port inventory
  - Network interfaces

**RAM and Expansion:**
- Check motherboard specifications before purchasing additional RAM
- Note maximum supported capacity and speed
- Consider whether dual-channel configuration is possible
- Keep original RAM modules even if upgrading

### Storage Solutions

**TerraMaster NAS**
- Label drive bays if not already marked
- Maintain disk inventory with serial numbers
- Document RAID configuration
- Set up automated backup schedules
- Keep spare drives for quick replacement
- Document network share configurations

## Security Hardware

### YubiKeys

**Organization:**
- Primary key: Daily use for authentication
- Backup key: Stored securely offline for account recovery
- Document which services are registered with each key
- Store backup key in a different physical location
- Never label security keys with account names or websites

**Best Practices:**
- Register both keys with all critical services when possible
- Test backup key quarterly to ensure it works
- Keep firmware updated
- Use different PINs for each key
- Document key serial numbers in secure password manager

### Amnesic Tails

**Preparation:**
- Create primary and backup Tails USB drives
- Configure persistent storage appropriately
- Document installed additional software packages
- Keep Tails updated to latest version
- Store offline in secure location when not in use

## Password and Documentation Management

### Small Notebooks for Passwords

**Organization System:**
1. Use color-coded notebooks:
   - One color for personal accounts
   - Another for work/project accounts
   - Separate color for network/hardware configurations

2. Structure entries consistently:
   - Service/device name
   - Username/account ID
   - Password (consider using password manager instead for critical accounts)
   - Recovery codes/questions
   - Date of last change

3. Security considerations:
   - Store in locked drawer or safe
   - Never leave in common areas
   - Consider encrypted password manager as primary solution
   - Use notebooks as backup only

### Color-Coded System

**Suggested Color Scheme:**
- **Red:** Critical/security devices (YubiKeys, admin passwords)
- **Blue:** Network equipment configurations
- **Green:** Storage devices and data locations
- **Yellow:** Development/testing equipment
- **Black:** General use devices

## Device Inventory Template

Create a master inventory document with the following information:

```
Device Type: [e.g., USB Drive, SD Card, Network Device]
Device Name: [Descriptive name]
Capacity/Spec: [Size, speed, or key specifications]
Label Color: [Physical label color]
Current Purpose: [What it's used for]
Last Updated: [Date]
Storage Location: [Where it's physically kept]
Notes: [Any additional relevant information]
```

## UTM-Specific Considerations

### VM Storage Strategy

**Local Storage (Mini PC):**
- Place frequently used VMs on internal NVMe
- Use USB 3.0 devices for portable VMs
- Reserve SD cards for lightweight testing VMs

**Network Storage (TerraMaster):**
- Store VM templates and backups
- Host shared folders for VMs
- Keep archived/rarely used VMs

### USB Device Pass-through

**Organization for Pass-through:**
- Label USB ports on host machine
- Document which devices are passed to which VMs
- Create consistency by using same ports for same devices
- Note USB controller information for pass-through configuration

### Hardware Compatibility Notes

**Compatible with UTM:**
- ✅ SD cards: Mount as external drives for VM access
- ✅ USB storage: Can be passed through or mounted
- ✅ WiFi adapters: Can be passed through to guest OS
- ✅ YubiKeys: Can be passed through for VM authentication
- ✅ NAS: Access via network shares in VMs

**Gaming Devices (Nintendo 3DS, Switch):**
- Can read SD cards formatted by these devices
- Useful for backing up save data
- Can test VM compatibility with SD card formats
- Switch can format cards as exFAT (compatible with most systems)

## Maintenance Schedule

**Weekly:**
- Check for device firmware updates
- Verify backup integrity
- Review device usage and reorganize if needed

**Monthly:**
- Test backup storage devices
- Clean USB connectors and ports
- Update inventory documentation
- Verify YubiKey functionality

**Quarterly:**
- Full inventory audit
- Replace any failing storage media
- Update security keys and passwords
- Review and optimize organization system

## Tips for Efficient Organization

1. **Start with a baseline:** Document everything you have now
2. **Create zones:** Group devices by usage frequency
3. **Use clear labels:** Invest in a label maker for consistency
4. **Regular maintenance:** Schedule time to maintain organization
5. **Document changes:** Keep notes when repurposing devices
6. **Backup critical data:** Never rely on a single storage device
7. **Test regularly:** Verify devices work before you need them urgently

## Additional Resources

- [UTM Documentation](https://docs.getutm.app/)
- [USB Device Management in VMs](https://docs.getutm.app/advanced/usb/)
- [Network Configuration](https://docs.getutm.app/settings/network/)
- YubiKey documentation for multi-factor authentication setup
- Tails documentation for portable secure computing
