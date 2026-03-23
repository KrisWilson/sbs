# Small Boot Server

## Small app just to netboot your computer, without need to configuring server and privilages, or mind about license to use software

Created in mind of simplicity and zero-setup to boot over LAN some PXE


![Showcase](https://github.com/KrisWilson/sbs/blob/master/showcase.gif)

### Server can host:
> DHCP & TFTP server - enough to boot over LAN (with downloading images into ramdisk)

Do some configs like:
* Server DHCP IP, Server TFTP IP
* Precise hostname, domain, boot-file, rootpath, timezone
* Stick IP to specific MAC
* Client IP subnetwork
* boot folder/file per architecture

### Client can:
> Exists and talk to DHCP, then get some data from TFTP e.g. 500MB iso image into ram

Tested platforms: i686 old intel celeron platform with Debian and Grub, and 200 qemu vm instances

#### Tested for i686/i386 (folder: pxe_example):  
FreeDOS 1.2 [Lite/Full], Hiren's BootCD, Memtest, NT Offline Editor, PLPBT, Super Grub 2, Debian

## Get started:
(root is needed to DHCP access packets for 0.0.0.0)  
(be aware of firewall at these ports 67 68 69)  
(tshark/wireshark might be useful for diagnosing problems)
```
git clone https://github.com/KrisWilson/sbs
# Config /config/server.yaml <-- your interface details
sudo python3 main.py
```


## Credits
- **Bootloader**: [GRUB2](https://www.gnu.org/software/grub/) (GPL-3.0)
- **Theme**: [Vimix GRUB Theme](https://github.com/vinceliuice/grub-themes) by Vinceliuice (GPL-3.0)
- **Tools**: [Memdisk](https://wiki.syslinux.org/wiki/index.php?title=MEMDISK) (GPL-2.0)