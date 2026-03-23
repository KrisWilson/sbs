# Small Boot Server

## Small app just to netboot your computer, without need to configuring server and privilages, or mind about license to use software

Created in mind of simplicity and zero-setup to boot over LAN some PXE


![Showcase](https://github.com/KrisWilson/sbs/blob/master/showcase.gif)

Server can host:
> DHCP & TFTP server - enough to boot over LAN

Do some configs like:
* Server DHCP IP, Server TFTP IP
* Precise hostname, domain, boot-file, rootpath, timezone
* Stick IP to specific MAC
* Client IP subnetwork
* boot folder per architecture

Client can:
> Exists and talk to DHCP to get download's ticket from TFTP

Tested platforms: i686 old intel celeron platform with Debian and Grub

Get started: (root is needed to DHCP access packets for 0.0.0.0)
(be aware of firewall at these ports 67 68 69)
(tshark/wireshark might be useful for diagnosing problems)
```
git clone https://github.com/KrisWilson/sbs
sudo python3 main.py
```

Tested for i686:
FreeDOS 1.2 [Lite/Full], Hiren's BootCD, Memtest, NT Offline Editor, PLPBT, Super Grub 2, Debian

Third-party assets:
Vimix theme from: https://github.com/vinceliuice/grub2-themes