# Small Boot Server

## Small app just to netboot your computer, without need to configuring server and privilages, or mind about license to use software

Created in mind of simplicity and zero-setup to boot over LAN some PXE

Server can:
> so far only do as DHCP for 1 client (its gonna change)

Do some configs like:
* Server IP
* Client IP pool

Client can:
> Exists and talk to DHCP without getting files to boot


Tested platforms: IA32 old intel celeron platform

Get started: (root is needed to DHCP access packets for 0.0.0.0)
(be aware of firewall at these ports 67 68 69)
```
git clone https://github.com/KrisWilson/sbs
sudo python3 main.py
```
