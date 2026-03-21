import socket
import os
import struct

## SMALL BOOT SERVER


# RFC2131 for DHCP: https://datatracker.ietf.org/doc/html/rfc2131
# @ helpfuldoc

class DHCP_packet:  # struktura zbudowana na podstawie RFC2131, zamieściłem więcej w pliku helpfuldoc bo utrapieniem było się odnalezienie w tej dokumentacji XDD
    def __init__(self, data_in):
        # 1 byte
        self.op = data_in[0]  # 0
        self.htype = data_in[1]  # 1
        self.hlen = data_in[2]  # 2
        self.hops = data_in[3]  # 3
        # 4 bytes
        self.xid = data_in[4:8]  # 4-7 Bytes
        # 2 bytes
        self.secs = data_in[8:10]  # 8-9
        self.flags = data_in[10:12]  # 10-11
        # 4 bytes
        self.ciaddr = data_in[12:16]  # 12-15
        self.yiaddr = data_in[16:20]  # 16-19
        self.siaddr = data_in[20:24]  # 20-23
        self.giaddr = data_in[24:28]  # 24-27
        # 16 bytes
        self.chaddr = data_in[28:44]  # 28-43
        # 64
        self.sname = data_in[44:108]  # null terminated?
        # 128
        self.file = data_in[108:108 + 128]
        # var
        self.option = data_in[133:]
        self.length = 4 + len(self.xid) + len(self.secs) + len(self.flags) + len(self.ciaddr) + len(self.yiaddr) + len(
            self.siaddr) + len(self.giaddr) + len(self.chaddr) + len(self.sname) + len(self.file) + len(self.option)

    def print(self):
        print("Length: " + str(self.length))
        print("Mess OP ", self.op)
        print("HTYPE \t", self.htype)
        print("HLEN \t", self.hlen)
        print("HOPS \t", self.hops)
        print("XID \t", self.xid)
        print("SECS \t", self.secs)
        print("FLAGS \t", self.flags)
        print("CIADDR \t", self.ciaddr)
        print("YIADDR \t", self.yiaddr)
        print("SIADDR \t", self.siaddr)
        print("GIADDR \t", self.giaddr)
        print("CHADDR \t", self.chaddr)
        print("SNAME \t", self.sname)
        print("FILE \t", self.file)
        print("OPTION \t", self.option)


client_ip = "192.168.2.2"
server_ip = "192.168.2.1"
server_tftp = server_ip


def create_dhcp_response(packet: DHCP_packet, clientip: str, response_type="OFFER"):
    # przyzwyczajenie z assemblera do małych komponentów aby używać capslocka
    OP = b'\x02'  # Boot Reply, client send 01
    HTYPE = bytes([packet.htype])  # ethernet type e.g. 1 = 10 mb/s ethernet @=>helpfuldoc
    HLEN = bytes([packet.hlen])  # hardware address length e.g. 6 for 10mb/s ethernet @=>helpfuldoc
    HOPS = b'\x00'  # server send always 0 @helpfuldoc line 41
    XID = packet.xid  # ticket ID - must be the same as client, its like the same series of corresponding
    SECS = b'\x00\x00'  # server sends 0
    FLAGS = b'\x80\x00'  # broadcasting

    client_ip = clientip
    CIADDR = b'\x00\x00\x00\x00'  # client IP - server sets 0
    YIADDR = socket.inet_aton(client_ip)  # 'your ip' - ip for client
    SIADDR = socket.inet_aton(server_ip)  # 'server ip' - server ip
    GIADDR = b'\x00\x00\x00\x00'  # Gateway IP - so far we can leave 0.0.0.0
    CHADDR = packet.chaddr  # selected hardware, the same as client (cuz we sending to client)

    header = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + \
             CIADDR + YIADDR + SIADDR + GIADDR + CHADDR + \
             (b'\x00' * 64) + (b'\x00' * 128)  # take all in

    magic_cookie = b'\x63\x82\x53\x63'  # dhcp is nightmare, there must be special cookie to difference between BOOTP and DHCP packets

    # building options
    #  tshark packet information from my client:
    #  Option: (55) Parameter Request List
    #        Length: 24
    #        Parameter Request List Item: (1) Subnet Mask
    #        Parameter Request List Item: (2) Time Offset
    #        Parameter Request List Item: (3) Router
    #        Parameter Request List Item: (5) Name Server
    #        Parameter Request List Item: (6) Domain Name Server
    #        Parameter Request List Item: (11) Resource Location Server
    #        Parameter Request List Item: (12) Host Name
    #        Parameter Request List Item: (13) Boot File Size
    #        Parameter Request List Item: (15) Domain Name
    #        Parameter Request List Item: (16) Swap Server
    #        Parameter Request List Item: (17) Root Path
    #        Parameter Request List Item: (18) Extensions Path
    #        Parameter Request List Item: (43) Vendor-Specific Information
    #        Parameter Request List Item: (54) DHCP Server Identifier
    #        Parameter Request List Item: (60) Vendor class identifier
    #        Parameter Request List Item: (67) Bootfile name

    # sending Offer or ACK, Offer is 02, and ACK is 05
    msg_type_byte = b'\x05' if response_type == "ACK" else b'\x02'

    # Option 53 - (3*16+5 = 48+5 = 53)
    options = (b'\x35\x01' + msg_type_byte)

    # Option 54 - Server address (
    SIADDR = socket.inet_aton(server_ip)
    options += b'\x36\x04' + SIADDR

    # Option 1 - Subnet mask
    options += b'\x01\x04\xff\xff\xff\x00'

    # Option 2 - Time Offset
    offset_seconds = 3600
    offset_bytes = struct.pack('>i', offset_seconds)
    options += b'\x02\x04' + offset_bytes

    # Options 3 - Router
    options += b'\x03\x04' + SIADDR

    # Option 6 - DNS (Domain Name Server)
    options += b'\x06\x04' + socket.inet_aton(server_ip)
    # Option 11 - skipped
    # Option 12 - Hostname
    hostname = b"pxe-client"
    options += b'\x0c' + bytes([len(hostname)]) + hostname

    # Option 15 - Domain name
    domain = b"local"
    options += b'\x0f' + bytes([len(domain)]) + domain

    # Option 43 - Vendor specific, PXE setup
    pxe_op43 = b'\x06\x01\x02\xff'
    options += b'\x2b' + bytes([len(pxe_op43)]) + pxe_op43

    # Option 60 - Vendor ID
    options += b'\x3c\x09PXEClient'

    # Option 66 - IP server for TFTP (resource server, option 11 dismissed)
    options += b'\x42' + bytes([len(socket.inet_aton(server_tftp))]) + socket.inet_aton(server_tftp)

    # Option 67 - Filename for bootfile at TFTP server
    boot_file = b"pxelinux.0"
    options += b'\x43' + bytes([len(boot_file)]) + boot_file

    # \255 ending for options and packet
    options += b'\xff'

    return header + magic_cookie + options


def format_mac(mac_in: bytes, hwlen: int):
    mac = ""  # FORMAT: AA BB CC DD EE FF
    for i in range(0, hwlen):
        one_byte = bytes([mac_in[i]])
        one_char = hex(int.from_bytes(one_byte, "big"))
        if len(str(one_char)) == 3:
            one_char = "0" + str(one_char)
        mac += one_char + " "
    return mac.replace("0x", "").upper()


def dhcp_server(port_in: int, port_out: int):
    print("[DHCP] Starting new server...")
    # #1 DHCP - the client will get assigned an Address to communicate with it later
    # AF_INET - IPv4
    # SOCK_DGRAM - UDP form of communication
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(('0.0.0.0', port_in))  # DHCP clients send Discover, Request on port 67
    broadcast_addr = ('255.255.255.255', port_out)  # DHCP clients listen for Offer, ACK on port 68
    print("[DHCP] Setup complete, now listening")
    while True:
        data, addr = sock.recvfrom(4096)  # retrieve packets from port 67
        packet_in = DHCP_packet(data)  # divide packet over custom class
        raw_opts = packet_in.option  # take last part of packet to search for options '53' (DISCOVER/REQUEST)
        reply = ''  # in case of failure (DISCOVER|REQUEST) send empty packet
        mac_addr = format_mac(packet_in.chaddr, packet_in.hlen)
        if b'\x35\x01\x01' in raw_opts:  # check for discover
            print("[DHCP] Found DISCOVER \t-> OFFER \thw: " + mac_addr)
            reply = create_dhcp_response(packet_in, "OFFER")
        elif b'\x35\x01\x03' in raw_opts:  # check for request
            print("[DHCP] Found REQUEST  \t-> ACK  \thw: " + mac_addr)
            reply = create_dhcp_response(packet_in, "ACK")
        # print(f"Pozycja Cookie: {reply.find(b'\x63\x82\x53\x63')}")
        sock.sendto(reply, broadcast_addr)


if __name__ == '__main__':
    dhcp_server(67, 68)

    #2 TFTP - trivial file transfer protocol - client will be able to access files eg. kernel, bootloader
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', 69))

#    while True:
#        # Receive the TFTP request from a client
#        data, addr = sock.recvfrom(4096)
#        print(addr)
