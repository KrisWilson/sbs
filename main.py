import os
import socket
import struct
import threading
import time
from os.path import exists


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

    def getArch(self):  # @helpfuldoc line:106
        if b'PXEClient:Arch' in self.option:
            if b'00000' in self.option:
                return "i386"
            elif b'00006' in self.option:
                return "EFI IA32"
            elif b'00007' in self.option:
                return "EFI x86-64"
            elif b'00010' in self.option:
                return "EFI ARM64"

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

client_prefixIP = "192.168.2."  # Client subnetwork
clients_ip = {
    'server': '192.168.2.1'
}  # Writing down the MAC <==> IP dependency

ip_arch = {
    '192.168.2.1': 'amd64'
}  # Writing down the IP  <==> Platform for booting

folder_arch = {
    'i386': 'i386',
    'EFI IA32': 'ia32',
    'EFI x86-64': 'x86',
    'EFI ARM64': 'arm64',
    'none': 'i386'
}
file_arch = {
    'i386': 'core.0',
    'EFI IA32': 'core.0',
    'EFI x86-64': 'core.0',
    'EFI ARM64': 'core.0',
    'none': 'core.0'
}

client_name = b'pxe_client'  # Client's hostname
domain_name = b'local'  # LAN domain
root_path = "./pxe_folder/"  # root for pxe files
offset_seconds = 3600  # Time offset for countries, here is +1 Hour
server_ip = "192.168.2.1"  # your eth address to reach out (DHCP/TFTP)
subnet_mask = b'\x01\x04\xff\xff\xff\x00'  #255.255.255.0
server_tftp = server_ip.encode()  # server_ip as bytes
# TODO: Better selecting Interface
# sudo sysctl -w net.ipv4.conf.eth_old.rp_filter=0
IFACE = "br0"

# Funkja tworząca na podstawie już istniejącego pakietu od klienta, nową odpowiedź typu OFFER/ACK
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
             (b'\x00' * 64) + (b'\x00' * 128)  # sname (64B) + file (128B)

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
    options += b'\x36\x04' + socket.inet_aton(server_ip)

    # Option 1 - Subnet mask
    options += subnet_mask

    # Option 2 - Time Offset
    offset_bytes = struct.pack('>i', offset_seconds)
    options += b'\x02\x04' + offset_bytes

    # Options 3 - Router
    options += b'\x03\x04' + SIADDR

    # Options 5 - Name server
    options += b'\x05\x04' + socket.inet_aton(server_ip)

    # Option 6 - DNS (Domain Name Server)
    options += b'\x06\x04' + socket.inet_aton(server_ip)
    # Option 11 - skipped (for dns)
    # Option 12 - Hostname
    options += b'\x0c' + bytes([len(client_name)]) + client_name

    # Option 15 - Domain name
    options += b'\x0f' + bytes([len(domain_name)]) + domain_name

    # Option 17 - Root path
    #options += b'\x11' + bytes([len('/')]) + b'/'
    platform_arch = packet.getArch()
    options += b'\x11' + bytes([len(platform_arch.encode())]) + platform_arch.encode()

    # Option 43 - Vendor specific, PXE setup @option 60
    #pxe_op43 = b'\x06\x01\x02\xff'
    #options += b'\x2b' + bytes([len(pxe_op43)]) + pxe_op43

    # Option 60 - Vendor ID - turn on to get proxyDHCP Request
    #options += b'\x3c\x09PXEClient'

    # Option 66 - IP server for TFTP
    options += b'\x42' + bytes([len(server_tftp)]) + server_tftp

    # Option 67 - Filename for bootfile at TFTP server
    boot_file = file_arch[packet.getArch()].encode()
    options += b'\x43' + bytes([len(boot_file)]) + boot_file

    # \255 ending for options and packet
    options += b'\xff'

    if response_type == "ACK":
            ip_arch[clientip] = platform_arch

    return header + magic_cookie + options


# Funkcja formatująca ## ## ## ## ## ## tylko do wyświetlenia
def format_mac(mac_in: bytes, hwlen: int):
    mac = ""  # FORMAT: AA BB CC DD EE FF
    for i in range(0, hwlen):
        one_byte = bytes([mac_in[i]])
        one_char = hex(int.from_bytes(one_byte, "big"))
        if len(str(one_char)) == 3:
            one_char = "0" + str(one_char)
        mac += one_char + " "
    return mac.replace("0x", "").upper()


# Funkcja zajmująca się przydzielaniem adresów (tylko przydziela, nie zajmuje się leasingiem ani terminacją)
def dhcp_server(port_in=67, port_out=68):
    print("[DHCP] Starting new server...")
    # #1 DHCP - the client will get assigned an Address to communicate with it later
    # AF_INET - IPv4
    # SOCK_DGRAM - UDP form of communication
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, IFACE.encode())
    sock.bind(('0.0.0.0', port_in))  # DHCP clients send Discover, Request on port 67
    broadcast_addr = ('255.255.255.255', port_out)  # DHCP clients listen for Offer, ACK on port 68
    print("[DHCP] Setup complete, now listening at " + IFACE)
    while True:
        data, addr = sock.recvfrom(4096)  # retrieve packets from port 67
        packet_in = DHCP_packet(data)  # divide packet over custom class
        raw_opts = packet_in.option  # take last part of packet to search for options '53' (DISCOVER/REQUEST)
        reply = ''  # in case of failure (DISCOVER|REQUEST) send empty packet
        mac_addr = format_mac(packet_in.chaddr, packet_in.hlen)

        try:
            clients_ip[mac_addr]
        except KeyError:
            clients_ip[mac_addr] = client_prefixIP + str(len(clients_ip)+1) # TODO: ogranicznik IP do 255, albo system zwalniania IP dzierżawa

        if b'\x35\x01\x01' in raw_opts:  # check for discover
            print(f"[DHCP] Found DISCOVER \t-> OFFER {packet_in.getArch()}\thw: " + mac_addr)
            reply = create_dhcp_response(packet_in, clients_ip[mac_addr], "OFFER")
        elif b'\x35\x01\x03' in raw_opts:  # check for request
            print(f"[DHCP] Found REQUEST  \t-> ACK   {packet_in.getArch()}\thw: " + mac_addr)
            reply = create_dhcp_response(packet_in, clients_ip[mac_addr], "ACK")
        # print(f"Pozycja Magic Cookie: {reply.find(b'\x63\x82\x53\x63')}")
        sock.sendto(reply, broadcast_addr)


# https://datatracker.ietf.org/doc/html/rfc1350 (kocham dokumentacje z lat 90)
# Funkcja zajmująca się wysyłaniem danych, so far so good debiana zbootowała do instalki i głębiej
def handle_tftp_request(data, addr):
    # OPCODES page 5 rfc1350
    #   TFTP supports five types of packets, all of which have been mentioned
    #   above:
    #          opcode  operation
    #            1     Read request (RRQ)
    #            2     Write request (WRQ)
    #            3     Data (DATA)
    #            4     Acknowledgment (ACK)
    #            5     Error (ERROR)
    #   @Page 9 for TFTP formats and headers
    #   @Page 10 for error codes
    opcode = data[0] << 8 | data[1]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, IFACE.encode())
    sock.settimeout(5)
    if opcode == 1:  # Read request (RRQ)
        packetsize = 1456
        # \x00 \x01 filename   \x00 octet \x00 tsize   \x00 0 \x00
        # \x00 \x01 filename   \x00 octet \x00 blksize \x00 0 \x00 tsize  \x00 0 \x00
        # \x00 \x01 pxelinux.0 \x00 octet \x00 blksize \x00 0 \x00'
        req = data.split(b'\x00')
        #print(req)
        filename = req[1][1:]
        filename = str(filename).replace("b'", "").replace("'", "")

        try:
            path = root_path + folder_arch[ ip_arch[addr[0]] ] + "/" + filename
            size = 0
        except KeyError:
            path = root_path + 'i386' + "/" + filename
            size = 0

        path.replace('//', '/')

        try:
            size = os.path.getsize(path)
        except FileNotFoundError:
            print("[TFTP] File not found => " + path)
            try:
                path = path.split("/grub.cfg-")[0] + "grub.cfg"
                size = os.path.getsize(path)
            except FileNotFoundError:
                print("[TFTP] File not found => " + path)
                return

        if req[3] == b'blksize':        # Handshake odnośnie prędkości pobierania -> OACK
            packetsize = int(req[4])

        # OACK handler, PXE normalnie nie potrzebuje tego, ale widocznie
        if len(req) == 6 or len(req) == 8:
            packet = b''
            if len(req) == 6:
                packet=b'\x00\x06tsize\x00' + str(size).encode() + b'\x00'
            #    sock.sendto(b'\x00\x06blksize\x00' + str(packetsize).encode() + b'\x00tsize\x00' + str(size).encode() + b'\x00', addr)
            elif len(req) == 8:
                if req[6] == b'0':  # tyle zachodu bo GRUB puka zamist pobierać od razu >:((
                    packet = b'\x00\x06blksize\x00' + req[4] + b'\x00tsize\x00' + str(size).encode() + b'\x00'
                elif req[4]== b'0': # PXELinux też ma odchyły, nie ma standardu kolejności opcji dodawanych do pakietu
                    packet = b'\x00\x06tsize\x00' + str(size).encode() + b'\x00blksize\x00' + req[6] + b'\x00'

            #print (str(data) + " " + str(addr))
            sock.sendto(packet, addr)
            #print (str(packet) + " " + str(sock.getsockname()[1]))
            #oack = struct.pack("!H", 6)  # Opcode 6
            #oack += b"tsize\x00" + str(size).encode() + b"\x00"
            #oack += b"blksize\x00" + b"1408\x00"
            #print (str(oack))
            for retry in range(3):
                try:
                    ack_data, ack_addr = sock.recvfrom(1024)
                    ack_opcode, ack_block = struct.unpack("!HH", ack_data[:4])
                    if ack_opcode == 4 and ack_block == 0:
                    #    print("[TFTP] OACK accepted, lets go")
                        break
                    else:
                     #   print("[TFTP] Error accepted, closing this connect << " + str(ack_opcode) + " " + str(ack_block))
                        return
                except socket.timeout:
                     print("[TFTP] Client/OACK not responding " + str(retry + 1) + "/3 " + path)
            else:
                sock.close()
                print("[TFTP] Timeout x3 OACK")
                return

        print(f"Received TFTP request for file '{path}' from {addr} in speed {packetsize}")
        with open(path, 'rb') as f:
            i = int(1)  #number of block
            while True:
                # page 9 - byte 0 | byte 3 | block numer | data
                data = f.read(packetsize)
                packet = b'\x00\x03' + bytes([int(i / 256)]) + bytes([i % 256]) + data
                exit_req = 0
                for retry in range(3):
                    sock.sendto(packet, addr)
                    print("[TFTP] Sending " + filename + " => " + str(int(i/256)) + "/" + str(int(i%256)) + " packet -> DATA")
                    try:
                        ack_data, ack_addr = sock.recvfrom(1024)
                        ack_opcode, ack_block = struct.unpack("!HH", ack_data[:4])
                        if ack_opcode == 4 and ack_block == i:
                            break
                        else:
                            print("[TFTP] Error accepted, closing this connect << " + str(ack_opcode) + " " + str(
                                ack_block))
                            exit_req = 1
                            break
                    except socket.timeout:
                        print("[TFTP] " + str(retry + 1) + "/3")
                else:
                    print("[TFTP] Timeout x3 interrupting")
                    return
                if exit_req:
                    print("[TFTP] Sending has been interrupted")
                    return
                if len(data) < packetsize:  #jeżeli dane nie wypełniły pełnego bloku to oznacza że nie ma co czytać już
                    f.close()
                    print("[TFTP] " + filename + " has been sent in " + str(i) + " blocks")
                    sock.close()
                    return
                i = i + 1  #???? i++ to nie, ale i+=1 to tak
    elif opcode == 2:  # Write request #TODO: dodaj obsługę write request; zwróć jakiś ICMP czy coś
        print("That doesnt make sense? write request from pxe boot handler?")
    elif opcode == 3:  # DATA   #TODO: ??? pakiet od klienta z danymi nie jest potrzebny
        print("got DATA opcode")
    elif opcode == 4:  # ACK    #TODO: ACK jest obsługiwany wewnątrz opcode 1
        print("got ACK")
    else:  # 5 == Error #TODO: ayayay karamba
        print("Unsupported TFTP request opcode == " + str(opcode))


# Funkcja zajmująca się przekierowaniem do pobierania danych
def tftp_server(port=69):
    #2 TFTP - trivial file transfer protocol - client will be able to access files eg. kernel, bootloader
    print("[TFTP] Starting new server...")
    tftp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tftp_sock.bind(("0.0.0.0", port))
    print("[TFTP] Setup complete, now listening")
    while True:
        # Read and dispatch tftp get request
        data, addr = tftp_sock.recvfrom(4096)
        #TODO: Popraw threading - tak aby tworzył kolejne instancje na kilka próśb
        print(addr)
        thread_sendfile = threading.Thread(target=handle_tftp_request, args=(data, addr), daemon=True)
        thread_sendfile.start()


if __name__ == '__main__':
    if not exists(root_path):
        os.mkdir(root_path)

    thread_dhcp = threading.Thread(target=dhcp_server)
    thread_tftp = threading.Thread(target=tftp_server)
    thread_dhcp.start()
    thread_tftp.start()
