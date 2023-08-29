# physical_buffer

=======================
|    START HIRAN      |
=======================
export SDE=/p4sde/bf-sde-8.9.1
export SDE_INSTALL=$SDE/install
/home/vpetya/p4_codes/BufferAsAService/tofino_p4_code/src/p4_build.sh /home/vpetya/p4_codes/BufferAsAService/tofino_p4_code/src/hiran.p4
cd $SDE
./run_switchd.sh -p hiran

=======================
|    FILL TABLES      |
=======================
bfrt_python /home/vpetya/physical_buffer/scripts/setup.py


=======================
|         UCLI        |
=======================
ucli
pm
port-del -/-
port-dis -/-
port-add 1/- 100G RS
port-add 2/- 100G RS
port-enb 1/-
port-enb 2/-
show


=======================
|      RECORD PKTS    |
=======================
sudo tcpdump -i enp5s0f1 -vvvv -w rlc1.pcap


=======================
| SCAPY SEND GTP PKT  |
=======================
a1 = '000c29dad1de000c29e3c64d08004500007c00004000401167bbc0a828b3c0a828b2086808680068bf6432ff0058'
gtp_teid = '00000002'
a2 = '28db0000450000540000400040015ea5ca0b289ec0a828b20800bee70000287b0411204bf43d0d0008090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637'
a = a1 + gtp_teid + a2
b = a.decode('hex')
B = Ether(b)
B.show()
sendp(B, iface='enp10s0f0')

========================
| SCAPY GEN N GTP PKT  |
========================
a1 = '000c29dad1de000c29e3c64d08004500007c00004000401167bbc0a828b3c0a828b2086808680068bf6432ff0058'
int_to_four_bytes = struct.Struct('<I').pack
a2 = '28db0000450000540000400040015ea5ca0b289ec0a828b20800bee70000287b0411204bf43d0d0008090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637'
for i in range(10000):
	gtp_teid=i#int_to_four_bytes(i & 0xFFFFFFFF)
	a = a1 + str(gtp_teid).zfill(8) + a2
	b = a#.decode('hex')
	B = Ether(b)
	B.show()
	wrpcap('gtp_traffic_10kid.pcap', B, append=True)

==============================
|  SCAPY GENERATE N PDCP NEW |
==============================
import random
import os, codecs
int_to_four_bytes = struct.Struct('<I').pack
num_digits = 24
addr = bytearray.fromhex(codecs.encode(os.urandom((int)(num_digits / 2)), 'hex').decode())
a1 = bytearray.fromhex("08004500" \
"007c00004000401167bb")
a2 = bytearray.fromhex("ff4f0068bf64644800010100" \
"05000300d601c0706463702d6c746500" \
"01000300040105000600000700080009" \
"010a000b000c000001")
ack = bytearray.fromhex("00") ## FF MEANS ACK
a3 = bytearray.fromhex("89675ef20000" \
"450000540000400040015ea5ca0b289e" \
"c0a828b20800bee70000287b0411204b" \
"f43d0d0008090a0b0c0d0e0f10111213" \
"1415161718191a1b1c1d1e1f20212223" \
"2425262728292a2b2c2d2e2f30313233" \
"450000540000400040015ea5ca0b289e" \
"c0a828b20800bee70000287b0411204b" \
"f43d0d0008090a0b0c0d0e0f10111213" \
"1415161718191a1b1c1d1e1f20212223" \
"2425262728292a2b2c2d2e2f30313233" \
"450000540000400040015ea5ca0b289e" \
"c0a828b20800bee70000287b0411204b" \
"f43d0d0008090a0b0c0d0e0f10111213" \
"1415161718191a1b1c1d1e1f20212223" \
"2425262728292a2b2c2d2e2f30313233" \
"c0a828b20800bee70000287b0411204b" \
"f43d0d0008090a0b0c0d0e0f10111213" \
"1415161718191a1b1c1d1e1f20212223" \
"2425262728292a2b2c2d2e2f30313233" \
"450000540000400040015ea5ca0b289e" \
"c0a828b20800bee70000287b0411204b" \
"f43d0d0008090a0b0c0d0e0f10111213" \
"1415161718191a1b1c1d1e1f20212223" \
"2425262728292a2b2c2d2e2f30313233" \
"450000540000400040015ea5ca0b289e" \
"c0a828b20800bee70000287b0411204b" \
"f43d0d0008090a0b0c0d0e0f10111213" \
"1415161718191a1b1c1d1e1f20212223" \
"2425262728292a2b2c2d2e2f30313233" \
"c0a828b20800bee70000287b0411204b" \
"f43d0d0008090a0b0c0d0e0f10111213" \
"1415161718191a1b1c1d1e1f20212223" \
"2425262728292a2b2c2d2e2f30313233" \
"450000540000400040015ea5ca0b289e" \
"c0a828b20800bee70000287b0411204b" \
"f43d0d0008090a0b0c0d0e0f10111213" \
"1415161718191a1b1c1d1e1f20212223" \
"2425262728292a2b2c2d2e2f30313233" \
"450000540000400040015ea5ca0b289e" \
"c0a828b20800bee70000287b0411204b" \
"f43d0d0008090a0b0c0d0e0f10111213" \
"1415161718191a1b1c1d1e1f20212223" \
"2425262728292a2b2c2d2e2f30313233" \
"c0a828b20800bee70000287b0411204b" \
"f43d0d0008090a0b0c0d0e0f10111213" \
"1415161718191a1b1c1d1e1f20212223" \
"2425262728292a2b2c2d2e2f30313233" \
"450000540000400040015ea5ca0b289e" \
"c0a828b20800bee70000287b0411204b" \
"f43d0d0008090a0b0c0d0e0f10111213" \
"1415161718191a1b1c1d1e1f20212223" \
"2425262728292a2b2c2d2e2f30313233" \
"450000540000400040015ea5ca0b289e" \
"c0a828b20800bee70000287b0411204b" \
"f43d0d0008090a0b0c0d0e0f10111213" \
"1415161718191a1b1c1d1e1f20212223" \
"2425262728292a2b2c2d2e2f30313233" \
"2425" \
"34353637")

import random
for i in range(100000):
    addr = bytearray.fromhex(codecs.encode(os.urandom((int)(num_digits / 2)), 'hex').decode())
    ipaddr = bytearray.fromhex(codecs.encode(os.urandom(8), 'hex').decode())
    srcport = bytearray.fromhex(codecs.encode(os.urandom(2), 'hex').decode())
    packet_ueid=bytearray(int_to_four_bytes(i & 0xFFFFFFFF))
    a = bytes(addr) + bytes(a1) + bytes(ipaddr) + bytes(srcport) +bytes(a2) + bytes(ack) + bytes(packet_ueid) + bytes(a3)
    #a = daddr + a1 + ack + packet_ueid + a2
    B = Ether(a)
    #B.show()
    wrpcap('pdcp_traffic_1024B_100kid_rss.pcap', B, append=True)

=======================
| SCAPY RECEIVE PDCP  |
=======================
x = sniff(iface="enp5s0f1", count=2)
sendp(x[1], iface='enp5s0f1')


=======================
|    SCAPY REPEATER   |
=======================
while (1):
    x = sniff(iface="veth8", count=1)
    if x[0][Ether].type == 0xabef:
        sendp(x, iface="veth8")
    else:
        print(x)

while (1):
    x = sniff(iface="veth0", count=1)
    if x[0][Ether].type == 0xabef:
        sendp(x, iface="veth0")
    else:
        print(x)

