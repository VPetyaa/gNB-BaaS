pktnum = 100000
netpacket_ack_no_nack = {}
netpacket_gtp = {}
netpacket_ack = {}
netpacket_rlc_status = {}

for i in range(pktnum):
    rand_part = os.urandom(10)
    teid = os.urandom(4)
    seq_num = os.urandom(2)
    netpacket_ack_no_nack[i] = Ether()/IP()/UDP(dport=12345)/Raw(b'\xff' + teid + seq_num+ rand_part)
    netpacket_ack[i] = Ether()/IP()/UDP(dport=12345)/Raw(b'\x00'+ teid + seq_num + rand_part)
    netpacket_gtp[i] = Ether()/IP()/UDP(dport=2152)/Raw(b'\xff\xff\xff\xff' + teid + seq_num)
    netpacket_rlc_status[i] = Ether()/IP()/UDP(sport=8040, dport=65359)/Raw( b''+((int.from_bytes(seq_num, "big") << 34) + int.from_bytes(teid, "big")).to_bytes(7, 'big'))

for i in range(pktnum):
    wrpcap(str(pktnum)+'packet_with_ack.pcap', netpacket_ack_no_nack[i], append=True)
    wrpcap(str(pktnum)+'packet_with_no_ack.pcap', netpacket_ack_no_nack[i], append=True)
    wrpcap(str(pktnum)+'gtp.pcap', netpacket_gtp[i], append=True)

for i in range(pktnum):
    wrpcap(str(pktnum)+'packet_with_ack.pcap', netpacket_ack[i], append=True)
    wrpcap(str(pktnum)+'packet_with_just_ack.pcap', netpacket_ack[i], append=True)
    wrpcap(str(pktnum)+'rlc_status.pcap', netpacket_rlc_status[i], append=True)


