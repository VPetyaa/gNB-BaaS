/* P4_16 */
#include <core.p4> // Mandatory for all programs.
#include <tna.p4>

/** Headers **/


/* Ethernet header definition */
header eth_h {
        bit<48> dmac;
        bit<48> smac;
        bit<16> type;
}

header ipv4_h {
        bit<4>  version;
        bit<4>  ihl;
        bit<8>  diffserv;
        bit<16> totalLen;
        bit<16> identification;
        bit<3>  flags;
        bit<13> fragOffset;
        bit<8>  ttl;
        bit<8>  protocol;
        bit<16> hdrChecksum;
        bit<32> srcAddr;
        bit<32> dstAddr;
}

header udp_h {
        bit<16> srcPort;
        bit<16> dstPort;
        bit<16> len;
        bit<16> checksum;
}

header inner_ipv4_h {
        bit<4>  version;
        bit<4>  ihl;
        bit<8>  diffserv;
        bit<16> totalLen;
        bit<16> identification;
        bit<3>  flags;
        bit<13> fragOffset;
        bit<8>  ttl;
        bit<8>  protocol;
        bit<16> hdrChecksum;
        bit<32> srcAddr;
        bit<32> dstAddr;
}

header inner_udp_h {
        bit<16> srcPort;
        bit<16> dstPort;
        bit<16> len;
        bit<16> checksum;
}

header gtpu_h {
        bit<8>  flags;
        bit<8>  type;
        bit<16> length;
        bit<32> teid;
        bit<16> seq_num;
}

header rlc_ack_mode_h {
        bit<1>  dc;
        bit<1>  p;
        bit<2>  si;
        bit<2>  r;
        bit<2>  snpadding;
        bit<16> sn;
        bit<32> teid;  //NOT SURE WHERE TO STORE IT
}

header rlc_status_h {
        bit<1>  dc;
        bit<3>  cpd;
        bit<2>  snpadding;
        bit<16> sn;
        bit<1>  e;
        bit<1>  r;
        bit<32> teid;  //NOT SURE WHERE TO STORE IT
}

header rlc_nack_h{
        bit<18> sn;
        bit<3>  e;
        bit<3>  r;
}

header physical_buffer_h {
        bit<8>  nack_count;
        bit<32> endpoint_id;
        bit<16> ack_sn;
}

const bit<16>  ETHPROTO_IPV4    = 0x0800;
const bit<8>   IPPROTO_TCP      = 6;
const bit<8>   IPPROTO_UDP      = 17;
const bit<9>   PHYS_BUFF_PORT   = 163;
const bit<9>   DOWNLINK_PORT    = 162;
const bit<9>   UPLINK_PORT      = 162;
const bit<16>  UDP_PORT_GTPU    = 2152;
const bit<16>  UDP_SPORT_RLC    = 8040;
const bit<16>  UDP_DPORT_RLC    = 65359;
const bit<16>  UDP_PORT_BUFFER  = 12345;

Hash<bit<32>>(HashAlgorithm_t.IDENTITY) cp_hash;
Hash<bit<32>>(HashAlgorithm_t.IDENTITY) cp_hash2;
Hash<bit<32>>(HashAlgorithm_t.IDENTITY) cp_hash3;
Hash<bit<32>>(HashAlgorithm_t.IDENTITY) cp_hash4;
Hash<bit<16>>(HashAlgorithm_t.IDENTITY) cp_hash5;

/* Ingress Pipe */

/* Headers to parse */
struct ingress_headers_t {
        eth_h                   eth;
        ipv4_h                  ipv4;
        udp_h                   udp;
        gtpu_h                  gtp;
        rlc_status_h            rlc_status;
        physical_buffer_h       buffering;
        rlc_nack_h[3]           rlc_nack;
        rlc_ack_mode_h          rlc_ack_mode;
        inner_ipv4_h            inneripv4;
        inner_udp_h             innerudp;
}

/* Intermediate data available for Ingress */
struct ingress_metadata_t {
}

/* Parsing logic */
parser IngressParser(packet_in  pkt,
        out ingress_headers_t   hdr,
        out ingress_metadata_t  meta,
        out ingress_intrinsic_metadata_t ig_intr_md)
{
        state start {
                pkt.extract(ig_intr_md);
                pkt.advance(PORT_METADATA_SIZE);
                transition parse_ethernet;
        }

        state parse_ethernet {
                pkt.extract(hdr.eth);
                transition select (hdr.eth.type){
                        ETHPROTO_IPV4   :       parse_ipv4;
                        default         :       accept;
                }
        }

        state parse_ipv4 {
                pkt.extract(hdr.ipv4);
                transition select (hdr.ipv4.protocol){
                        IPPROTO_UDP     :       parse_udp;
                        default :       accept;
                }
        }

        state parse_udp {
                pkt.extract(hdr.udp);
                transition select (hdr.udp.dstPort) {
                        UDP_PORT_GTPU   :       parse_gtp;
                        UDP_DPORT_RLC   :       parse_rlc;
                        UDP_PORT_BUFFER :       parse_phys_buffer;
                        default         :       accept;
                }
        }

        state parse_gtp {
                pkt.extract(hdr.gtp);
                        transition accept;
                }

        state parse_phys_buffer {
                pkt.extract(hdr.buffering);
                transition select(hdr.buffering.nack_count){
                        0       :       parse_inner_headers;
                        default :       parse_rlc_status_nacks;
                }
        }

        state parse_rlc {
                transition select(pkt.lookahead<bit<1>>()){
                        0       :       parse_rlc_status;
                        1       :       parse_rlc_ack_mode;
                }
        }

        state parse_rlc_ack_mode {
                pkt.extract(hdr.rlc_ack_mode);
                transition accept;
        }

        state parse_rlc_status {
                pkt.extract(hdr.rlc_status);
                hdr.buffering.nack_count = 0;
                transition select(hdr.rlc_status.e){
                        1       :       parse_rlc_status_nacks;
                        0       :       accept;
                }
        }

        state parse_rlc_status_nacks {
                pkt.extract(hdr.rlc_nack.next);
                transition select(hdr.rlc_nack.last.e){
                        1       :       parse_rlc_status_nacks;
                        default :       count_nacks;
                }
        }

        state count_nacks {
                //hdr.buffering.nack_count = (bit<6>)hdr.rlc_nack.lastIndex; //BUG?
                transition parse_inner_headers;
        }

	state parse_inner_headers {
		pkt.extract(hdr.rlc_ack_mode);
		pkt.extract(hdr.inneripv4);
		pkt.extract(hdr.innerudp);
		transition accept;
	}

}

control IngressDeparser(packet_out pkt,
inout ingress_headers_t hdr,
in ingress_metadata_t   meta,
in ingress_intrinsic_metadata_for_deparser_t    ig_dprsr_md)
{
        apply {
                pkt.emit(hdr);
        }
}

control Ingress(

        /* user defined */
        inout ingress_headers_t         hdr,
        inout ingress_metadata_t        meta,

        /* system defined */
        in ingress_intrinsic_metadata_t                 ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t     ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t       ig_tm_md) {

        action uplink() {
                hdr.gtp.setValid();
                hdr.gtp.flags = 0x32;
                hdr.gtp.type = 0xff;
                hdr.gtp.length = 88;
                //hdr.gtp.teid = hdr.rlc_ack_mode.teid; //PHV ERR FIXED WITH IDENTICAL HASH 
                hdr.gtp.seq_num = hdr.rlc_ack_mode.sn;
                hdr.udp.dstPort = UDP_PORT_GTPU;

                hdr.rlc_ack_mode.setInvalid();
                ig_tm_md.ucast_egress_port = UPLINK_PORT;
        }

        action buffering(){
                hdr.buffering.setValid();
                //hdr.buffering.endpoint_id = hdr.gtp.teid; //PHV ERR FIXED WITH IDENTICAL HASH
                hdr.buffering.ack_sn = hdr.gtp.seq_num;
                hdr.buffering.nack_count = 0xff; //0xff MEANS NOT A STATUS MESSAGE

                hdr.gtp.setInvalid();
                hdr.inneripv4.setValid();
                hdr.innerudp.setValid();
                hdr.inneripv4 = hdr.ipv4;
                hdr.innerudp = hdr.udp;

                hdr.rlc_ack_mode.setValid();
                hdr.rlc_ack_mode.dc=1;
                hdr.rlc_ack_mode.p=0x000;
                hdr.rlc_ack_mode.si=0x00;
                hdr.rlc_ack_mode.r=0x00;
                hdr.rlc_ack_mode.sn = hdr.buffering.ack_sn;

                hdr.udp.dstPort = UDP_PORT_BUFFER;
                ig_tm_md.ucast_egress_port = PHYS_BUFF_PORT;    //SENT TO BUFFERING
        }

        action status_buffering(){
                hdr.buffering.setValid();
                //hdr.buffering.nack_count = (bit<6>)hdr.rlc_nack.lastIndex; //DONE IN PARSER
                hdr.buffering.nack_count = 0; //TODO REMOVE
                hdr.buffering.endpoint_id = hdr.rlc_status.teid;
                hdr.rlc_status.setInvalid();
                hdr.udp.dstPort = UDP_PORT_BUFFER;
                ig_tm_md.ucast_egress_port = PHYS_BUFF_PORT;    //SEND TO BUFFER FOR REMOVAL OR RESUBMIT
        }

        action retransmit_from_buffer(){
                hdr.ipv4 = hdr.inneripv4;
                hdr.udp = hdr.innerudp;
                hdr.inneripv4.setInvalid();
                hdr.innerudp.setInvalid();
                hdr.buffering.setInvalid();
                ig_tm_md.ucast_egress_port = DOWNLINK_PORT;
        }

        apply {
                if (ig_intr_md.ingress_port == PHYS_BUFF_PORT){
                        hdr.rlc_ack_mode.teid = cp_hash.get(hdr.buffering.endpoint_id);
                        retransmit_from_buffer();
                }else{
                        if (hdr.gtp.isValid()){                 //IF PACKET IS GTP
                                hdr.buffering.endpoint_id = cp_hash2.get(hdr.gtp.teid);
                                buffering();
                        }else if(hdr.rlc_status.isValid()){     //IF PACKET IS RLC STATUS
                                hdr.buffering.ack_sn = cp_hash5.get(hdr.rlc_status.sn);
                                status_buffering();
                        }else if(hdr.rlc_ack_mode.isValid()){   //IF PACKET IS RLC BUT NOT STATUS
                                hdr.gtp.teid = cp_hash4.get(hdr.rlc_ack_mode.teid);
                                uplink();
                        }
                }

                // No need for egress processing, skip it and use empty controls for egress.
                ig_tm_md.bypass_egress = 1;
        }
}


/* Egress Pipe */
struct egress_headers_t {}
struct egress_metadata_t {}
parser EgressParser(packet_in pkt,
        out egress_headers_t    hdr,
        out egress_metadata_t   meta,
        out egress_intrinsic_metadata_t eg_intr_md)
{
        state start {
                pkt.extract(eg_intr_md);
                transition accept;
        }
}
control Egress(
/* user defined */
inout egress_headers_t          hdr,
inout egress_metadata_t         meta,

/* system defined */
in egress_intrinsic_metadata_t                  eg_intr_md,
in egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
inout egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md,
inout egress_intrinsic_metadata_for_output_port_t       eg_tm_md) {
        apply {
        }
}

control EgressDeparser(packet_out pkt,
inout egress_headers_t          hdr,
in egress_metadata_t    meta,
in egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md) {
        apply {
        }
}


/* Complete Pipeline */
Pipeline(
        IngressParser(), Ingress(), IngressDeparser(),
        EgressParser(), Egress(), EgressDeparser()
) pipe;

Switch(pipe) main;

