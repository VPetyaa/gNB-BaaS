/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation
 */
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <unistd.h>

#ifndef BAAS_UDP_PORT
# define BAAS_UDP_PORT 12346
#endif

#ifndef BAAS_RSS_HF
# define BAAS_RSS_HF ETH_RSS_IPV4 | ETH_RSS_NONFRAG_IPV4_TCP | ETH_RSS_NONFRAG_IPV4_UDP | ETH_RSS_IPV6 | ETH_RSS_NONFRAG_IPV6_TCP | ETH_RSS_NONFRAG_IPV6_UDP | ETH_RSS_IPV6_EX | ETH_RSS_IPV6_TCP_EX | ETH_RSS_IPV6_UDP_EX
#endif

#ifndef BAAS_RX_OFFLOADS
# define BAAS_RX_OFFLOADS DEV_RX_OFFLOAD_CHECKSUM
#endif

#ifndef BAAS_TIMER_RESOLUTION
# define BAAS_TIMER_RESOLUTION 10000.0
#endif

static struct rte_hash_parameters ut_params = {
    .name = "BufferTable",
    .entries = 1024*1024,
    .key_len = sizeof(uint64_t),
    .hash_func = rte_jhash,
    .hash_func_init_val = 0,
    .socket_id = 0,
};

static struct rte_hash_parameters ut_params_teid = {
    .name = "BufferTableTeid",
    .entries = 1024*1024,
    .key_len = sizeof(uint32_t),
    .hash_func = rte_jhash,
    .hash_func_init_val = 0,
    .socket_id = 0,
};

//#define DEBUG_BUILD 1
#ifdef DEBUG_BUILD
#define DEBUG(...) fprintf(stderr, __VA_ARGS__)
#else
#define DEBUG(...) \
    do {           \
    } while(0)
#endif
#define PKTSIZE 1152
#define USE_DIFFERENT_POOL_FOR_LCORES 0

static uint8_t mempool_num = 0;
static uint8_t resubmission_time = 10; //MS

struct packet_in_buffer_t {
    struct rte_mbuf * pkt;
    uint8_t portid;
    uint64_t pktid;
};

struct bucket_t {
    struct packet_in_buffer_t ** data;
    uint16_t last_element;
    uint16_t count;
};

static volatile bool force_quit;

#define RTE_LOGTYPE_L2FWD RTE_LOGTYPE_USER1

#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN_US 1 /* TX drain every ~100us */ //100
#define MEMPOOL_CACHE_SIZE 512

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;
static const int bucket_size = 1024 * 128;

/* ethernet addresses of ports */
static struct rte_ether_addr l2fwd_ports_eth_addr[RTE_MAX_ETHPORTS];

/* mask of enabled ports */
static uint32_t l2fwd_enabled_port_mask = 0;

/* list of enabled ports */
static uint32_t l2fwd_dst_ports[RTE_MAX_ETHPORTS];

static unsigned int l2fwd_rx_queue_per_lcore = 1;

#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 16
struct lcore_queue_conf {
    unsigned n_rx_port;
    unsigned rx_port_list[MAX_RX_QUEUE_PER_LCORE];
}
__rte_cache_aligned;
struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];
struct bucket_t* global_buckets[RTE_MAX_LCORE];

//static struct rte_eth_dev_tx_buffer * tx_buffer[RTE_MAX_ETHPORTS];
static struct rte_eth_dev_tx_buffer * tx_buffer[RTE_MAX_ETHPORTS][RTE_MAX_LCORE];

struct rte_eth_conf port_conf = {
    .rxmode = {
        .mq_mode = ETH_MQ_RX_RSS,
        .max_rx_pkt_len = 128,//RTE_ETHER_MAX_LEN,
        .split_hdr_size = 0,
        .offloads = BAAS_RX_OFFLOADS,
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = NULL,
            .rss_hf = (BAAS_RSS_HF),
        },
    },
    .txmode = {
        .mq_mode = ETH_MQ_TX_NONE,
    },
};

struct rte_mempool ** l2fwd_pktmbuf_pool;
struct rte_mempool *  clone_pktmbuf_pool;

/* Per-port statistics struct */
struct l2fwd_port_statistics {
    uint64_t tx;
    uint64_t rx;
    uint64_t dropped;
    uint64_t deleted;
    uint64_t inserted;
}
__rte_cache_aligned;
struct l2fwd_port_statistics port_statistics[RTE_MAX_LCORE];

#define MAX_TIMER_PERIOD 86400 /* 1 day max */
/* A tsc-based timer responsible for triggering statistics printout */
static uint64_t timer_period = 3; /* default period is 3 seconds */

/* Print out statistics on packets dropped */
static void
print_stats(void) {
    uint64_t total_packets_dropped, total_packets_tx, total_packets_rx;
    unsigned portid;

    total_packets_dropped = 0;
    total_packets_tx = 0;
    total_packets_rx = 0;

    const char clr[] = {
        27,
        '[',
        '2',
        'J',
        '\0'
    };
    const char topLeft[] = {
        27,
        '[',
        '1',
        ';',
        '1',
        'H',
        '\0'
    };

    /* Clear screen and move to top left */
    //printf("%s%s", clr, topLeft);

    printf("\nPort statistics ====================================");

    for (portid = 0; portid < RTE_MAX_LCORE; portid++) {
        /* skip disabled ports */
        if ((rte_lcore_is_enabled(portid)) == 0)
            continue;
        printf("\nStatistics for lcore %u ------------------------------"
            "\nPackets sent: %24"
            PRIu64 "\nPackets received: %20"
            PRIu64 "\nPackets dropped: %21"
            PRIu64 "\nPackets buffered: %20"
            PRIu64 "\nPackets deleted: %21"
            PRIu64,
            portid,
            port_statistics[portid].tx,
            port_statistics[portid].rx,
            port_statistics[portid].dropped,
            port_statistics[portid].inserted,
            port_statistics[portid].deleted);

        total_packets_dropped += port_statistics[portid].dropped;
        total_packets_tx += port_statistics[portid].tx;
        total_packets_rx += port_statistics[portid].rx;
    }
    printf("\nAggregate statistics ==============================="
        "\nTotal packets sent: %18"
        PRIu64 "\nTotal packets received: %14"
        PRIu64 "\nTotal packets dropped: %15"
        PRIu64,
        total_packets_tx,
        total_packets_rx,
        total_packets_dropped);
    printf("\n====================================================\n");
    fflush(stdout);
}

static struct packet_in_buffer_t** insert_packet_to_bucket(struct bucket_t * current_bucket, struct rte_mbuf * m, uint8_t portid, uint64_t pktid) {
    if (current_bucket -> last_element >= bucket_size){
        return NULL;
    }
    struct packet_in_buffer_t** ptr = &current_bucket -> data[current_bucket -> last_element];
    if(current_bucket -> data[current_bucket -> last_element] == 0x0)
        current_bucket -> data[current_bucket -> last_element] = malloc(sizeof(struct packet_in_buffer_t));
    current_bucket -> data[current_bucket -> last_element] -> pkt = m;
    current_bucket -> data[current_bucket -> last_element] -> portid = portid;
    current_bucket -> data[current_bucket -> last_element] -> pktid = pktid;
    current_bucket -> last_element++;
    current_bucket -> count++;
    return ptr;
}

static void remove_packet_from_bucket(struct bucket_t * current_bucket, struct packet_in_buffer_t * pointer_to_packet_in_bucket) {
    pointer_to_packet_in_bucket->pkt = 0x0;
    pointer_to_packet_in_bucket->portid = 0x0;
    pointer_to_packet_in_bucket->pktid = 0x0;
    rte_pktmbuf_free(pointer_to_packet_in_bucket->pkt);
    if (current_bucket -> count > 0)
        current_bucket -> count--;
}

static void resend_packet_from_bucket(struct packet_in_buffer_t * pointer_to_packet_in_bucket) {
    struct rte_mbuf* cloned_pkt;
    if (unlikely ((cloned_pkt = rte_pktmbuf_clone(pointer_to_packet_in_bucket->pkt, clone_pktmbuf_pool)) == NULL)){
        return;
    }

    uint8_t portid = pointer_to_packet_in_bucket -> portid;
    unsigned dst_port = l2fwd_dst_ports[portid];
    uint8_t lcoreindex = rte_lcore_index(rte_lcore_id());
    struct rte_eth_dev_tx_buffer * buffer = tx_buffer[portid][lcoreindex];
    int sent = rte_eth_tx_buffer(dst_port, lcoreindex, buffer, cloned_pkt);
    if (sent)
        port_statistics[rte_lcore_id()].tx += sent;
}

static void send_out_current_bucket_wo_removal(struct bucket_t * current_bucket, struct rte_hash* buffer_table, uint8_t lcoreindex) {
    DEBUG("NOTICE, SENDING OUT BUCKET\n");
    uint8_t shift_packets_by_index = 0;
    if (current_bucket -> last_element == 0)
        current_bucket->count = 0;

    for (int i = 0; i < current_bucket -> last_element; i++) {
        struct rte_eth_dev_tx_buffer * buffer;
        int sent;
        if (current_bucket -> data[i] == 0x0)
	    current_bucket -> data[i] = malloc(sizeof(struct packet_in_buffer_t));
        if (current_bucket -> data[i] -> pkt != 0x0) {
            uint8_t portid = current_bucket -> data[i] -> portid;
            unsigned dst_port = l2fwd_dst_ports[portid];
            buffer = tx_buffer[portid][lcoreindex];

            if (shift_packets_by_index > 0){
                DEBUG("WARNING, - SHIFTING NEEDED %d\n", shift_packets_by_index);
                current_bucket -> data[i-shift_packets_by_index]->pkt = current_bucket -> data[i]->pkt;
                current_bucket -> data[i-shift_packets_by_index]->portid = current_bucket -> data[i]->portid;
                current_bucket -> data[i-shift_packets_by_index]->pktid = current_bucket -> data[i]->pktid;
                current_bucket -> data[i]->pkt = 0x0;
                current_bucket -> data[i]->portid = 0x0;
                current_bucket -> data[i]->pktid = 0x0;
                struct packet_in_buffer_t** ptr = &current_bucket -> data[i-shift_packets_by_index];

                //rte_hash_del_key(buffer_table, &current_bucket -> data[i-shift_packets_by_index]->pktid);
                int ret = rte_hash_add_key_data(buffer_table, &(current_bucket -> data[i-shift_packets_by_index]->pktid), *ptr);
                if (ret == 22){
                    DEBUG("ERROR INSERTION: %d WRONG PARAM\n", ret);
                    rte_exit(EXIT_FAILURE, "UNABLE TO STORE HASH ENTRY WRONG PARAM\n");
                }else if (ret == ENOSPC){
                    DEBUG("ERROR INSERTION: %d NO SPACE\n", ret);
                    rte_exit(EXIT_FAILURE, "UNABLE TO STORE HASH ENTRY NO SPACE\n");
                }else{
                    DEBUG("NOTICE, INSERTION %d OK\n", ret);
                }


            }
            DEBUG("NOTICE, CLONING\n");
            struct rte_mbuf* cloned_pkt;
            if (current_bucket -> data[i-shift_packets_by_index] -> pkt == 0x0 || unlikely ((cloned_pkt = rte_pktmbuf_clone(current_bucket -> data[i-shift_packets_by_index] -> pkt, clone_pktmbuf_pool)) == NULL)){
                rte_pktmbuf_free(cloned_pkt);
                continue;
            }
            DEBUG("NOTICE, CLONING DONE\n");
            sent = rte_eth_tx_buffer(dst_port, lcoreindex, buffer, cloned_pkt);
            if (sent)
                port_statistics[rte_lcore_id()].tx += sent;
        }else{
            shift_packets_by_index++;
        }
    }
    current_bucket -> last_element -= shift_packets_by_index;
    //current_bucket -> count = current_bucket -> last_element;
}

#if 0
static void send_out_current_bucket(struct bucket_t * current_bucket, struct rte_hash* buffer_table, uint8_t lcoreindex) {
    for (int i = 0; i < current_bucket -> last_element; i++) {
        struct rte_eth_dev_tx_buffer * buffer;
        int sent;
        if (current_bucket -> data[i] -> pkt != 0x0) {
            uint8_t portid = current_bucket -> data[i] -> portid;
            unsigned dst_port = l2fwd_dst_ports[portid];
            buffer = tx_buffer[portid][lcoreindex];
            sent = rte_eth_tx_buffer(dst_port, lcoreindex, buffer, current_bucket -> data[i] -> pkt);

            rte_hash_del_key(buffer_table, &current_bucket -> data[i] -> pktid);

            current_bucket -> data[i] -> pkt = 0x0;
            current_bucket -> data[i] -> portid = 0x0;
            current_bucket -> data[i] -> pktid = 0x0;
            if (sent)
                port_statistics[rte_lcore_id()].tx += sent;
        }
    }
    current_bucket -> last_element = 0;
    current_bucket -> count = 0;
}
#endif

static bool
array_contains(uint64_t element, uint64_t array[], uint32_t array_size){
    for (uint32_t i=0; i<array_size; i++)
        if (array[i] == element)
            return true;
    return false;
}

static void
handle_incoming_packet(struct rte_mbuf * m, struct bucket_t * current_bucket, struct rte_hash* buffer_table, struct rte_hash* buffer_table_teid, uint8_t portid) {
    uint8_t * data_start = rte_pktmbuf_mtod(m, uint8_t * );
    if (unlikely(data_start == 0x0)) return;

    if (*(uint16_t *)(data_start + 12) != htobe16(0x800)){
        rte_pktmbuf_free(m);
        return;
    }

    //SWAP MAC ADDRESSES
    struct rte_ether_hdr *eth;
    struct rte_ether_addr tmp;
    eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    rte_ether_addr_copy(&eth->d_addr, &tmp);
    rte_ether_addr_copy(&eth->s_addr, &eth->d_addr);
    rte_ether_addr_copy(&tmp, &eth->s_addr);

    uint8_t *ip = data_start + 14;
    if (ip[0] != 0x45 || ip[9] != 17){ // ipv4+udp
        rte_pktmbuf_free(m);
        return;
    }

    //SWAP IP ADDRESSES
    uint32_t tmp_ip;
    tmp_ip = *(uint32_t*)(ip+12);
    *(uint32_t*)(ip+12) = *(uint32_t*)(ip+16);
    *(uint32_t*)(ip+16) = tmp_ip;


    uint8_t *udp = ip + 20;
    if (*(uint16_t*)(udp + 0) != htobe16(BAAS_UDP_PORT) ||
        *(uint16_t*)(udp + 2) != htobe16(BAAS_UDP_PORT)){
        rte_pktmbuf_free(m);
        return;
    }

    //SWAP UDP PORTS
    uint16_t udp_tmp;
    udp_tmp = *(uint16_t*)(udp + 0);
    *(uint16_t*)(udp + 0) = *(uint16_t*)(udp + 2);
    *(uint16_t*)(udp + 2) = udp_tmp;

    uint8_t *buffheader = udp + 8;

    uint8_t  nack_count = *buffheader;
    uint64_t endpoint_id = *(uint32_t * )(buffheader + 1);
    uint16_t ack_sequence_number = be16toh(* (uint16_t * )(buffheader + 1+4));
    uint64_t packet_id = (endpoint_id<<32)+ack_sequence_number;

    uint8_t *nacks = buffheader + 7;

    DEBUG("NOTICE, endpoint_id 0x%.16" PRIX64 " endpoint shifted 0x%.16" PRIX64" packet_id 0x%.16" PRIX64" \n", endpoint_id, endpoint_id<<32, packet_id);
    if (nack_count != 0xff) {
		DEBUG("NOTICE, nack count: %d \n", nack_count);
        uint64_t nack_list[nack_count];
        for (int nack_index=0; nack_index<nack_count; nack_index++){
            uint16_t nack_serial_number = be16toh(*(uint16_t * )(nacks + nack_index*2));
            uint64_t nack_pkt_id = (endpoint_id<<32)+nack_serial_number;
            nack_list[nack_index] = nack_pkt_id;
            DEBUG("NOTE, INSTANT RESUBMIT FOR PACKET 0x%.16" PRIX64 " \n", nack_pkt_id);
            struct packet_in_buffer_t* pointer_to_packet_in_bucket;
            int ret = rte_hash_lookup_data(buffer_table, &nack_pkt_id, (void**) &pointer_to_packet_in_bucket);
            if(ret >= 0) {
                DEBUG("NOTE, PACKET FOUND 0x%.16" PRIX64"  \n", nack_pkt_id);
                resend_packet_from_bucket(pointer_to_packet_in_bucket);
            }else{
                DEBUG("WARNING, PACKET NOT FOUND 0x%.16" PRIX64"  \n", nack_pkt_id);
            }
        }
        uint16_t* first_seq_to_ack_ptr;
        int ret = rte_hash_lookup_data(buffer_table_teid, &endpoint_id, (void**)&first_seq_to_ack_ptr);
        uint16_t first_seq_to_ack;
        if(ret >= 0) {
            first_seq_to_ack = *first_seq_to_ack_ptr;
        }else{
            first_seq_to_ack_ptr = malloc(sizeof(uint16_t));
            if (unlikely(!first_seq_to_ack_ptr)) abort();
        }
        *first_seq_to_ack_ptr = ack_sequence_number+1;
        rte_hash_add_key_data(buffer_table_teid, &endpoint_id, first_seq_to_ack_ptr);
            //first_seq_to_ack = 0;

        DEBUG("NOTE, ACK arrived DELETING FROM 0x%.4" PRIX16 " 0x%.16" PRIX16 "\n", first_seq_to_ack, ack_sequence_number);

        uint64_t ack_pkt_id;
        unsigned max_ack = ack_sequence_number;
        if (first_seq_to_ack > ack_sequence_number)
            max_ack = ack_sequence_number + 0x10000; // handle overflow
        for (unsigned ack_index=first_seq_to_ack; ack_index<=max_ack; ack_index++){
            ack_pkt_id = (endpoint_id<<32)+(ack_index & 0xffff);
        if (array_contains(ack_pkt_id, nack_list, nack_count)){ // Skip the list of nacks
                continue;
        }
            struct packet_in_buffer_t* pointer_to_packet_in_bucket;
            int ret = rte_hash_lookup_data(buffer_table, &ack_pkt_id, (void**)&pointer_to_packet_in_bucket);
            if(ret >= 0) {
                DEBUG("NOTE, PACKET FOUND 0x%.16" PRIX64"  \n", ack_pkt_id);
                remove_packet_from_bucket(current_bucket, pointer_to_packet_in_bucket);
                port_statistics[rte_lcore_id()].deleted += 1;
                rte_hash_del_key(buffer_table, &ack_pkt_id);
            }else{
                DEBUG("WARNING, PACKET NOT FOUND 0x%.16" PRIX64"  \n", ack_pkt_id);
                port_statistics[rte_lcore_id()].dropped += 1;
            }
        }
        rte_pktmbuf_free(m);
    } else {
        struct packet_in_buffer_t* packet_in_bucket;
        DEBUG("NOTICE, PKT pre storing: 0x%.16" PRIX64"\n", packet_id);
        int ret = rte_hash_lookup_data(buffer_table, &packet_id, (void**)&packet_in_bucket);
        if(ret >= 0) {
            DEBUG("WARNING, PACKET IS ALREADY BUFFERED 0x%.16" PRIX64" \n", packet_id);
            port_statistics[rte_lcore_id()].dropped += 1;
            rte_pktmbuf_free(m);
            return;
        }

        DEBUG("NOTICE, PKT storing: 0x%.16" PRIX64" \n", packet_id);
        struct packet_in_buffer_t** pointer_to_packet_in_bucket;
        pointer_to_packet_in_bucket = insert_packet_to_bucket(current_bucket, m, portid, packet_id);
        if (pointer_to_packet_in_bucket == NULL){
            DEBUG("WARNING, PACKET CANNOT BE STORED IN BUCKET, DROPPED 0x%.16" PRIX64 " \n", packet_id);
            port_statistics[rte_lcore_id()].dropped += 1;
            rte_pktmbuf_free(m);
        }else{
            port_statistics[rte_lcore_id()].inserted += 1;
            int ret = rte_hash_add_key_data(buffer_table, &packet_id, *pointer_to_packet_in_bucket);
            if (ret == 22){
                DEBUG("ERROR INSERTION: %d WRONG PARAM\n", ret);
                rte_exit(EXIT_FAILURE, "UNABLE TO STORE HASH ENTRY WRONG PARAM\n");
            }else if (ret == ENOSPC){
                DEBUG("ERROR INSERTION: %d NO SPACE\n", ret);
                rte_exit(EXIT_FAILURE, "UNABLE TO STORE HASH ENTRY NO SPACE\n");
            }else{
                DEBUG("NOTICE, INSERTION %d OK\n", ret);
            }
        }
    }
}


/* main processing loop */
static void
l2fwd_main_loop(void) {
    struct rte_mbuf * pkts_burst[MAX_PKT_BURST];
    struct rte_mbuf * m;
    int sent;
    unsigned lcore_id;
    uint64_t prev_tsc, diff_tsc, cur_tsc, timer_tsc;
    cur_tsc = 0;
    unsigned i, j, portid, nb_rx;
    struct lcore_queue_conf * qconf;
    const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S *
        BURST_TX_DRAIN_US;
    struct rte_eth_dev_tx_buffer * buffer;

    prev_tsc = 0;
    timer_tsc = 0;

    lcore_id = rte_lcore_id();
    qconf = & lcore_queue_conf[lcore_id];

    if (qconf -> n_rx_port == 0) {
        RTE_LOG(INFO, L2FWD, "lcore %u has nothing to do\n", lcore_id);
        //return;
    }

    RTE_LOG(INFO, L2FWD, "entering main loop on lcore %u\n", lcore_id);

    for (i = 0; i < qconf -> n_rx_port; i++) {
        portid = qconf -> rx_port_list[i];
        RTE_LOG(INFO, L2FWD, " -- lcoreid=%u portid=%u\n", lcore_id,
            portid);

    }

    //Create Hash table
    char tmp[50];
    sprintf(tmp, "HashTable%d", lcore_id);
    ut_params.name = tmp;
    struct rte_hash* buffer_table = rte_hash_create(&ut_params);
    if (buffer_table == NULL) rte_exit(EXIT_FAILURE, "UNABLE TO CREATE HASHTABLE\n");

    sprintf(tmp, "HashTableTeid%d", lcore_id);
    ut_params.name = tmp;
    struct rte_hash* buffer_table_teid = rte_hash_create(&ut_params_teid);
    if (buffer_table_teid == NULL) rte_exit(EXIT_FAILURE, "UNABLE TO CREATE HASHTABLE\n");

    uint8_t current_bucket = 0;
    //struct bucket_t* buckets = malloc(sizeof(struct bucket_t) * resubmission_time);
    struct bucket_t* buckets = rte_malloc(NULL, sizeof(struct bucket_t) * resubmission_time, 0);
    global_buckets[lcore_id] = buckets;

    for (int i = 0; i < resubmission_time; i++) {
        buckets[i].data = rte_malloc(NULL, bucket_size * sizeof(struct packet_in_buffer_t* ), 0);
        //buckets[i].data = malloc(bucket_size * sizeof(struct packet_in_buffer_t* ));
        buckets[i].last_element = 0;
        buckets[i].count = 0;
        for (int j = 0; j < bucket_size; j++) {
            buckets[i].data[j] = rte_malloc(NULL, sizeof(struct packet_in_buffer_t), 0);
            //buckets[i].data[j] = malloc(sizeof(struct packet_in_buffer_t));
            if (buckets[i].data[j] == NULL) rte_exit(EXIT_FAILURE, "UNABLE TO ALLOCATE BUCKET\n");
        }
    }
    int previous_bucket = -1;
    uint8_t lcoreindex = rte_lcore_index(lcore_id);

    uint64_t proc_timer_hz = rte_get_timer_hz();
    uint64_t now = rte_rdtsc();
    while (!force_quit) {
        now = rte_rdtsc();
        if (now - (proc_timer_hz/10.0)*resubmission_time > cur_tsc) {
            cur_tsc = now;
            current_bucket = (current_bucket + 1) % resubmission_time;
        }
        //DEBUG("LCORE %d -- Current bucket:%d == prev %d => %d \n", lcore_id, current_bucket, previous_bucket, current_bucket == previous_bucket);
        if (previous_bucket != current_bucket) {
            //send_out_current_bucket( & (buckets[current_bucket]), buffer_table, lcoreindex );
            send_out_current_bucket_wo_removal( & (buckets[current_bucket]), buffer_table, lcoreindex );
            previous_bucket = current_bucket;
            /*
             * TX burst queue drain
             */
            diff_tsc = cur_tsc - prev_tsc;
            if (unlikely(diff_tsc > drain_tsc)) {

                for (i = 0; i < qconf -> n_rx_port; i++) {

                    portid = l2fwd_dst_ports[qconf -> rx_port_list[i]];
                    buffer = tx_buffer[portid][lcoreindex];

                    sent = rte_eth_tx_buffer_flush(portid, lcoreindex, buffer);
                    if (sent)
                        port_statistics[lcore_id].tx += sent;

                }

                /* if timer is enabled */
                if (timer_period > 0) {

                    /* advance the timer */
                    timer_tsc += diff_tsc;

                    /* if timer has reached its timeout */
                    if (unlikely(timer_tsc >= timer_period)) {

                        /* do this only on master core */
                        if (lcore_id == rte_get_master_lcore()) {
                            print_stats();
                            int sum_buckets = 0;
                            for (int lc=0; lc<RTE_MAX_LCORE; lc++){
                                if (!rte_lcore_is_enabled(lc)) continue;
                                for (int i = 0; i < resubmission_time; i++) {
                                    if(unlikely(port_statistics[lcore_id].inserted == port_statistics[lcore_id].deleted)){
                                        global_buckets[lc][i].count = 0;
                                        global_buckets[lc][i].last_element = 0;
                                    }
                                    printf("LCORE %d: Bucket %d has %d elements\n", lc, i, global_buckets[lc][i].count);
                                    sum_buckets += global_buckets[lc][i].count;
                                }
                }
                            printf("Bucket SUM has %d elements\n", sum_buckets);
                            /* reset the timer */
                            timer_tsc = 0;
                        }
                    }
                }

                prev_tsc = cur_tsc;
            }
        }

        /*
         * Read packet from RX queues
         */
        for (i = 0; i < qconf -> n_rx_port; i++) {

            portid = qconf -> rx_port_list[i];
            nb_rx = rte_eth_rx_burst(portid, lcoreindex,
                pkts_burst, MAX_PKT_BURST);
            port_statistics[lcore_id].rx += nb_rx;


            for (j = 0; j < nb_rx; j++) {
                m = pkts_burst[j];
                if(unlikely(m==0x0)) continue;
                rte_prefetch0(rte_pktmbuf_mtod(m, void * ));
                handle_incoming_packet(m, & buckets[current_bucket], buffer_table, buffer_table_teid, portid);
            }
        }
    }
}

static int
l2fwd_launch_one_lcore(__attribute__((unused)) void * dummy) {
    l2fwd_main_loop();
    return 0;
}

/* display usage */
static void
l2fwd_usage(const char * prgname) {
    printf("%s [EAL options] -- -p PORTMASK [-q NQ]\n"
        "  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
        "  -q NQ: number of queue (=ports) per lcore (default is 1)\n"
        "  -T PERIOD: statistics will be refreshed each PERIOD seconds (0 to disable, 10 default, 86400 maximum)\n"
        "  --[no-]mac-updating: Enable or disable MAC addresses updating (enabled by default)\n"
        "      When enabled:\n"
        "       - The source MAC address is replaced by the TX port MAC address\n"
        "       - The destination MAC address is replaced by 02:00:00:00:00:TX_PORT_ID\n",
        prgname);
}

static int
l2fwd_parse_portmask(const char * portmask) {
    char * end = NULL;
    unsigned long pm;

    /* parse hexadecimal string */
    pm = strtoul(portmask, & end, 16);
    if ((portmask[0] == '\0') || (end == NULL) || ( * end != '\0'))
        return -1;

    if (pm == 0)
        return -1;

    return pm;
}

static unsigned int
l2fwd_parse_nqueue(const char * q_arg) {
    char * end = NULL;
    unsigned long n;

    /* parse hexadecimal string */
    n = strtoul(q_arg, & end, 10);
    if ((q_arg[0] == '\0') || (end == NULL) || ( * end != '\0'))
        return 0;
    if (n == 0)
        return 0;
    if (n >= MAX_RX_QUEUE_PER_LCORE)
        return 0;

    return n;
}

static int
l2fwd_parse_timer_period(const char * q_arg) {
    char * end = NULL;
    int n;

    /* parse number string */
    n = strtol(q_arg, & end, 10);
    if ((q_arg[0] == '\0') || (end == NULL) || ( * end != '\0'))
        return -1;
    if (n >= MAX_TIMER_PERIOD)
        return -1;

    return n;
}

static
const char short_options[] =
    "p:" /* portmask */
"q:" /* number of queues */
"T:" /* timer period */ ;

#define CMD_LINE_OPT_MAC_UPDATING "mac-updating"
#define CMD_LINE_OPT_NO_MAC_UPDATING "no-mac-updating"

enum {
    /* long options mapped to a short option */

    /* first long only option value must be >= 256, so that we won't
     * conflict with short options */
    CMD_LINE_OPT_MIN_NUM = 256,
};

static
const struct option lgopts[] = {
    {
        NULL,
        0,
        0,
        0
    }
};

/* Parse the argument given in the command line of the application */
static int
l2fwd_parse_args(int argc, char ** argv) {
    int opt, ret, timer_secs;
    char ** argvopt;
    int option_index;
    char * prgname = argv[0];

    argvopt = argv;

    while ((opt = getopt_long(argc, argvopt, short_options,
            lgopts, & option_index)) != EOF) {

        switch (opt) {
            /* portmask */
        case 'p':
            l2fwd_enabled_port_mask = l2fwd_parse_portmask(optarg);
            if (l2fwd_enabled_port_mask == 0) {
                printf("invalid portmask\n");
                l2fwd_usage(prgname);
                return -1;
            }
            break;

            /* nqueue */
        case 'q':
            l2fwd_rx_queue_per_lcore = l2fwd_parse_nqueue(optarg);
            if (l2fwd_rx_queue_per_lcore == 0) {
                printf("invalid queue number\n");
                l2fwd_usage(prgname);
                return -1;
            }
            break;

            /* timer period */
        case 'T':
            timer_secs = l2fwd_parse_timer_period(optarg);
            if (timer_secs < 0) {
                printf("invalid timer period\n");
                l2fwd_usage(prgname);
                return -1;
            }
            timer_period = timer_secs;
            break;

            /* long options */
        case 0:
            break;

        default:
            l2fwd_usage(prgname);
            return -1;
        }
    }

    if (optind >= 0)
        argv[optind - 1] = prgname;

    ret = optind - 1;
    optind = 1; /* reset getopt lib */
    return ret;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint32_t port_mask) {
    #define CHECK_INTERVAL 100 /* 100ms */
    #define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
    uint16_t portid;
    uint8_t count, all_ports_up, print_flag = 0;
    struct rte_eth_link link;

    printf("\nChecking link status");
    fflush(stdout);
    for (count = 0; count <= MAX_CHECK_TIME; count++) {
        if (force_quit)
            return;
        all_ports_up = 1;
        RTE_ETH_FOREACH_DEV(portid) {
            if (force_quit)
                return;
            if ((port_mask & (1 << portid)) == 0)
                continue;
            memset( & link, 0, sizeof(link));
            rte_eth_link_get_nowait(portid, & link);
            /* print link status if flag set */
            if (print_flag == 1) {
                if (link.link_status)
                    printf(
                        "Port%d Link Up. Speed %u Mbps - %s\n",
                        portid, link.link_speed,
                        (link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
                        ("full-duplex") : ("half-duplex\n"));
                else
                    printf("Port %d Link Down\n", portid);
                continue;
            }
            /* clear all_ports_up flag if any link down */
            if (link.link_status == ETH_LINK_DOWN) {
                all_ports_up = 0;
                break;
            }
        }
        /* after finally printing all link status, get out */
    if (print_flag == 1)
            break;

        if (all_ports_up == 0) {
            printf(".");
            fflush(stdout);
            rte_delay_ms(CHECK_INTERVAL);
        }

        /* set the print_flag if all ports up or timeout */
        if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
            print_flag = 1;
            printf("done\n");
        }
    }
}

static void
signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\n\nSignal %d received, preparing to exit...\n",
            signum);
        force_quit = true;
    }
}

int
main(int argc, char ** argv) {
    struct lcore_queue_conf * qconf;
    int ret;
    uint16_t nb_ports;
    uint16_t nb_ports_available = 0;
    uint16_t portid, last_port;
    unsigned lcore_id;
    unsigned nb_ports_in_mask = 0;
    unsigned int nb_mbufs;

    /* init EAL */
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
    argc -= ret;
    argv += ret;

    force_quit = false;
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* parse application arguments (after the EAL ones) */
    ret = l2fwd_parse_args(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid L2FWD arguments\n");

    /* convert to number of cycles */
    timer_period *= rte_get_timer_hz();

    nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0)
        rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

    /* check port mask to possible port mask */
    if (l2fwd_enabled_port_mask & ~((1 << nb_ports) - 1))
        rte_exit(EXIT_FAILURE, "Invalid portmask; possible (0x%x)\n",
            (1 << nb_ports) - 1);

    /* reset l2fwd_dst_ports */
    for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++)
        l2fwd_dst_ports[portid] = 0;
    last_port = 0;

    /*
     * Each logical core is assigned a dedicated TX queue on each port.
     */
    RTE_ETH_FOREACH_DEV(portid) {
        /* skip ports that are not enabled */
        if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
            continue;

        if (nb_ports_in_mask % 2) {
            l2fwd_dst_ports[portid] = last_port;
            l2fwd_dst_ports[last_port] = portid;
        } else
            last_port = portid;

        nb_ports_in_mask++;
    }
    if (nb_ports_in_mask % 2) {
        printf("Notice: odd number of ports in portmask.\n");
        l2fwd_dst_ports[last_port] = last_port;
    }

    qconf = NULL;

    /* Initialize the port/queue configuration of each logical core */
    RTE_ETH_FOREACH_DEV(portid) {
        /* skip ports that are not enabled */
        if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
            continue;

        for (uint8_t lcoreid = 0; lcoreid<RTE_MAX_LCORE; lcoreid++){
            if(rte_lcore_is_enabled(lcoreid)){
                if (qconf != & lcore_queue_conf[lcoreid]) {
                    qconf = & lcore_queue_conf[lcoreid];
                }
                qconf -> rx_port_list[qconf -> n_rx_port] = portid;
                qconf -> n_rx_port++;
                printf("Lcore %u: RX port %u\n", lcoreid, portid);
            }
        }
    }

    nb_mbufs = 1024U * 1024U * 1U - 1;
    l2fwd_pktmbuf_pool = malloc(rte_lcore_count()*sizeof(struct rte_mempool*));
    clone_pktmbuf_pool = rte_pktmbuf_pool_create("CLONEPOOL", 1024, 32, 0, 0, rte_socket_id());
    if (clone_pktmbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot init clone mbuf pool\n");

    /* create the mbuf pool */
    if (USE_DIFFERENT_POOL_FOR_LCORES == 1){
        mempool_num=rte_lcore_count();
        printf("Using different mempool for all the %d lcores\n", mempool_num);
    }else{
        mempool_num=1;
        printf("Using the same mempool for all lcores\n");
    }
    for (uint8_t queues = 0; queues<mempool_num; queues++){
        char tmp[50] = "";
        sprintf(tmp, "mbuf_pool%d",queues);
        l2fwd_pktmbuf_pool[queues] = rte_pktmbuf_pool_create(tmp, nb_mbufs,
            MEMPOOL_CACHE_SIZE, 0, PKTSIZE, //RTE_MBUF_DEFAULT_BUF_SIZE,
            rte_socket_id());
        if (l2fwd_pktmbuf_pool[queues] == NULL)
            rte_exit(EXIT_FAILURE, "Cannot init mbuf pool %d\n", queues);
    }
    /* Initialise each port */
    RTE_ETH_FOREACH_DEV(portid) {
        struct rte_eth_rxconf rxq_conf;
        struct rte_eth_txconf txq_conf;
        struct rte_eth_conf local_port_conf = port_conf;
        struct rte_eth_dev_info dev_info;

        /* skip ports that are not enabled */
        if ((l2fwd_enabled_port_mask & (1 << portid)) == 0) {
            printf("Skipping disabled port %u\n", portid);
            continue;
        }
        nb_ports_available++;

        /* init port */
        printf("Initializing port %u... ", portid);
        fflush(stdout);
        rte_eth_dev_info_get(portid, & dev_info);
        if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
            local_port_conf.txmode.offloads |=
            DEV_TX_OFFLOAD_MBUF_FAST_FREE;
        ret = rte_eth_dev_configure(portid, rte_lcore_count()/*1*/, rte_lcore_count()/*1*/, & local_port_conf);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n",
                ret, portid);

        ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, & nb_rxd, &
            nb_txd);
        if (ret < 0)
            rte_exit(EXIT_FAILURE,
                "Cannot adjust number of descriptors: err=%d, port=%u\n",
                ret, portid);

        rte_eth_macaddr_get(portid, & l2fwd_ports_eth_addr[portid]);

        /* init one RX queue */
        fflush(stdout);
        rxq_conf = dev_info.default_rxconf;
        rxq_conf.offloads = local_port_conf.rxmode.offloads;
        for (uint8_t queues = 0; queues<rte_lcore_count(); queues++){
            if (mempool_num == 1){
                ret = rte_eth_rx_queue_setup(portid, queues, nb_rxd,
                    rte_eth_dev_socket_id(portid), &
                    rxq_conf,
                    l2fwd_pktmbuf_pool[0]);
            }else{
                ret = rte_eth_rx_queue_setup(portid, queues, nb_rxd,
                    rte_eth_dev_socket_id(portid), &
                    rxq_conf,
                    l2fwd_pktmbuf_pool[queues]);
            }
            if (ret < 0)
                rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n",
                    ret, portid);
        }

        /* init one TX queue on each port */
        fflush(stdout);
        txq_conf = dev_info.default_txconf;
        txq_conf.offloads = local_port_conf.txmode.offloads;
        //ret = rte_eth_tx_queue_setup(portid, 0, nb_txd,
        for(uint8_t i=0; i<rte_lcore_count(); i++){
            ret = rte_eth_tx_queue_setup(portid, i, nb_txd,
                rte_eth_dev_socket_id(portid), &txq_conf);
            if (ret < 0)
                rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n",
                    ret, portid);

        /* Initialize TX buffers */
            tx_buffer[portid][i] = rte_zmalloc_socket("tx_buffer",
                RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0,
                rte_eth_dev_socket_id(portid));
            if (tx_buffer[portid][i] == NULL)
                rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port %u\n",
                    portid);

            rte_eth_tx_buffer_init(tx_buffer[portid][i], MAX_PKT_BURST);

            ret = rte_eth_tx_buffer_set_err_callback(tx_buffer[portid][i],
                rte_eth_tx_buffer_count_callback, &
                port_statistics[i].dropped);
            if (ret < 0)
                rte_exit(EXIT_FAILURE,
                    "Cannot set error callback for tx buffer on port %u\n",
                    portid);
        }

        /* Start device */
        ret = rte_eth_dev_start(portid);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
                ret, portid);

        printf("done: \n");

        rte_eth_promiscuous_enable(portid);

        printf("Port %u, MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n\n",
            portid,
            l2fwd_ports_eth_addr[portid].addr_bytes[0],
            l2fwd_ports_eth_addr[portid].addr_bytes[1],
            l2fwd_ports_eth_addr[portid].addr_bytes[2],
            l2fwd_ports_eth_addr[portid].addr_bytes[3],
            l2fwd_ports_eth_addr[portid].addr_bytes[4],
            l2fwd_ports_eth_addr[portid].addr_bytes[5]);

        /* initialize port stats */
        memset( & port_statistics, 0, sizeof(port_statistics));
    }

    if (!nb_ports_available) {
        rte_exit(EXIT_FAILURE,
            "All available ports are disabled. Please set portmask.\n");
    }

    check_all_ports_link_status(l2fwd_enabled_port_mask);

    ret = 0;
    /* launch per-lcore init on every lcore */
    rte_eal_mp_remote_launch(l2fwd_launch_one_lcore, NULL, CALL_MASTER);
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        if (rte_eal_wait_lcore(lcore_id) < 0) {
            ret = -1;
            break;
        }
    }

    RTE_ETH_FOREACH_DEV(portid) {
        if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
            continue;
        printf("Closing port %d...", portid);
        rte_eth_dev_stop(portid);
        rte_eth_dev_close(portid);
        printf(" Done\n");
    }
    printf("Bye...\n");

    return ret;
}

