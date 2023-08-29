#!/bin/sh

RTEROOT="/home/vpetya/dpdk-20.08/x86_64-native-linuxapp-gcc"
CPPFLAGS="$CPPFLAGS -I$RTEROOT/include -DDEBUG_BUILD"
LDFLAGS="$LDFLAGS -L$RTEROOT/lib"
CPPFLAGS="$CPPFLAGS -DBAAS_RSS_HF=0 -DBAAS_RX_OFFLOADS=0 -DBAAS_TIMER_RESOLUTION=10.0"

cc -g -O0 -W -Wall -include rte_config.h -march=native $CPPFLAGS main.c \
-o build/Baas-static  $LDFLAGS \
 -Wl,-whole-archive  -lrte_pmd_ixgbe -lrte_pmd_i40e -lrte_pmd_e1000 -lrte_mempool \
-lrte_mempool_ring -lrte_pmd_pcap -lrte_pmd_af_packet  -lrte_pmd_virtio \
-lrte_pmd_vhost -lrte_pmd_memif -Wl,-no-whole-archive  \
-lrte_ethdev -lrte_net -lrte_mbuf -lrte_ip_frag -lrte_hash -lrte_eal -lrte_ring \
-lrte_pmd_ring -lrte_lpm -lrte_kni -lrte_vhost \
-Wl,--as-needed  -lnuma  -lrte_cryptodev \
-lcrypto -lrte_kvargs -lrte_bus_pci -lrte_pci -lrte_bus_vdev -lrte_rcu \
-lrte_telemetry -Wl,--no-as-needed -lpcap -ldl -lrt -lpthread

