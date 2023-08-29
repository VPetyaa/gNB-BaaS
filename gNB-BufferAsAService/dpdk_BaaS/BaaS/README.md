# DPDK packet buffering


=======================
| CONFIGURE CORE_NUM  |
=======================
In main.c set:
#define LCORE_COUNT x


=======================
|     BUILD + RUN     |
=======================
make
-c requires a coremask for LCORE_COUNT+1 cores
sudo ./build/Baas -c 0x1f -w 0000:41:00.0

