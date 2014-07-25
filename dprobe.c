/*-
 *   BSD LICENSE
 * 
 *   Copyright(c) 2014 Choonho Son All rights reserved.
 *   All rights reserved.
 * 
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 * 
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 * 
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <termios.h>
#include <sys/queue.h>
#include <getopt.h>
#include <signal.h>
#include <time.h>

#include <rte_common.h> 
#include <rte_byteorder.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_ethdev.h> 
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_hash_crc.h>
#include <rte_ring.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_cycles.h>
#include <cmdline_rdline.h>
#include <cmdline_parse.h>
#include <cmdline_socket.h>
#include <cmdline.h>

#include "dprobe.h"
#include "mp_commands.h"

//#define RTE_LOGTYPE_APP RTE_LOGTYPE_USER1

/*
 * RX and TX Prefetch, Host, and Write-back threshold values should be
 * carefully set for optimal performance. Consult the network
 * controller's datasheet and supporting DPDK documentation for guidance
 * on how these parameters should be set.
 */
#define RX_PTHRESH 8 /**< Default values of RX prefetch threshold reg. */
#define RX_HTHRESH 8 /**< Default values of RX host threshold reg. */
#define RX_WTHRESH 4 /**< Default values of RX write-back threshold reg. */

#define MAX_PKT_BURST 32

#define MBUF_SIZE (2048 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
#define NB_MBUF   8192

/* Configurable number of RX ring descriptors */
#define RTE_TEST_RX_DESC_DEFAULT 128
#define RTE_TEST_TX_DESC_DEFAULT 512


/* mask of enabled ports */
static uint32_t enabled_port_mask = 0;
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

//static int promiscuous_on = 1; /* Ports set in promiscuous mode on by default */
 
/**< Default values of TX prefetch threshold reg. */
#define TX_PTHRESH 36
#define TX_HTHRESH 0  /**< Default values of TX host threshold reg. */
#define TX_WTHRESH 0  /**< Default values of TX write-back threshold reg. */

#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT RTE_MAX_ETHPORTS
#define MAX_RX_QUEUE_PER_PORT 128

#define MAX_LCORE_PARAMS 1024
struct lcore_params {
    uint8_t port_id;
    uint8_t queue_id;
    uint8_t lcore_id;
} __rte_cache_aligned;

//static struct lcore_params lcore_params_array[MAX_LCORE_PARAMS];
static struct lcore_params lcore_params_array_default[] = {
    {0, 0, 2},
    {0, 1, 2},
    {0, 2, 2},
    {1, 0, 2},
    {1, 1, 2},
    {1, 2, 2},
    {2, 0, 2},
    {3, 0, 3},
    {3, 1, 3},
};

static struct lcore_params * lcore_params = lcore_params_array_default;
static uint16_t nb_lcore_params = sizeof(lcore_params_array_default) /
                sizeof(lcore_params_array_default[0]);


static const struct rte_eth_conf port_conf = {
	.rxmode = {
		.split_hdr_size = 0,
		.header_split   = 0, /**< Header Split disabled */
		.hw_ip_checksum = 0, /**< IP checksum offload disabled */
		.hw_vlan_filter = 0, /**< VLAN filtering disabled */
		.jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
		.hw_strip_crc   = 0, /**< CRC stripped by hardware */
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};


static const struct rte_eth_rxconf rx_conf = {
	.rx_thresh = {
		.pthresh = RX_PTHRESH,
		.hthresh = RX_HTHRESH,
		.wthresh = RX_WTHRESH,
	},
};
static const struct rte_eth_txconf tx_conf = {
	.tx_thresh = {
		.pthresh = TX_PTHRESH,
		.hthresh = TX_HTHRESH,
		.wthresh = TX_WTHRESH,
	},
};



/* ethernet addresses ports */
static struct ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];
static struct rte_mempool * pktmbuf_pool;


/*
 * Statistics
 *
 * structure to record the rx and tx packets. Put two per cache line as ports
 * used in pairs 
 */
struct port_stats{
    unsigned rx_packets;
    unsigned long rx_bytes;
    time_t start;
    time_t end;
} __attribute__((aligned(CACHE_LINE_SIZE / 2)));

static struct port_stats pstats[RTE_MAX_ETHPORTS];

/*
 * command line 
 */
static const char *_MSG_POOL = "MSG_POOL";
static const char *_SEC_2_PRI = "SEC_2_PRI";
static const char *_PRI_2_SEC = "PRI_2_SEC";
const unsigned string_size = 64;

struct rte_ring *send_ring, *recv_ring;
struct rte_mempool *message_pool;
volatile int quit = 0;

static void
reset_stat(unsigned portid) {
    pstats[portid].rx_packets = 0;
    pstats[portid].rx_bytes = 0;
    pstats[portid].start = clock();
    pstats[portid].end = clock();
}

static void
print_ipv4_5_tuple(struct ipv4_5tuple *flow) {
    ipv4_addr_dump(NULL, flow->ip_src);
    printf(" %d ", rte_be_to_cpu_16(flow->port_src));
    printf("-(%d)->", flow->proto); 
    printf(" %d ", rte_be_to_cpu_16(flow->port_dst));
    ipv4_addr_dump(NULL, flow->ip_dst);
}

static void
ipv4_addr_to_dot(uint32_t be_ipv4_addr, char *buf)
{
    uint32_t ipv4_addr;

    ipv4_addr = rte_be_to_cpu_32(be_ipv4_addr);
    sprintf(buf, "%d.%d.%d.%d", (ipv4_addr >> 24) & 0xFF,
        (ipv4_addr >> 16) & 0xFF, (ipv4_addr >> 8) & 0xFF,
        ipv4_addr & 0xFF);
}


static void
ipv4_addr_dump(const char *what, uint32_t be_ipv4_addr)
{
    char buf[16];

    ipv4_addr_to_dot(be_ipv4_addr, buf);
    if (what)
        printf("%s", what);
    printf("%s", buf);
}

static inline uint32_t
ipv4_hash_crc(void *data, __rte_unused uint32_t data_len,
    uint32_t init_val)
{
    struct ipv4_5tuple *k;
    uint32_t t;
    const uint32_t *p;

    k = data;
    t = k->proto;
    p = (const uint32_t *)&k->port_src;

#ifdef RTE_MACHINE_CPUFLAG_SSE4_2
    init_val = rte_hash_crc_4byte(t, init_val);
    init_val = rte_hash_crc_4byte(k->ip_src, init_val);
    init_val = rte_hash_crc_4byte(k->ip_dst, init_val);
    init_val = rte_hash_crc_4byte(*p, init_val);
#else /* RTE_MACHINE_CPUFLAG_SSE4_2 */
    init_val = rte_jhash_1word(t, init_val);
    init_val = rte_jhash_1word(k->ip_src, init_val);
    init_val = rte_jhash_1word(k->ip_dst, init_val);
    init_val = rte_jhash_1word(*p, init_val);
#endif /* RTE_MACHINE_CPUFLAG_SSE4_2 */
    return (init_val);
}

static void
netflow_collect(struct rte_mbuf *m, unsigned portid)
{
    struct ether_hdr *eth_hdr;
    struct ipv4_hdr *ipv4_hdr;
    struct udp_hdr  *udp_hdr;
    struct tcp_hdr  *tcp_hdr;
    struct ipv4_5tuple *flow;

    uint32_t flow_hash;
    uint16_t l4_proto;
    uint16_t eth_type;
    //uint16_t ol_flags;
    uint16_t pkt_ol_flags;
    uint8_t l2_len;
    uint8_t l3_len;

    /*
     * Try to figure out ether type
     */
    l2_len = sizeof(struct ether_hdr);
    pkt_ol_flags = m->ol_flags;
    //ol_flags = (uint16_t) (pkt_ol_flags & (~PKT_TX_L4_MASK));

    eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
    eth_type = rte_be_to_cpu_16(eth_hdr->ether_type);

    if (eth_type == ETHER_TYPE_VLAN) {
        /* TODO: Only allow single VLAN label here */
        l2_len += sizeof(struct vlan_hdr);
    }
    /*
     * Try to figure out L3 packet type
     */
    if ((pkt_ol_flags & (PKT_RX_IPV4_HDR | PKT_RX_IPV4_HDR_EXT |
            PKT_RX_IPV6_HDR | PKT_RX_IPV6_HDR_EXT)) == 0) {
        if (eth_type == ETHER_TYPE_IPv4) {
            pkt_ol_flags |= PKT_RX_IPV4_HDR;
         }
        else if (eth_type == ETHER_TYPE_IPv6)
            pkt_ol_flags |= PKT_RX_IPV6_HDR;
    }

    /*
     * Simplify the protocol parsing
     * Assuming the incoming packets format as
     *      Ethernet2 + optional single VLAN
     *      + ipv4 or ipv6
     *      + udp or tcp or sctp or others
     *
     * flow is saved as network order
     */
    flow = malloc(sizeof(struct ipv4_5tuple));


    /* update Statistics */
    pstats[portid].rx_packets += 1;
 
    if (pkt_ol_flags & PKT_RX_IPV4_HDR) {
        l3_len = sizeof(struct ipv4_hdr);
        ipv4_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(m, unsigned char *) + l2_len);
        l4_proto = ipv4_hdr->next_proto_id;
        flow->ip_src = ipv4_hdr->src_addr;
        flow->ip_dst = ipv4_hdr->dst_addr;
        flow->proto  = l4_proto;
        pstats[portid].rx_bytes += rte_be_to_cpu_16(ipv4_hdr->total_length);

        /* UDP Packet */
        if (l4_proto == IPPROTO_UDP) {
            udp_hdr = (struct udp_hdr*)(rte_pktmbuf_mtod(m, unsigned char *) + l2_len + l3_len);
            flow->port_src = udp_hdr->src_port;
            flow->port_dst = udp_hdr->dst_port;
        }
        /* TCP Packet */
        else if (l4_proto == IPPROTO_TCP) {
            tcp_hdr = (struct tcp_hdr*)(rte_pktmbuf_mtod(m, unsigned char *) + l2_len + l3_len);
            flow->port_src = tcp_hdr->src_port;
            flow->port_dst = tcp_hdr->dst_port;
        }

    }
    flow_hash = ipv4_hash_crc(flow, 0, 0);
    //printf("hash:%u ", flow_hash);
    //print_ipv4_5_tuple(flow);
    //printf("\n");
    free(flow);
    rte_pktmbuf_free(m);
}

/* signal handler configured for SIGTERM and SIGINT to print stats on exit */
static void
print_stats(int signum)
{
    unsigned i;
    unsigned num_ports=1;
    double diff_sec, pps,bandwidth;

    printf("\nExiting on signal %d\n\n", signum);

    pstats[0].end = clock();

    printf("##########################################################\n");
    printf(" Port\tpackets\tKpps\tBytes\tMbps\n");
    printf("----------------------------------------------------------\n");
    for (i = 0; i < num_ports; i++){
        //const uint8_t p_num = ports[i];
        const uint8_t p_num = i;

        diff_sec = (pstats[0].end - pstats[0].start)/CLOCKS_PER_SEC;
        pps = ((double)pstats[p_num].rx_packets / diff_sec) / 1000; 
        bandwidth = ( (double)pstats[p_num].rx_bytes / diff_sec )*8 / 1000000;

        printf(" %u\t%u\t%.lf\t%lu\t%.lf\n", (unsigned)p_num,
                pstats[p_num].rx_packets, pps, pstats[p_num].rx_bytes,
                bandwidth);
    }
    exit(0);
}


static int
lcore_probe(__attribute__((unused)) void *arg)
{
    unsigned lcore_id;
	unsigned portid, nb_rx;
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    struct rte_mbuf *m;
    unsigned j;
    unsigned long count;

    lcore_id = rte_lcore_id();
    printf("netflow-DPDK from core %u\n", lcore_id);

    
    /*
     * Read packet from RX queues
     */
	while (!quit) {
		portid = 0;
        void *msg;
		nb_rx = rte_eth_rx_burst((uint8_t)portid, 0, pkts_burst, MAX_PKT_BURST);
        //pstats[portid].rx += nb_rx;

        for ( j = 0; j < nb_rx; j++) {
            m = pkts_burst[j];
            rte_prefetch0(rte_pktmbuf_mtod(m, void *));
            netflow_collect(m, portid);
        }
        /* check cli */
        if (unlikely(rte_ring_dequeue(send_ring, &msg) < 0)) {
            continue;
        }
        RTE_LOG(INFO, EAL, "[lcore ID:%d] Received '%s'\n", lcore_id, (char *)msg);
        rte_mempool_put(message_pool, msg);
	}
    print_stats(0);
    RTE_LOG(INFO, EAL, "Finished lcore\n");
    return 0;
}


static int
parse_portmask(const char *portmask)
{
	char *end = NULL;
	unsigned long pm;

	/* parse hexadecimal string */
	pm = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;

	if (pm == 0)
		return -1;

	return pm;
}

static void
print_ethaddr(const char *name, const struct ether_addr *eth_addr)
{
	printf ("%s%02X:%02X:%02X:%02X:%02X:%02X", name,
		eth_addr->addr_bytes[0],
		eth_addr->addr_bytes[1],
		eth_addr->addr_bytes[2],
		eth_addr->addr_bytes[3],
		eth_addr->addr_bytes[4],
		eth_addr->addr_bytes[5]);
}

static uint8_t
get_port_n_rx_queues(const uint8_t port)
{
    int queue = -1;
    uint16_t i;

    printf("## SON : nb_lcore_params:%d\n", nb_lcore_params);
    for (i = 0; i < nb_lcore_params; ++i) {
        if (lcore_params[i].port_id == port && lcore_params[i].queue_id > queue)
            queue = lcore_params[i].queue_id;
    }
    return (uint8_t)(++queue);
}


/* display usage */
static void
print_usage(const char *prgname)
{
	printf ("%s [EAL options] -- -p PORTMASK -P"
		"  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
		"  -P : enable promiscuous mode\n",
		prgname);
}

/* Parse the argument given in the command line of the application */
static int
parse_args(int argc, char **argv)
{
	int opt, ret;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];
	static struct option lgopts[] = {
		{NULL, 0, 0, 0}
	};

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, "p:",
				  lgopts, &option_index)) != EOF) {

		switch (opt) {
		/* portmask */
		case 'p':
			enabled_port_mask = parse_portmask(optarg);
			if (enabled_port_mask == 0) {
				printf("invalid portmask\n");
				print_usage(prgname);
				return -1;
			}
			break;


		/* long options */
		case 0:
			print_usage(prgname);
			return -1;

		default:
			print_usage(prgname);
			return -1;
		}
	}

	if (optind >= 0)
		argv[optind-1] = prgname;

	ret = optind-1;
	optind = 0; /* reset getopt lib */
	return ret;
}



int
MAIN(int argc, char **argv)
{
    int ret;
    unsigned lcore_id;
	unsigned nb_ports;
	uint8_t portid, nb_rx_queue;

    const unsigned flags = 0;
    const unsigned ring_size = 64;
    const unsigned pool_size = 1024;
    const unsigned pool_cache = 32;
    const unsigned priv_data_sz = 0;

    /* set up signal handlers to print status on exit */
    signal(SIGINT, print_stats);
    signal(SIGTERM, print_stats);
 
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid EAL argument\n");

    /* init cli */
    send_ring = rte_ring_create(_PRI_2_SEC, ring_size, rte_socket_id(), flags);
    recv_ring = rte_ring_create(_SEC_2_PRI, ring_size, rte_socket_id(), flags);
    message_pool = rte_mempool_create(_MSG_POOL, pool_size,
            string_size, pool_cache, priv_data_sz,
            NULL, NULL, NULL, NULL,
            rte_socket_id(), flags);

    if (send_ring == NULL)
        rte_exit(EXIT_FAILURE, "Problem getting sending ring\n");
    if (recv_ring == NULL)
        rte_exit(EXIT_FAILURE, "Problem getting receiving ring\n");
    if (message_pool == NULL)
        rte_exit(EXIT_FAILURE, "Problem getting message pool\n");

    /* init stat */
    reset_stat(0);

	argc -= ret;
	argv += ret;

	/* parse application arguments (after the EAL ones) */
	ret = parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid arguments\n");

	/* create the mbuf pool */
	pktmbuf_pool =
		rte_mempool_create("mbuf_pool", NB_MBUF,
					MBUF_SIZE, 32,
					sizeof(struct rte_pktmbuf_pool_private),
					rte_pktmbuf_pool_init, NULL,
					rte_pktmbuf_init, NULL,
					0, 0);
	/* init driver */
//	if (rte_pmd_init_all() < 0)
//		rte_exit(EXIT_FAILURE, "Cannot init pmd\n");
//
//	if (rte_eal_pci_probe() < 0)
//		rte_exit(EXIT_FAILURE, "Cannnot probe PCI\n");
	
	nb_ports = rte_eth_dev_count();
	if (nb_ports > RTE_MAX_ETHPORTS)
		nb_ports = RTE_MAX_ETHPORTS;

	printf("Number of port:%d\n", nb_ports);

	for (portid = 0; portid < nb_ports; portid++) {
		printf("Port id:%d\n", portid);
		if ((enabled_port_mask & (1 << portid)) == 0) {
			printf("Skipping disabled port %d\n", portid);
			continue;
		}
        nb_rx_queue = get_port_n_rx_queues(portid);
        printf("Creating Queues: nb_rxq=%d", nb_rx_queue);

		/* init RX Queue */
		rte_eth_dev_configure(portid, 1, 1, &port_conf);
		printf("Queue setup:%d\n", portid);
		printf("nb_rxd:%d\n", nb_rxd);
		ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd, 
						0, &rx_conf, pktmbuf_pool);
		printf("rx_setup:%d", ret);
		ret = rte_eth_tx_queue_setup(portid, 0, nb_txd, 
						0, &tx_conf);
		printf("tx_setup:%d", ret);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d,port=%u\n",
						ret, (unsigned)portid);
		fflush(stdout);

		rte_eth_macaddr_get(portid, &ports_eth_addr[portid]);
		print_ethaddr("Address:", &ports_eth_addr[portid]);
		printf("\n");	
		
		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start: err=%d, port=%d\n", ret, portid);
		printf("Enabled promiscuous mode : port %d\n", portid);
		rte_eth_promiscuous_enable(portid);


	}	
        /* call lcore_probe() on every slave lcore */
        RTE_LCORE_FOREACH_SLAVE(lcore_id) {
                rte_eal_remote_launch(lcore_probe, NULL, lcore_id);
        }

        struct cmdline *cl = cmdline_stdin_new(simple_mp_ctx, "cmd > ");
        if (cl == NULL)
            rte_exit(EXIT_FAILURE, "Cannot create cmdline instance\n");
        cmdline_interact(cl);
        cmdline_stdin_exit(cl);
 
        /* call it on master lcore too */
        //lcore_probe(NULL);
 
        rte_eal_mp_wait_lcore();
        return 0;
}
