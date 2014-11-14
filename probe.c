#include "probe.h"


extern probe_t  probe;

// Allocate the netflow structure for global use

volatile    int quit = 0;

/**************************************************************************//**
*
* packet_type - Examine a packet and return the type of packet
*
* DESCRIPTION
* Examine a packet and return the type of packet.
* the packet.
*
* RETURNS: N/A
*
* SEE ALSO:
*/

static __inline__ pktType_e
packet_type( struct rte_mbuf * m )
{
    pktType_e   ret;
    struct ether_hdr *eth;

    eth = rte_pktmbuf_mtod(m, struct ether_hdr *);

    ret = ntohs(eth->ether_type);

    return ret;
}

#define PRINT_IP(x) printf("%d.%d.%d.%d", (x&0x000000ff), (x&0x0000ff00)>>8, (x&0x00ff0000)>>16, (x&0xff000000)>>24)

void
print_ipv4(struct ipv4_hdr *ip)
{
    PRINT_IP(ip->src_addr);
    printf("-(%d)->", ip->next_proto_id);
    PRINT_IP(ip->dst_addr);
    printf("\n");
}
void
print_flow(union rte_table_netflow_key *k)
{
    PRINT_IP(k->ip_src);
    printf(" (%d) -[%d]-> (%d) ", ntohs(k->port_src), k->proto, ntohs(k->port_dst));
    PRINT_IP(k->ip_dst);
    printf("\n");
}

/****************************************************************************
 * 
 */
void
process_ipv4(struct rte_mbuf * m, int pid, int vlan)
{
    port_info_t *info = &probe.info[pid];
    struct rte_table_netflow *t = (struct rte_table_netflow *)probe.table[0][0];
    hashBucket_t *bkt;
    int key_found=0;
    char proto;
    struct ether_hdr *eth = rte_pktmbuf_mtod(m, struct ether_hdr *);
    struct ipv4_hdr  *ip  = (struct ipv4_hdr *)&eth[1];
    struct tcp_hdr   *tcp;
    struct udp_hdr   *udp;
       
    union rte_table_netflow_key k;

    uint32_t init_val;
 
    /* Adjust for a vlan header if present */
    if (vlan)
        ip = (struct ipv4_hdr *)((char *)ip + sizeof(struct vlan_hdr));

    k.ip_src = ip->src_addr;
    k.ip_dst = ip->dst_addr;
    k.proto  = ip->next_proto_id;
    k.pad0 = 0;
    k.pad1 = 0;
    k.vlanId = vlan;

    //print_ipv4(ip);
    // based on proto, TCP/UDP/ICMP...
    switch(ip->next_proto_id) {
        case IPPROTO_UDP:
            udp = (struct udp_hdr *)((unsigned char*)ip + sizeof(struct ipv4_hdr)); 
            k.port_src = udp->src_port;
            k.port_dst = udp->dst_port;
            break;
        
        case IPPROTO_TCP:
            tcp = (struct tcp_hdr *)((unsigned char*)ip + sizeof(struct ipv4_hdr));
            k.port_src = tcp->src_port;
            k.port_dst = tcp->dst_port;
            break;
        
        default:
            break;
    }
    rte_table_netflow_entry_add(t, &k, ip, &key_found, &bkt);

    //print_flow(&k);
    //TODO
    // 1) decode flow header
    // 2) pkt to hash
    //printf("%" PRIu32 "\n", init_val);
    // 3) process hash table (export flows)
}


/****************************************************************************
*
* packet_classify - Examine a packet and classify it for statistics
*
* DESCRIPTION
* Examine a packet and determine its type along with counting statistics around
* the packet.
*
* RETURNS: N/A
*
* SEE ALSO:
*/
#define FCS_SIZE 4

static void
packet_classify( struct rte_mbuf * m, int pid )
{
    port_info_t * info = &probe.info[pid];
    int     plen = (m->pkt_len + FCS_SIZE);
    pktType_e   pType;

    pType = packet_type(m);

    switch((int)pType) {
        case ETHER_TYPE_ARP:    info->stats.arp_pkts++; printf("arp\n"); break;
        case ETHER_TYPE_IPv4:   info->stats.ip_pkts++;  process_ipv4(m, pid, 0);  break;
        case ETHER_TYPE_IPv6:   info->stats.ipv6_pkts++; break;
        case ETHER_TYPE_VLAN:   info->stats.vlan_pkts++; break;
        case UNKNOWN_PACKET:    /* FALL THRU */
        default:                break;
    }
    
}


/*************************************************************
 * packet classify - Classify a set of packets in one call
 * 
 * DESCRIPTION
 * Classify a list of packets and to improve clasify peformance.
 * 
 * Return: N/A
 */
#define PREFETCH_OFFSET     3
static __inline__ void
packet_classify_bulk(struct rte_mbuf **pkts, int nb_rx, int pid)
{
    int j;
    /* Prefetch first packets */
    for (j = 0; j < PREFETCH_OFFSET && j < nb_rx; j++)
        rte_prefetch0(rte_pktmbuf_mtod(pkts[j], void *));

    /* Prefetch and handle already prefetched packets */
    for (j = 0; j < (nb_rx-PREFETCH_OFFSET); j++) {
        rte_prefetch0(rte_pktmbuf_mtod(pkts[j + PREFETCH_OFFSET], void *));
        packet_classify(pkts[j], pid);
    }

    /* TODO */
    // Additional processing like DPI
    
    /* Handle remaining prefetched packets */
    for (; j < nb_rx; j++)
        packet_classify(pkts[j], pid);

}

int
launch_probe(__attribute__((unused)) void *arg)
{
    uint8_t lcore_id = rte_lcore_id();
    uint8_t nb_rx, pid, j;
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    struct rte_mbuf *m;
    
    printf("## lcore_id:%d\n", lcore_id);

    pid = 0;
    while(!quit) {
        // Read packet from RX Queue
        nb_rx = rte_eth_rx_burst(pid, 0, pkts_burst, MAX_PKT_BURST);
		if (unlikely(nb_rx == 0)) continue;

	    // classify the packets
        packet_classify_bulk(pkts_burst, nb_rx, pid);

       // free the packets
        for(j = 0; j < nb_rx; j++)
            rte_pktmbuf_free(pkts_burst[j]);
            
    }
    return 0;
}
