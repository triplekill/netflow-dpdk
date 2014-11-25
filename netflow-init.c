/*-
 *   BSD LICENSE
 * 
 *   Copyright(c) 2014, Choonho Son choonho.som@gmail.com
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


#include "netflow-init.h"

#include "probe.h"
#include "rte_table_netflow.h"

static void
print_ethaddr(const char *name, const struct ether_addr *eth_addr)
{
    printf ("%s%02X:%02X:%02X:%02X:%02X:%02X\n", name,
        eth_addr->addr_bytes[0],
        eth_addr->addr_bytes[1],
        eth_addr->addr_bytes[2],
        eth_addr->addr_bytes[3],
        eth_addr->addr_bytes[4],
        eth_addr->addr_bytes[5]);
}

#define NETFLOW_HASH_ENTRIES 4 * 1024 * 1024

static void
setup_netflow_table(probe_t* p)
{
    struct rte_table_netflow_params param = {
        .n_entries = NETFLOW_HASH_ENTRIES,
        .offset = 0,
        .f_hash = rte_hash_crc_4byte,
        .seed = 0,
    };
   
    
    int i,j;
    for (i = 0; i < p->nb_ports; i++) {
        p->table[i] = (struct rte_table_netflow *)rte_table_netflow_create(&param, i, sizeof(hashBucket_t));
    }
}   

int
init_memory(unsigned nb_mbuf, uint8_t pid, uint8_t nb_queues)
{
    uint8_t lid;    // lcore_id
    int sid;        // socket_id
    int ret;
    uint8_t qid;    // queue_id  
    char s[64];
    uint8_t i;

    if (numa_on)
        sid = rte_lcore_to_socket_id(lid);
    else
        sid = 0;

    /* mempool */
    if (pktmbuf_pool[sid] == NULL) {
        snprintf(s, sizeof(s), "netflow_pool_%d", sid);
        pktmbuf_pool[sid] =
            rte_mempool_create(s, nb_mbuf, MBUF_SIZE, MEMPOOL_CACHE_SIZE,
                sizeof(struct rte_pktmbuf_pool_private),
                rte_pktmbuf_pool_init, NULL,
                rte_pktmbuf_init, NULL,
                sid, 0);
        if (pktmbuf_pool[sid] == NULL)
            rte_exit(EXIT_FAILURE, "Cannot init mbuf pool on socket(%d)\n", sid);
    }

    /* mbuf pool */
    for(i = 0; i < nb_queues; i++) {
        ret = rte_eth_rx_queue_setup(pid, i, 512, sid, &rx_conf, pktmbuf_pool[sid]);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "Failed to rx_queue_setup\n");
    }
    ret = rte_eth_tx_queue_setup(pid, 0, 128, sid, &tx_conf);

}

int
netflow_init(probe_t *probe)
{
    probe->nb_ports = rte_eth_dev_count();
    uint8_t pid;    // port_id
    uint8_t ret;

    RTE_LOG(DEBUG, PMD, "Number of ports: %d\n", probe->nb_ports);    

    /* init Port */
    for (pid = 0; pid < probe->nb_ports; pid++) {
        RTE_LOG(DEBUG, PMD, "Init Port(%d)\n", pid);

        // param (port_id,nb_rx_queue, nb_tx_queue, ...)
        ret = rte_eth_dev_configure(pid, probe->nb_queues, 1, &port_conf);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%d\n", ret, pid);

            rte_eth_macaddr_get(pid, &probe->ports_eth_addr[pid]);
            print_ethaddr("MAC address:", &probe->ports_eth_addr[pid]);

        /* init memory per port */
        if (init_memory(NB_MBUF, pid, probe->nb_queues) < 0)
            rte_exit(EXIT_FAILURE, "Fail to initialize memory\n");

        /* start device */
        ret = rte_eth_dev_start(pid);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "Fail to start dev\n");

        rte_eth_promiscuous_enable(pid);
    }

    /* netflow hash table init */
    setup_netflow_table(probe);

    /* setup netflow collector information */
    probe->collector.sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    bzero(&probe->collector.servaddr, sizeof(probe->collector.servaddr));
    probe->collector.servaddr.sin_family = AF_INET;
    probe->collector.servaddr.sin_addr.s_addr = inet_addr(probe->collector.addr);
    probe->collector.servaddr.sin_port = rte_cpu_to_be_16(probe->collector.port);

 
printf("----------- MEMORY_SEGMENTS -----------\n");
rte_dump_physmem_layout(stdout);
printf("--------- END_MEMORY_SEGMENTS ---------\n");
printf("------------ MEMORY_ZONES -------------\n");
rte_memzone_dump(stdout);
printf("---------- END_MEMORY_ZONES -----------\n");
printf("---------- TAIL_QUEUES ----------------\n");
rte_dump_tailq(stdout);
 
    return 0;
}
