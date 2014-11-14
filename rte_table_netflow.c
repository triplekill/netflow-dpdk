#include <string.h>
#include <stdio.h>
#include <sys/time.h>

#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_log.h>
#include <rte_byteorder.h>
#include <rte_hash_crc.h>

#include "rte_table_netflow.h"

void *
rte_table_netflow_create(void *params, int socket_id, uint32_t entry_size)
{
    struct rte_table_netflow_params *p = 
        (struct rte_table_netflow_params *) params;

    struct rte_table_netflow *t;
    uint32_t total_cl_size, total_size;
    uint32_t i;

    /* Check input parameters */
    if ((p == NULL) ||
        (p->n_entries == 0) ||
        (!rte_is_power_of_2(p->n_entries)) ||
        ((p->offset &0x3)  != 0) ) {
        return NULL;
    }

    /* Memory allocation */
    total_cl_size = (sizeof(struct rte_table_netflow) +
            CACHE_LINE_SIZE) / CACHE_LINE_SIZE;
    total_cl_size += (p->n_entries * sizeof(hashBucket_t*) + 
            CACHE_LINE_SIZE) / CACHE_LINE_SIZE;
    total_size = total_cl_size * CACHE_LINE_SIZE;
    t = rte_zmalloc_socket("TABLE", total_size, CACHE_LINE_SIZE, socket_id);
    if (t == NULL) {
        RTE_LOG(ERR, TABLE,
            "%s: Cannot allocate %u bytes for netflow table\n",
            __func__, total_size);
        return NULL;
    }

    /* Memory initialzation */
    t->entry_size = entry_size;
    t->n_entries = p->n_entries;
    t->offset = p->offset;
    t->entry_pos_mask = t->n_entries - 1;
    t->f_hash = p->f_hash;
    t->seed = p->seed;

    return t;
}

int
rte_table_netflow_entry_add(
    void *table,
    void *key,
    void *entry,
    int *key_found,
    void **entry_ptr)
{
    struct rte_table_netflow *t = (struct rte_table_netflow *)table;
    union rte_table_netflow_key *k = key;
    struct ipv4_hdr *ip = entry;
    struct tcp_hdr *tcp;
    hashBucket_t *previous_pointer = NULL;
    hashBucket_t *bucket = NULL;
    hashBucket_t *bkt = NULL;
    uint32_t idx = 0;
    uint8_t updated = 0; 
    uint8_t notfound = 0; 
    struct timeval curr;

    /* hashing with SSE4_2 CRC32 */ 
    idx = rte_hash_crc_4byte(k->proto, idx);
    idx = rte_hash_crc_4byte(k->ip_src, idx);
    idx = rte_hash_crc_4byte(k->ip_dst, idx);
    idx = rte_hash_crc_4byte(k->port_src, idx);
    idx = rte_hash_crc_4byte(k->port_dst, idx);
    idx = idx % t->n_entries;
    //idx = (k->proto + k->ip_src + k->ip_dst + k->port_src + k->port_dst) % t->n_entries;
    bucket = t->array[idx];
    previous_pointer = bucket;
    
    /* TODO: need lock on this entry */
    while (bucket != NULL) {
        /* Find same flow in the bucket's list */
        if ((bucket->ip_src == k->ip_src) && (bucket->ip_dst == k->ip_dst) ) {
            /* accumulated ToS Field */
            bucket->src2dstTos |= ip->type_of_service;

            /* accumulated TCP Flags */
            if (k->proto == IPPROTO_TCP) {
                tcp = (struct tcp_hdr *)((unsigned char*)ip + sizeof(struct ipv4_hdr));
                bucket->src2dstTcpFlags |= tcp->tcp_flags;
            }

            /* accumulated Bytes */
            bucket->bytesSent += rte_be_to_cpu_16(ip->total_length);
            bucket->pktSent++;

            /* Time */
            gettimeofday(&curr, NULL);
            bucket->lastSeenSent = curr;

            updated = 1;
            break;
        }
        printf("Bucket collision\n");
        notfound = 1;
        previous_pointer = bucket;
        bucket = bucket->next;
    }

    if( !updated ) {
        /* Create New Bucket */
        printf("First Seen : %" PRIu32 "\n", idx);
        bkt = (hashBucket_t *)rte_zmalloc("BUCKET", sizeof(hashBucket_t), CACHE_LINE_SIZE);
        bkt->magic = 1;
        bkt->vlanId     = k->vlanId;
        bkt->proto      = k->proto;
        bkt->ip_src     = k->ip_src;
        bkt->ip_dst     = k->ip_dst;
        bkt->port_src   = k->port_src;
        bkt->port_dst   = k->port_dst;
    
        /* ToS Field */
        bkt->src2dstTos = ip->type_of_service; 
        
        /* TCP Flags */
        if (k->proto == IPPROTO_TCP) {
            tcp = (struct tcp_hdr *)((unsigned char*)ip + sizeof(struct ipv4_hdr));
            bkt->src2dstTcpFlags = tcp->tcp_flags;

            /* TODO: If TCP flags is start of Flow (Syn) 
             * Save payload of DPI 
             */

            /* If Flags is FIN, check and of flow */
        }

        /* Bytes (Total number of Layer 3 bytes)  */
        bkt->bytesSent = rte_be_to_cpu_16(ip->total_length);
        bkt->pktSent++;

        /* Time */
        gettimeofday(&curr, NULL);
        bkt->firstSeenSent = bkt->lastSeenSent = curr; 
        
        /* Update contents of bucket */
        if (notfound) previous_pointer->next = bkt;
        else t->array[idx] = bkt;
    }
   
    return 1;
}
static int
rte_table_netflow_free(void *table)
{
    struct rte_table_netflow *t = (struct rte_table_netflow *)table;
    
    /* Check input paramters */
    if (t == NULL) {
        RTE_LOG(ERR, TABLE, "%s: table parameter is NULL\n", __func__);
        return -EINVAL;
    }

    /* Free previously allocated resources */
    rte_free(t);
    return 0;
}


struct rte_table_ops rte_table_netflow_ops = {
    .f_create = rte_table_netflow_create,
    .f_free   = rte_table_netflow_free,
    .f_add    = rte_table_netflow_entry_add,
    .f_delete = NULL,
    .f_lookup = NULL, /* rte_table_netflow_lookup, */
};


