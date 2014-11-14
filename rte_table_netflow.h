#ifndef __INCLUDE_RTE_TABLE_NETFLOW_H__
#define __INCLUDE_RTE_TABLE_NETFLOW_H__

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * RTE Table Netflow
 *
 * array indexing, Lookup key is the array entry index.
 *
 ***/

#include <stdint.h>
#include <sys/time.h>

#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>

#include "rte_table.h"

typedef struct rte_table_hashBucket_v5 {
    uint8_t magic;
    uint8_t bucket_expired;
    uint8_t _pad0, _pad1;

    uint32_t srcaddr;
    uint32_t dstaddr;
    uint32_t nexthop;
    uint16_t input;                 /**< SNMP index of input interface                                  */
    uint16_t output;                /**< SNMP index of output interface                                 */
    uint32_t dPkts;                 /**< Packets in the flow                                            */
    uint32_t dOctets;               /**< Total number of Layer 3 bytes in the packets of the flow       */
    uint32_t first;                 /**< SysUptime at start of flow                                     */
    uint32_t last;                  /**< SysUptime at the time the last packet of the flow was received */
    uint16_t srcport;               /**< TCP/UDP source port number or equivalent                       */
    uint16_t dstport;               /**< TCP/UDP destination port number or equivalent                  */
    uint8_t  pad1;                  /**< Unused (zero) bytes                                            */
    uint8_t  tcp_flags;             /**< Cumulative OR of TCP flags                                     */
    uint8_t  prot;                  /**< IP protocol type                                               */
    uint8_t  tos;                   /**< IP type of service (TOS)                                       */
    uint16_t src_as;                /**< Autonomous system number of the source, either orgin or peer   */
    uint16_t dst_as;                /**< Autonomous system number of the destination, either or peer    */
    uint8_t  src_mask;              /**< Source address prefix mask bits                                */
    uint8_t  dst_mask;              /**< Dstination address prefix mask bits                            */
    uint16_t pad2;                  /**< Unused (zero) bytes                              (4+48 Bytes)  */

    struct rte_table_hashBucket_v5 *next;
} hashBucket_v5;
 
typedef struct rte_table_hashBucket {
    uint8_t magic;                                  /**< magic code for validation */
    uint8_t bucket_expired;                         /**< force bucket to expire */
    uint8_t vlanId;
    uint8_t proto;

    uint32_t ip_src;                                /**< saved in network order */
    uint32_t ip_dst;                                /**< saved in network order */
    uint16_t port_src;                              /**< saved in network order */
    uint16_t port_dst;                              /**< saved in network order */

    uint8_t src2dstTos, dst2srcTos;
    uint8_t src2dstTcpFlags, dst2srcTcpFlags;
    uint8_t pad1, pad2;

    uint64_t bytesSent, pktSent;                    /**< saved in host order */
    uint64_t bytesRcvd, pktRcvd;                    /**< saved in host order */
    struct timeval firstSeenRcvd, lastSeenRcvd;     /**< sizeof(timeval) = 16 Bytes */
    struct timeval firstSeenSent, lastSeenSent;

  
    struct rte_table_hashBucket *next;
} hashBucket_t;

/** Netflow table key format */
union rte_table_netflow_key {
    struct {
        uint8_t pad0;
        uint8_t vlanId;
        uint8_t pad1;
        uint8_t proto;
        uint32_t ip_src;
        uint32_t ip_dst;
        uint16_t port_src;
        uint16_t port_dst;
    };
    __m128i xmm;
};


/** Hash function (rte_hash_crc_4bytes) */
typedef uint32_t (*rte_table_netflow_op_hash)(
    uint32_t key,
    uint32_t seed);


/** Netflow table parameters */
struct rte_table_netflow_params {
    /** Number of array entries. Has to be a power of two. */
    uint32_t n_entries;

    /** Byte offset within input */
    uint32_t offset;

    /** Hash function */
    rte_table_netflow_op_hash f_hash;

    /** Seed value for the hash function */
    uint64_t seed;

};


struct rte_table_netflow {
    /* Input parameters */
    uint32_t entry_size;
    uint32_t n_entries;
    uint32_t offset;

    rte_table_netflow_op_hash f_hash;
    uint64_t seed;

    /* Internal fields */
    uint32_t entry_pos_mask;

    /* Internal table */
    hashBucket_t *array[0] __rte_cache_aligned;
} __rte_cache_aligned;


/** Netflow table operations */
extern struct rte_table_ops rte_table_netflow_ops;

void *rte_table_netflow_create(void *, int, uint32_t);

#ifdef __cplusplus
}
#endif

#endif
