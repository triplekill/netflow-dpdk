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
#include <rte_spinlock.h>

#include "rte_table.h"

#define MAX_ENTRY       2 * 1024 * 1024

/* ***************************************** */

#define FLOW_VERSION_5       5
#define V5FLOWS_PER_PAK     30

struct flow_ver5_hdr {
  u_int16_t version;         /* Current version=5*/
  u_int16_t count;           /* The number of records in PDU. */
  u_int32_t sysUptime;       /* Current time in msecs since router booted */
  u_int32_t unix_secs;       /* Current seconds since 0000 UTC 1970 */
  u_int32_t unix_nsecs;      /* Residual nanoseconds since 0000 UTC 1970 */
  u_int32_t flow_sequence;   /* Sequence number of total flows seen */
  u_int8_t  engine_type;     /* Type of flow switching engine (RP,VIP,etc.)*/
  u_int8_t  engine_id;       /* Slot number of the flow switching engine */
  u_int16_t sampleRate;      /* Packet capture sample rate */
};

struct flow_ver5_rec {
  u_int32_t srcaddr;    /* Source IP Address */
  u_int32_t dstaddr;    /* Destination IP Address */
  u_int32_t nexthop;    /* Next hop router's IP Address */
  u_int16_t input;      /* Input interface index */
  u_int16_t output;     /* Output interface index */
  u_int32_t dPkts;      /* Packets sent in Duration (milliseconds between 1st
               & last packet in this flow)*/
  u_int32_t dOctets;    /* Octets sent in Duration (milliseconds between 1st
               & last packet in  this flow)*/
  u_int32_t first;      /* SysUptime at start of flow */
  u_int32_t last;       /* and of last packet of the flow */
  u_int16_t srcport;    /* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int16_t dstport;    /* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int8_t pad1;        /* pad to word boundary */
  u_int8_t tcp_flags;   /* Cumulative OR of tcp flags */
  u_int8_t proto;        /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
  u_int8_t tos;         /* IP Type-of-Service */
  u_int16_t src_as;     /* source peer/origin Autonomous System */
  u_int16_t dst_as;     /* dst peer/origin Autonomous System */
  u_int8_t src_mask;    /* source route's mask bits */
  u_int8_t dst_mask;    /* destination route's mask bits */
  u_int16_t pad2;       /* pad to word boundary */
};

typedef struct single_flow_ver5_rec {
  struct flow_ver5_hdr flowHeader;
  struct flow_ver5_rec flowRecord[V5FLOWS_PER_PAK+1 /* safe against buffer overflows */];
} NetFlow5Record;

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

    rte_table_netflow_op_hash f_hash;
    uint64_t seed;

    /* Spinlock for entry */
    rte_spinlock_t lock[MAX_ENTRY];

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
