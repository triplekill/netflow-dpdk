#ifndef _MAIN_H_
#define _MAIN_H_

#ifdef RTE_EXEC_ENV_BAREMETAL
#define MAIN _main
#else
#define MAIN main
#endif

/* struct for netflow */
//typedef struct rte_hash lookup_struct_t;
//static lookup_struct_t *ipv4_flow_lookup;

struct ipv4_5tuple {
        uint32_t ip_dst;
        uint32_t ip_src;
        uint16_t port_dst;
        uint16_t port_src;
        uint8_t  proto;
} __attribute__((__packed__));


static void print_ipv4_5_tuple(struct ipv4_5tuple *);
static void ipv4_addr_dump(const char *, uint32_t);

int MAIN(int argc, char **argv);

#endif /* _MAIN_H_ */
