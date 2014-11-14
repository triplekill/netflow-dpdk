#include <unistd.h>
#include <time.h>

#include "probe.h"
#include "rte_table_netflow.h"

#include <rte_byteorder.h>

#include "netflow-export.h"

extern probe_t probe;

/* Global Variable */
static struct timeval initialSniffTime;
static struct timeval actTime;

uint8_t engineType, engineId;
uint16_t sampleRate;

NetFlow5Record theV5Flow;

void netflow_export_init() {
    gettimeofday(&initialSniffTime, NULL);
    engineType = 0;
    engineId = 0;
    sampleRate = 0;
}

/* ****************************************************** */

u_int32_t msTimeDiff(struct timeval end, struct timeval begin) {
  if((end.tv_sec == 0) && (end.tv_usec == 0))
    return(0);
  else
    return((end.tv_sec-begin.tv_sec)*1000+(end.tv_usec-begin.tv_usec)/1000);
}

/******************************************************* */

void initNetFlowV5Header(NetFlow5Record *theV5Flow) {
  memset(&theV5Flow->flowHeader, 0, sizeof(theV5Flow->flowHeader));

  theV5Flow->flowHeader.version        = rte_cpu_to_be_16(5);
  theV5Flow->flowHeader.sysUptime      = rte_cpu_to_be_32(msTimeDiff(actTime,
                              initialSniffTime));
  theV5Flow->flowHeader.unix_secs      = rte_cpu_to_be_32(actTime.tv_sec);
  theV5Flow->flowHeader.unix_nsecs     = rte_cpu_to_be_32(actTime.tv_usec/1000);
  /* NOTE: theV5Flow->flowHeader.flow_sequence will be filled by sendFlowData */
  theV5Flow->flowHeader.engine_type    = (u_int8_t)engineType;
  theV5Flow->flowHeader.engine_id      = (u_int8_t)engineId;

  theV5Flow->flowHeader.sampleRate     = rte_cpu_to_be_16(sampleRate);
}

static int exportBucketToNetflowV5(hashBucket_t* bkt, uint8_t numFlows)
{
    theV5Flow.flowRecord[numFlows].input     = 0;           // TODO
    theV5Flow.flowRecord[numFlows].output    = 0;           // TODO
    theV5Flow.flowRecord[numFlows].srcaddr   = bkt->ip_src;
    theV5Flow.flowRecord[numFlows].dstaddr   = bkt->ip_dst;
    theV5Flow.flowRecord[numFlows].dPkts     = rte_cpu_to_be_32(bkt->pktSent);
    theV5Flow.flowRecord[numFlows].dOctets   = rte_cpu_to_be_32(bkt->bytesSent);
    theV5Flow.flowRecord[numFlows].first     = rte_cpu_to_be_32(msTimeDiff(bkt->firstSeenSent, initialSniffTime));
    theV5Flow.flowRecord[numFlows].last      = rte_cpu_to_be_32(msTimeDiff(bkt->lastSeenSent, initialSniffTime));
    theV5Flow.flowRecord[numFlows].srcport   = bkt->port_src;
    theV5Flow.flowRecord[numFlows].dstport   = bkt->port_dst;
    theV5Flow.flowRecord[numFlows].tos       = bkt->src2dstTos;
    theV5Flow.flowRecord[numFlows].src_as    = 0;           // TODO
    theV5Flow.flowRecord[numFlows].dst_as    = 0;           // TODO 
    theV5Flow.flowRecord[numFlows].src_mask  = 0;           // TODO
    theV5Flow.flowRecord[numFlows].dst_mask  = 0;           // TODO
    theV5Flow.flowRecord[numFlows].tcp_flags = bkt->src2dstTcpFlags;

}

hashBucket_t* makeNetFlowV5(hashBucket_t *list)
{
    int8_t num_flows = 1;
    hashBucket_t *temp;

    /* Make header */
    initNetFlowV5Header(&theV5Flow);
    /* Make Records */
    while(list != NULL) {
        temp = list;
        exportBucketToNetflowV5(list, num_flows);
        list = list->next;
        rte_free(temp);
        num_flows++;
        if(num_flows > V5FLOWS_PER_PAK) break;
    }
    theV5Flow.flowHeader.count = --num_flows;
    return list; 
}

void sendNetflowV5()
{
    printf("count:%d\n", theV5Flow.flowHeader.count);
}

static void make_export(hashBucket_t *export_list)
{
    hashBucket_t *next;
    uint32_t count = 0;
    gettimeofday(&actTime, NULL);
    
    if (5) {
        while (export_list != NULL) {
            export_list = makeNetFlowV5(export_list);
            sendNetflowV5();
        }
    }
}
#define IDLE_TIMEOUT 60
#define LIFETIME_TIMEOUT 120

void process_hashtable()
{
    struct rte_table_netflow *t = (struct rte_table_netflow *)probe.table[0][0];
    hashBucket_t *bkt;
    hashBucket_t *export_list = NULL;
    struct rte_table_hashBucket *prev_next_pointer;

    uint32_t i, entry;
    uint32_t sleep_time;
    struct timeval curr, lastseen, firstseen;

    while (1) {
        sleep_time = 60 - (time(NULL) % 60);        /* Align minutes */
        sleep(sleep_time);

        /* check hash table */
        entry = t->n_entries;
        
        /* loop all entry */
        for(i = 0; i < entry; i++) {
            /****************************************************************
             * Lock one entry (t->array[i]'s lock = t->lock[i]
             *
             * So netflow_export can use other entries 
             ****************************************************************/
            rte_spinlock_lock(&t->lock[i]);
     
            bkt = t->array[i];
            if(likely(bkt == NULL)) {
                rte_spinlock_unlock(&t->lock[i]); 
                continue;
            }

            /* Bucket exist */
            /* lock the entry */
            gettimeofday(&curr, NULL);

            /* check first bucket */
            lastseen = bkt->lastSeenSent;
            firstseen = bkt->firstSeenSent;

            prev_next_pointer = t->array[i];

            /* check after first bucket */
            while(bkt != NULL) {
                /* check bucket timestamp */
                lastseen = bkt->lastSeenSent;
                firstseen = bkt->firstSeenSent;

                if ( ((curr.tv_sec - lastseen.tv_sec) > IDLE_TIMEOUT)          /* data doesn't send for a while */
                    || ((curr.tv_sec - firstseen.tv_sec) > LIFETIME_TIMEOUT)   /* flow is active, but too old   */
                    || bkt->bucket_expired > 0 ) {
                    /* export bucket to export_list */
                    prev_next_pointer = bkt->next;
                    bkt->next = export_list;
                    export_list = bkt;

                    bkt = prev_next_pointer;
                    continue;
                }
                prev_next_pointer = bkt->next;
                bkt = bkt->next;
            }
       
            rte_spinlock_unlock(&t->lock[i]);
            /***********************************************************************
             * End of entry lock
             * release lock
             **********************************************************************/
        }
        /* for each entry, check life time */
        make_export(export_list);

    } /* end of while */

}
