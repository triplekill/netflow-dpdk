#include <unistd.h>

#include "probe.h"
#include "rte_table_netflow.h"

#include "netflow-export.h"

extern probe_t probe;

static void add_to_expired(hashBucket_t *export_list, hashBucket_t *bkt)
{
    printf("Add to export list\n");
    while (export_list != NULL) {
        export_list = export_list->next;
    }
    export_list = bkt;
    export_list->next = NULL;
}

static void make_export(hashBucket_t *export_list)
{
    hashBucket_t *next;
    uint32_t count = 0;
    while(export_list != NULL) {
        next = export_list->next;
        printf("Free :%d\n", count++);
        free(export_list);
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
    struct timeval curr, lastseen, firstseen;

    while (1) {
        /* check hash table */
        entry = t->n_entries;
        
        /* loop all entry */
        for(i = 0; i < entry; i++) {
            bkt = t->array[i];
            if(likely(bkt == NULL)) continue;

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
                    add_to_expired(export_list, bkt);
                    bkt = prev_next_pointer;
                    continue;
                }
                prev_next_pointer = bkt->next;
                bkt = bkt->next;
            }
        }
        /* for each entry, check life time */
        make_export(export_list);
        sleep(1);

    } /* end of while */

}
