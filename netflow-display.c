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


#include "netflow-display.h"

#include <stdio.h>
#include <unistd.h>

#include <rte_log.h>
#include <rte_ethdev.h>
#include "probe.h"
#include "netflow-logs.h"

extern probe_t  probe;

void 
netflow_logo(int row, int col,   const char * appname)
{
    int i;
    static const char * logo[] = {
        "",
        "#     #  #####  #######  ######  #         ####    #       #       #",
        "##    #  #         #     #       #        #    #    #     # #     #",  
        "# #   #  #         #     #       #       #      #   #     # #     #",
        "#  #  #  #####     #     ######  #       #      #    #   #   #   #",
        "#   # #  #         #     #       #       #      #    #   #   #   #",
        "#    ##  #         #     #       #        #    #      # #     # #",
        "#     #  #####     #     #       ######    ####        #       #",
        NULL
    };

    for(i=0, row++; logo[i] != NULL; i++)
        printf("%s\n", logo[i]);
}

void
clrscr()
{
    int ret;
    const char* CLEAR_SCREE_ANSI = "\e[1;1H\e[2J";
    ret = write(STDOUT_FILENO,CLEAR_SCREE_ANSI,12);
}

void
netflow_print(int signo)
{
    int i;
    port_info_t *info;
    printf("\n\n\n"); 
    NETFLOW_DISPLAY(INFO, "############ Statistics ###############\n");
    for (i = 0; i < probe.nb_ports; i++) {
        info = &probe.info[i];
        NETFLOW_DISPLAY(INFO, "+Processing(Port: %d)\n", i);
        NETFLOW_DISPLAY(INFO, " +---ARP : %" PRIu64 "\n", info->stats.arp_pkts);
        NETFLOW_DISPLAY(INFO, " +---IPv4: %" PRIu64 "\n", info->stats.ip_pkts);
        NETFLOW_DISPLAY(INFO, " +---IPv6: %" PRIu64 "\n", info->stats.ipv6_pkts);
    
        /* log ethernet stat */
        rte_eth_stats_get(i, &info->port_stats);
        NETFLOW_DISPLAY(INFO, "+Ethernet Stats(Port: %d)\n", i);
        NETFLOW_DISPLAY(INFO, " +---ipackets: %" PRIu64 "\n", info->port_stats.ipackets - info->init_stats.ipackets);
        NETFLOW_DISPLAY(INFO, " +---ibytes  : %" PRIu64 "\n", info->port_stats.ibytes - info->init_stats.ibytes);
        NETFLOW_DISPLAY(INFO, " +---imissed : %" PRIu64 "\n", info->port_stats.imissed - info->init_stats.imissed);
    }

    exit(1);
}

