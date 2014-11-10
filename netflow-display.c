#include "netflow-display.h"

#include <stdio.h>
#include <unistd.h>

#include "probe.h"

extern probe_t  probe;

void 
netflow_logo(int row, int col,   const char * appname)
{
    int i;
    static const char * logo[] = {
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
    port_info_t *info = &probe.info[0];
    printf("############ Statistics ###############\n");
    printf("+Pkts\n");
    printf(" +---ARP : %" PRIu64 "\n", info->stats.arp_pkts);
    printf(" +---IPv4: %" PRIu64 "\n", info->stats.ip_pkts);
    printf(" +---IPv6: %" PRIu64 "\n", info->stats.ipv6_pkts);
    exit(1);
}

