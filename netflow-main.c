/*-
 *   BSD LICENSE
 * 
 *   Copyright(c) 2014 Choonho Son All rights reserved.
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
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
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

#include "netflow-main.h"

#include "probe.h"
#include "netflow-display.h"
#include "netflow-init.h"
#include "netflow-export.h"

#include <signal.h>

probe_t probe;


/**************************************************************************
 * netflow_usage - Display the help for the command line.
 * 
 * DESCRIPTION
 * Display the help message for the command line.
 *
 * RETURNS: N/A
 */

static void
netflow_usage(const char *prgname)
{
    printf("Usage: %s [EAL options] -- [-h]\n"
            " -m <string> matrix for mapping ports to logical cores\n"
            " -h        Display the help information\n",
            prgname);
}

/****************************************************************************** 
 * netflow_parse_args - Parse the argument given in the command line of the application 
 *
 * DESCRIPTION
 * Main parsing routine for the command line.
 * 
 * RETURNS: N/A
 */

static int
netflow_parse_args(int argc, char **argv)
{
    int opt, ret;
    char **argvopt;
    int option_index;
    char *prgname = argv[0];
    static struct option lgopts[] = {
        {NULL, 0, 0, 0}
    };

    argvopt = argv;

    while ((opt = getopt_long(argc, argvopt, "p:",
                  lgopts, &option_index)) != EOF) {

        switch (opt) {
        /* portmask */
        case 'p':
            // Port mask not used anymore
            break;


        /* long options */
        case 0:
            netflow_usage(prgname);
            return -1;

        default:
            netflow_usage(prgname);
            return -1;
        }
    }

    if (optind >= 0)
        argv[optind-1] = prgname;

    ret = optind-1;
    optind = 0; /* reset getopt lib */
    return ret;
}



int main(int argc, char **argv)
{
    int32_t ret;
    uint8_t lcore_id;

    /* Signal */
    signal(SIGINT,(void *)netflow_print);
 

    clrscr();
    // call before the rte_eal_init()
    (void)rte_set_application_usage_hook(netflow_usage);

    memset(&probe, 0, sizeof(probe));

    netflow_logo(8, 0, NETFLOW_APP_NAME); 
    sleep(2);
    
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Failed in rte_eal_init\n");
    argc -= ret;
    argv += ret;
    
    ret = netflow_parse_args(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid arguments\n");
  
    netflow_init(&probe);

    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        rte_eal_remote_launch(launch_probe, NULL, lcore_id);
    }
    rte_delay_ms(5000);     // wait for the lcores to start up

    // Wait for all of the cores to stop runing and exit.

    process_hashtable();
    rte_eal_mp_wait_lcore(); 

    return 0;
}

