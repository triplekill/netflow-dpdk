# Netflow engine with DPDK support #

## Abstract ##
Netflow is a key component for network traffic monitoring. As high speed technologies such as 10 Gbps or 40 Gbps links are common in a backbone network, it is impossible to monitor traffic via conventional software like nProbe. DPDK is next solution for monitoring high speed network with commodity hardware.

## Proposal ##

## Background ##

## Rationale ##

## Initial Goal ##
  * rte\_table\_netflow structure
  * Probe 10G/40G traffic without packet loss
  * Export netflow V5 format

## External Dependencies ##
  * DPDK

## Initial Committers ##
  * Choonho Son (choonho.son@gmail.com)

## Installation ##


```
git clone https://code.google.com/p/netflow-dpdk/
cd netflow-dpdk
export RTE_SDK=<DPDK source path>
export RTE_TARGET=x86_64-native-linuxapp-gcc
make
```


Usage
```
./build/dprobe -c 3 -n 2 -- -m "2:0.0" -q 1
```

Roadmap

# Performance #
![https://netflow-dpdk.googlecode.com/git/doc/netflow_testbed.png](https://netflow-dpdk.googlecode.com/git/doc/netflow_testbed.png)