![Alt text](http://fmad.io/analytics/logo_capmerge.png "fmadio platform integration")

[FMADIO Packet Capture 10G 40G 100G](https://fmad.io)


# NASDAQ ITCH Gap Detector

Example program which show gap detection against NASDAQ MouldUDP protocol.

On the Host forward historical data to the containers. One lxc_ring per multicast group 

```
sudo stream_cat --ring /opt/fmadio/queue/lxc_ring0 "vlan and port 26400" 
                --ring /opt/fmadio/queue/lxc_ring1 "vlan and port 26477" 
                --ring /opt/fmadio/queue/lxc_ring2 "vlan and port 25475" 
                -v  nasdaq_itch_20220329_0709 



fmadio@fmadio100v2-228U:~$ sudo stream_cat --ring /opt/fmadio/queue/lxc_ring0 "vlan and port 26400" --ring /opt/fmadio/queue/lxc_ring1 "vlan and port 26477" --ring /opt/fmadio/queue/lxc_ring2  "vlan and port 25475" -v  nasdaq_itch_20220329_0709
outputting to FMAD Ring [/opt/fmadio/queue/lxc_ring0j BPF[vlan and port 26400]
outputting to FMAD Ring [/opt/fmadio/queue/lxc_ring1j BPF[vlan and port 26477]
outputting to FMAD Ring [/opt/fmadio/queue/lxc_ring2j BPF[vlan and port 25475]
stream_cat ioqueue: 4
calibrating...
0 : 2095077966           2.0951 cycles/nsec offset:4.922 Mhz
Cycles/Sec 2095077966.0000 Std:       0 cycle std(  0.00000000) Target:2.10 Ghz
StartChunkID: 0
StartChunk: 0 Offset: 0 Stride: 1
StartChunk: 0
Ring size   : 10489868 16777216
Ring Version:      100      100
RING: Put:a0be2d16
RING: Get:a0be2d16
Ring size   : 10489868 16777216
Ring Version:      100      100
RING: Put:16690b93
RING: Get:16690b93
Ring size   : 10489868 16777216
Ring Version:      100      100
RING: Put:44c78a2
RING: Get:44c78a2
0M Offset:    0GB ChunkID:0 TS:14:00:00.103.352.156 | Pending 209258 MB 0.221Gbps 0.262Mpps CPUIdle:0.000 CPUFetch:0.021 CPUSend:0.000
0M Offset:    0GB ChunkID:414 TS:14:02:44.414.018.489 | Pending 209154 MB 0.754Gbps 0.883Mpps CPUIdle:0.000 CPUFetch:0.025 CPUSend:0.000
1M Offset:    0GB ChunkID:800 TS:14:05:55.054.412.232 | Pending 209058 MB 0.703Gbps 0.826Mpps CPUIdle:0.000 CPUFetch:0.023 CPUSend:0.000
3M Offset:    0GB ChunkID:1427 TS:14:10:29.560.387.241 | Pending 208901 MB 1.143Gbps 1.335Mpps CPUIdle:0.000 CPUFetch:0.037 CPUSend:0.000
4M Offset:    0GB ChunkID:2045 TS:14:16:16.307.170.507 | Pending 208746 MB 1.127Gbps 1.318Mpps CPUIdle:0.000 CPUFetch:0.037 CPUSend:0.000
5M Offset:    0GB ChunkID:2677 TS:14:22:25.039.270.996 | Pending 208588 MB 1.152Gbps 1.341Mpps CPUIdle:0.000 CPUFetch:0.037 CPUSend:0.000
7M Offset:    0GB ChunkID:3308 TS:14:27:31.606.063.986 | Pending 208431 MB 1.152Gbps 1.337Mpps CPUIdle:0.000 CPUFetch:0.038 CPUSend:0.000
8M Offset:    0GB ChunkID:3959 TS:14:28:36.186.994.132 | Pending 208268 MB 1.201Gbps 1.263Mpps CPUIdle:0.000 CPUFetch:0.038 CPUSend:0.000
9M Offset:    0GB ChunkID:4648 TS:14:29:26.644.744.185 | Pending 208096 MB 1.276Gbps 1.320Mpps CPUIdle:0.000 CPUFetch:0.041 CPUSend:0.000
10M Offset:    1GB ChunkID:5322 TS:14:30:00.261.452.606 | Pending 207927 MB 1.249Gbps 1.285Mpps CPUIdle:0.000 CPUFetch:0.039 CPUSend:0.000
12M Offset:    1GB ChunkID:6112 TS:14:30:06.741.726.187 | Pending 207730 MB 1.479Gbps 1.380Mpps CPUIdle:0.000 CPUFetch:0.046 CPUSend:0.000
13M Offset:    1GB ChunkID:6829 TS:14:30:24.556.991.206 | Pending 207550 MB 1.335Gbps 1.310Mpps CPUIdle:0.000 CPUFetch:0.042 CPUSend:0.000
14M Offset:    1GB ChunkID:7590 TS:14:30:43.850.797.971 | Pending 207360 MB 1.425Gbps 1.310Mpps CPUIdle:0.000 CPUFetch:0.045 CPUSend:0.000
16M Offset:    1GB ChunkID:8244 TS:14:31:02.844.839.054 | Pending 207197 MB 1.195Gbps 1.371Mpps CPUIdle:0.000 CPUFetch:0.038 CPUSend:0.000
17M Offset:    1GB ChunkID:8902 TS:14:31:23.491.012.442 | Pending 207032 MB 1.203Gbps 1.381Mpps CPUIdle:0.000 CPUFetch:0.039 CPUSend:0.000
.
.
.
.
.

```

In each container run the following

```
root@centos7:/opt/fmadio/platform/itch_gap# sudo ../fmadio2pcap/fmadio2pcap  -i /opt/fmadio/queue/lxc_ring2 | ./itch_gap
fmadio2pcap
FMAD Ring [/opt/fmadio/queue/lxc_ring2]
Ring size   : 10489868 10489868 16777216
Ring Version:      100      100
RING: Put:44c78a2 a2
RING: Get:44c78a2 a2
{ "_index": "stats", "srcIP": "206.200.243.225", "dstIP": "233.54.12.40", "srcPort": 44314, "dstPort": 25475, "session":"000008792D", "timestamp": "1583244000.000245", "TS": "14:00:00.000.244.736" "messageCount": 1, "gapCount": 0, "vlan_id": 3904 }
{ "_index": "stats", "srcIP": "206.200.243.225", "dstIP": "233.54.12.40", "srcPort": 44314, "dstPort": 25475, "session":"000008792D", "timestamp": "1583244001.000722", "TS": "14:00:01.000.721.664" "messageCount": 1062, "gapCount": 0, "vlan_id": 3904 }
{ "_index": "stats", "srcIP": "206.200.243.225", "dstIP": "233.54.12.40", "srcPort": 44314, "dstPort": 25475, "session":"000008792D", "timestamp": "1583244002.005299", "TS": "14:00:02.005.298.688" "messageCount": 1982, "gapCount": 0, "vlan_id": 3904 }
{ "_index": "stats", "srcIP": "206.200.243.225", "dstIP": "233.54.12.40", "srcPort": 44314, "dstPort": 25475, "session":"000008792D", "timestamp": "1583244003.008571", "TS": "14:00:03.008.571.392" "messageCount": 2657, "gapCount": 0, "vlan_id": 3904 }
{ "_index": "stats", "srcIP": "206.200.243.225", "dstIP": "233.54.12.40", "srcPort": 44314, "dstPort": 25475, "session":"000008792D", "timestamp": "1583244004.013286", "TS": "14:00:04.013.285.888" "messageCount": 2904, "gapCount": 0, "vlan_id": 3904 }
{ "_index": "stats", "srcIP": "206.200.243.225", "dstIP": "233.54.12.40", "srcPort": 44314, "dstPort": 25475, "session":"000008792D", "timestamp": "1583244005.015062", "TS": "14:00:05.015.061.504" "messageCount": 3560, "gapCount": 0, "vlan_id": 3904 }
{ "_index": "stats", "srcIP": "206.200.243.225", "dstIP": "233.54.12.40", "srcPort": 44314, "dstPort": 25475, "session":"000008792D", "timestamp": "1583244006.016664", "TS": "14:00:06.016.663.808" "messageCount": 3885, "gapCount": 0, "vlan_id": 3904 }
{ "_index": "stats", "srcIP": "206.200.243.225", "dstIP": "233.54.12.40", "srcPort": 44314, "dstPort": 25475, "session":"000008792D", "timestamp": "1583244007.031615", "TS": "14:00:07.031.614.464" "messageCount": 4640, "gapCount": 0, "vlan_id": 3904 }
{ "_index": "stats", "srcIP": "206.200.243.225", "dstIP": "233.54.12.40", "srcPort": 44314, "dstPort": 25475, "session":"000008792D", "timestamp": "1583244008.050033", "TS": "14:00:08.050.032.640" "messageCount": 5089, "gapCount": 0, "vlan_id": 3904 }
{ "_index": "stats", "srcIP": "206.200.243.225", "dstIP": "233.54.12.40", "srcPort": 44314, "dstPort": 25475, "session":"000008792D", "timestamp": "1583244009.058244", "TS": "14:00:09.058.244.096" "messageCount": 5683, "gapCount": 0, "vlan_id": 3904 }
{ "_index": "stats", "srcIP": "206.200.243.225", "dstIP": "233.54.12.40", "srcPort": 44314, "dstPort": 25475, "session":"000008792D", "timestamp": "1583244010.067862", "TS": "14:00:10.067.861.760" "messageCount": 6106, "gapCount": 0, "vlan_id": 3904 }
{ "_index": "stats", "srcIP": "206.200.243.225", "dstIP": "233.54.12.40", "srcPort": 44314, "dstPort": 25475, "session":"000008792D", "timestamp": "1583244011.068692", "TS": "14:00:11.068.691.712" "messageCount": 7202, "gapCount": 0, "vlan_id": 3904 }
{ "_index": "stats", "srcIP": "206.200.243.225", "dstIP": "233.54.12.40", "srcPort": 44314, "dstPort": 25475, "session":"000008792D", "timestamp": "1583244012.072803", "TS": "14:00:12.072.803.072" "messageCount": 8164, "gapCount": 0, "vlan_id": 3904 }
{ "_index": "stats", "srcIP": "206.200.243.225", "dstIP": "233.54.12.40", "srcPort": 44314, "dstPort": 25475, "session":"000008792D", "timestamp": "1583244013.072822", "TS": "14:00:13.072.821.504" "messageCount": 8970, "gapCount": 0, "vlan_id": 3904 }
{ "_index": "stats", "srcIP": "206.200.243.225", "dstIP": "233.54.12.40", "srcPort": 44314, "dstPort": 25475, "session":"000008792D", "timestamp": "1583244014.077359", "TS": "14:00:14.077.359.360" "messageCount": 9674, "gapCount": 0, "vlan_id": 3904 }
.
.
.
.

```



