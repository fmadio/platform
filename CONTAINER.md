# FMADIO Refernce Container Images

## CentOS 7.9

Stock centos container image

[CentOS 7.9 Base](https://fmad.io/download/lxc/20220119_lxc_centos7.9.tar.gz)

MD5     : 0525ee54f30dab29af296e8e104d69c4
UserName: fmadio
Network : Bridged DHCP 


FMADIO Software install in
/opt/fmadio/platform

Example usage:

```
fmadio@centos:/$ /opt/fmadio/platform/fmadio2pcap/fmadio2pcap -i /opt/fmadio/queue/lxc_ring0  | tcpdump -r - -nn | head -n 100
fmadio2pcap
FMAD Ring [/opt/fmadio/queue/lxc_ring0]
Ring size   : 10489868 10489868 16777216
Ring Version:      100      100
RING: Put:98c81024
RING: Get:98c81024
reading from file -, link-type EN10MB (Ethernet)
10:28:37.118509 00:af:20:03:01:00 > 00:af:20:03:02:00 Null Information, send seq 0, rcv seq 0, Flags [Command], length 50
        0x0000:  0000 0000 00ca 0100 00ca 0200 00ca 0300  ................
        0x0010:  00ca 0400 00ca 0500 00ca 0600 00ca 0700  ................
        0x0020:  00ca 0800 00ca 0900 00ca 0a00 00ca bfaa  ................
        0x0030:  fda0                                     ..
10:28:37.118509 00:af:20:03:01:00 > 00:af:20:03:02:00 Null Unnumbered, 0b, Flags [Command], length 50
        0x0000:  0000 0b00 00ca 0c00 00ca 0d00 00ca 0e00  ................
        0x0010:  00ca 0f00 00ca 1000 00ca 1100 00ca 1200  ................
        0x0020:  00ca 1300 00ca 1400 00ca 1500 00ca c961  ...............a
        0x0030:  dc89                                     ..
10:28:37.118509 00:af:20:03:01:00 > 00:af:20:03:02:00 Null Information, send seq 11, rcv seq 0, Flags [Command], length 50
        0x0000:  0000 1600 00ca 1700 00ca 1800 00ca 1900  ................
        0x0010:  00ca 1a00 00ca 1b00 00ca 1c00 00ca 1d00  ................
        0x0020:  00ca 1e00 00ca 1f00 00ca 2000 00ca a968  ...............h
        0x0030:  54a9                                     T.
10:28:37.118509 00:af:20:03:01:00 > 00:af:20:03:02:00 Null Supervisory, Receiver Ready, rcv seq 0, Flags [Command], length 50
10:28:37.118509 00:af:20:03:01:00 > 00:af:20:03:02:00 Null Information, send seq 22, rcv seq 0, Flags [Command], length 50
        0x0000:  0000 2c00 00ca 2d00 00ca 2e00 00ca 2f00  ..,...-......./.
        0x0010:  00ca 3000 00ca 3100 00ca 3200 00ca 3300  ..0...1...2...3.
        0x0020:  00ca 3400 00ca 3500 00ca 3600 00ca 3170  ..4...5...6...1p
        0x0030:  918d                                     ..
10:28:37.118509 00:af:20:03:01:00 > 00:af:20:03:02:00 Null Unnumbered, 27, Flags [Poll], length 50
        0x0000:  0000 3700 00ca 3800 00ca 3900 00ca 3a00  ..7...8...9...:.
        0x0010:  00ca 3b00 00ca 3c00 00ca 3d00 00ca 3e00  ..;...<...=...>.
        0x0020:  00ca 3f00 00ca 4000 00ca 4100 00ca b12a  ..?...@...A....*
        0x0030:  533e                                     S>
10:28:37.118509 00:af:20:03:01:00 > 00:af:20:03:02:00 Null Information, send seq 33, rcv seq 0, Flags [Command], length 50
        0x0000:  0000 4200 00ca 4300 00ca 4400 00ca 4500  ..B...C...D...E.
        0x0010:  00ca 4600 00ca 4700 00ca 4800 00ca 4900  ..F...G...H...I.
        0x0020:  00ca 4a00 00ca 4b00 00ca 4c00 00ca ab91  ..J...K...L.....
        0x0030:  16e2                                     ..
10:28:37.118509 00:af:20:03:01:00 > 00:af:20:03:02:00 Null Supervisory, ?, rcv seq 0, Flags [Command], length 50
10:28:37.118509 00:af:20:03:01:00 > 00:af:20:03:02:00 Null Information, send seq 44, rcv seq 0, Flags [Command], length 50
        0x0000:  0000 5800 00ca 5900 00ca 5a00 00ca 5b00  ..X...Y...Z...[.
        0x0010:  00ca 5c00 00ca 5d00 00ca 5e00 00ca 5f00  ..\...]...^..._.
        0x0020:  00ca 6000 00ca 6100 00ca 6200 00ca 11d9  ..`...a...b.....
        0x0030:  e17d                                     .}
10:28:37.118509 00:af:20:03:01:00 > 00:af:20:03:02:00 Null Unnumbered, ua, Flags [Command], length 50
        0x0000:  0000 6300 00ca 6400 00ca 6500 00ca 6600  ..c...d...e...f.
        0x0010:  00ca 6700 00ca 6800 00ca 6900 00ca 6a00  ..g...h...i...j.
        0x0020:  00ca 6b00 00ca 6c00 00ca 6d00 00ca eabc  ..k...l...m.....
        0x0030:  ce39                                     .9
10:28:37.118509 00:af:20:03:01:00 > 00:af:20:03:02:00 Null Information, send seq 55, rcv seq 0, Flags [Command], length 50
        0x0000:  0000 6e00 00ca 6f00 00ca 7000 00ca 7100  ..n...o...p...q.
        0x0010:  00ca 7200 00ca 7300 00ca 7400 00ca 7500  ..r...s...t...u.
        0x0020:  00ca 7600 00ca 7700 00ca 7800 00ca f8a3  ..v...w...x.....
        0x0030:  aa8b                                     ..
10:28:37.118509 00:af:20:03:01:00 > 00:af:20:03:02:00 Null Supervisory, Reject, rcv seq 0, Flags [Command], length 50
10:28:37.118509 00:af:20:03:01:00 > 00:af:20:03:02:00 Null Information, send seq 66, rcv seq 0, Flags [Command], length 50
        0x0000:  0000 8400 00ca 8500 00ca 8600 00ca 8700  ................
        0x0010:  00ca 8800 00ca 8900 00ca 8a00 00ca 8b00  ................
        0x0020:  00ca 8c00 00ca 8d00 00ca 8e00 00ca ef30  ...............0
        0x0030:  68aa                                     h.
10:28:37.118509 00:af:20:03:01:00 > 00:af:20:03:02:00 Null Unnumbered, 8f, Flags [Command], length 50
        0x0000:  0000 8f00 00ca 9000 00ca 9100 00ca 9200  ................
        0x0010:  00ca 9300 00ca 9400 00ca 9500 00ca 9600  ................

```




