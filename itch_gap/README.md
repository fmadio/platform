# NASDAQ ITCH Gap Detector

Example program which show gap detection against NASDAQ MouldUDP protocol.

On the Host forward historical data to the containers. One lxc_ring per multicast group 

```
sudo stream_cat --ring /opt/fmadio/queue/lxc_ring0 "vlan and port 26400" --ring /opt/fmadio/queue/lxc_ring1 "vlan and port 26477" --ring /opt/fmadio/queue/lxc_ring2  "vlan and port 25475" -v  nasdaq_itch_20220329_0709 
```

In each container run the following

```
root@centos7:/opt/fmadio/platform/itch_gap# sudo ../fmadio2pcap/fmadio2pcap  -i /opt/fmadio/queue/lxc_ring2 | ./itch_gap
```



