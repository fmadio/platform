# Operation

```

sudo stream_cat test1_20251003_0802 | ./pcap_l1softmac | capinfos2 -v --seq --with-fcs --pcap-portid


```

This outputs a standard PCAP file on stdout using the Layer1 XGMII Packet In Packet Capture as the data source

capinfos2 will sequence check all the payloaded data. This step can be omited and the PCAP written directly to disk


## Example of Corrupted Layer 1 Traffic

Debugging corrupted Layer1 traffic can be assisted using

```
sudo stream_cat test1_20251003_0802 | ./pcap_l1softmac --xgmii-packet > /dev/null 
```


The resulting output shows the raw Layer1 data used to output a packet. This allows easy identification of Layer1 problems such as missing SOF, Preamble, EOF markers as shown below


Example Correct fully framed packet 

```
Generate packet: TS:0 Bytes:73
 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1
fb555555555555d5001111111111005500000000000000000b0000ca0c0000ca0d0000ca0e0000ca0f0000ca100000ca110000ca120000ca130000ca140000ca150000ca465d7389fd
```


Example missing SOF


```
Generate packet: TS:0 Bytes:73
 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1
fb515555555554d500111101111100150000000000000000160000ca170000ca180000ca190000ca1a0000ca1b0000ca1c0000ca1d0000ca1e0000ca1f0081aa200402ca26567b89fd
invalid preamble

```


Example missing EOF


```
Generate packet: TS:0 Bytes:157
 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 1 1 1 1 1 1 1 1 0 1 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1
fb515555555554d5001111011111001500000000000000402c0000ca2d0000ca2e0000ca2f0000ca300000ca310000ca320000ca330000ca340000ca3500008a360402cabe4e3f8ddd0707070705074707070517fb555515555155d500111011111100450000004000000000370000ca380000ca390000ca3a0000ca3b0000ca3c0000ca3d0000ca3e0000ca3f0000ca600400da4102018a3e16fe2efd

```

