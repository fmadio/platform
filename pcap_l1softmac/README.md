# Operation

```

sudo stream_cat test1_20251003_0802 | ./pcap_l1softmac | capinfos2 -v --seq --with-fcs --pcap-portid


```

This outputs a standard PCAP file on stdout using the Layer1 XGMII Packet In Packet Capture as the data source

capinfos2 will sequence check all the payloaded data. This step can be omited and the PCAP written directly to disk

