all:
	make -C fmadio2pcap
	make -C fmadio2eth
	make -C fmadio2stat
	make -C pcap2fmadio 
