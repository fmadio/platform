all:
	make -C fmadio2pcap
	make -C fmadio2eth
	make -C fmadio2stat
	make -C fmadio2trace
	make -C pcap2fmadio 
