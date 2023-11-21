DEF =

# GCC 11-specific
DEF += -Wno-unused-result
DEF += -Wno-address-of-packed-member

all:
	gcc -I ../ -o pcap2fmadio main.c -O3 $(DEF) --std=c99 -D_LARGEFILE64_SOURCE -D_GNU_SOURCE -lm

clean:
	rm pcap2fmadio

