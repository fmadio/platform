
DEF =
DEF += -Wno-address-of-packed-member


all:
	gcc -I ../ -o fmadio2stat main.c -O3 $(DEF) --std=c99 -D_LARGEFILE64_SOURCE -D_GNU_SOURCE -lm

clean:
	rm fmadio2stat
