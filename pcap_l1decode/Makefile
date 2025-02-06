GIT_COMMIT := $(shell git rev-parse HEAD)

OBJS =
OBJS += main.o

DEF =
DEF += -O2
DEF += --std=c11
DEF += -I../
DEF += -D_LARGEFILE64_SOURCE
DEF += -D_GNU_SOURCE
DEF += -DGIT_COMMIT='"$(GIT_COMMIT)"'
DEF += -march=core-avx2
DEF += -mavx2

LIBS =
LIBS += -lm
LIBS += -lpthread

%.o: %.c
	gcc $(DEF) -c -o $@ $<

all: $(OBJS)
	gcc -o pcap_l1decode $(OBJS) $(LIBS)

clean:
	rm -f $(OBJS)
	rm -f pcap_l1decode
