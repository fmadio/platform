APP = itch_gap

OBJS =
OBJS += main.o

DEF =
DEF += -O3
DEF += --std=c99
DEF += -D_LARGEFILE64_SOURCE
DEF += -D_GNU_SOURCE
DEF += -g

LIBS =

LDFLAG =

%.o: %.c
	gcc $(LDFLAG) $(DEF) -c -o $@ -g $<

all: $(OBJS)
	gcc $(LDFLAG) -g -o $(APP) $(OBJS) $(LIBS)

clean:
	rm -f $(OBJS) $(APP)
