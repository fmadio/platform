OBJS =
OBJS += main.o

DEF = 
DEF += -O2
DEF += --std=c99 
DEF += -I../
DEF += -D_LARGEFILE64_SOURCE 
DEF += -D_GNU_SOURCE 
DEF += -g

LIBS =
LIBS += -lm
LIBS += -lpthread

%.o: %.c
	gcc $(DEF) -c -o $@ $<

all: $(OBJS) 
	gcc -o capinfos2 -g $(OBJS)  $(LIBS)

clean:
	rm -f $(OBJS)
	rm -f capinfos2 

