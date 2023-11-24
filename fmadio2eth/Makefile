DEF =
DEF += -O3
DEF += --std=c99
DEF += -D_LARGEFILE64_SOURCE
DEF += -D_GNU_SOURCE

# GCC 11-specific
DEF += -Wno-unused-result
DEF += -Wno-address-of-packed-member

INCL =
INCL += -I ../

LIBS =
LIBS += -lm

all:
	gcc -o fmadio2eth main.c $(DEF) $(INCL) $(LIBS)

clean:
	rm fmadio2eth

