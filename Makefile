CC=gcc
CFLAGS=-g -static
BINARY_ADDR_SPACE=-Wl,-Ttext-segment=0xff0000

all: apager dpager hello_world

apager: apager.c
	$(CC) $(CFLAGS) apager.c -o apager

dpager: dpager.c
	$(CC) $(CFLAGS) dpager.c -o dpager

hello_world: hello_world.c
	$(CC) $(CFLAGS) $(BINARY_ADDR_SPACE) hello_world.c -o hello_world

clean:
	rm -f apager dpager hello_world
