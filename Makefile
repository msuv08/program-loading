CC=gcc
CFLAGS=-g -static

all: apager hello_world

apager: apager.c
	$(CC) $(CFLAGS) apager.c -o apager

hello_world: hello_world.c
	$(CC) $(CFLAGS) hello_world.c -o hello_world

clean:
	rm -f apager hello_world
