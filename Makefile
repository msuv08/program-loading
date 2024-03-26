# This is how you write comments
# Use gcc as a compiler
CC=gcc
# CFLAGS will be the options we'll pass to the compiler, adjusted for 64-bit
CFLAGS=-Wall -g -static -fno-pic

# Default target to build everything
all: program_loader hello_world simple_math

# Compile and link the program loader
program_loader: program_loader.o
	$(CC) $(CFLAGS) program_loader.o -o program_loader

# Compile program_loader.c to an object file
program_loader.o: program_loader.c
	$(CC) $(CFLAGS) -c program_loader.c -o program_loader.o

# Compile and link the hello_world program
hello_world: hello_world.o
	$(CC) $(CFLAGS) hello_world.o -o hello_world

# Compile hello_world.c to an object file
hello_world.o: hello_world.c
	$(CC) $(CFLAGS) -c hello_world.c -o hello_world.o

# Compile and link the simple_math program
simple_math: simple_math.o
	$(CC) $(CFLAGS) simple_math.o -o simple_math

# Compile simple_math.c to an object file
simple_math.o: simple_math.c
	$(CC) $(CFLAGS) -c simple_math.c -o simple_math.o

# Clean up build artifacts
clean:
	rm -f *.o program_loader hello_world simple_math
