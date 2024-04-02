CC=gcc
CFLAGS=-g -static
BINARY_ADDR_SPACE=-Wl,-Ttext-segment=0xff0000

# List of test programs
TESTS = hello_world simple_math memory_alloc file_operations string_manipulation prime_numbers

all: apager dpager tests

apager: apager.c
	$(CC) $(CFLAGS) apager.c -o apager

dpager: dpager.c
	$(CC) $(CFLAGS) dpager.c -o dpager

tests: $(TESTS)

# Compile test programs
$(TESTS): %: %.c
	$(CC) $(CFLAGS) $(BINARY_ADDR_SPACE) $< -o $@

clean:
	rm -f apager dpager $(TESTS)
