CC ?= clang
CFLAGS ?= -Wall -Wextra -pedantic -std=c99 -O2

.PHONY: all
all:
	$(CC) $(CFLAGS) kextract.c -o kextract

.PHONY: clean
clean:
	$(RM) kextract
