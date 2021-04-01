OUT := wrapper
SRCS := $(wildcard ./*.c)
HEADERS := $(wildcard ./*.h)
CFLAGS := -O3 -Wall -Wextra -Wpedantic -m32 -ggdb -Iinclude
CC := gcc
PROGRAMS := as cc1

all: $(PROGRAMS)

$(PROGRAMS): $(SRCS) $(HEADERS)
	$(CC) $(CFLAGS) $(SRCS) -DPROG=$@ -o $@

clean:
	rm -f $(PROGRAMS)

test: as
	./as in.s -o out.o

.PHONY: all clean test