OUT := wrapper
SRCS := $(wildcard ./*.c)
HEADERS := $(wildcard ./*.h)
CFLAGS := -O3 -Wall -Wextra -Wpedantic -m32 -ggdb
CC := gcc

all: $(OUT)

$(OUT): $(SRCS) $(HEADERS)
	$(CC) $(CFLAGS) $(SRCS) -o $@

clean:
	rm $(OUT)

test: $(OUT)
	./$(OUT) kmc/gcc/MIPSE/BIN/AS.OUT

.PHONY: all clean test
