CC ?= gcc
CFLAGS = -O2 -Wall
BIN = ../bin

all: $(BIN)/xor_brute $(BIN)/rc4_crack $(BIN)/elf_strings $(BIN)/smart_brute

$(BIN)/%: %.c
	mkdir -p $(BIN) && $(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(BIN)/*

.PHONY: all clean
