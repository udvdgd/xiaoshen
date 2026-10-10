CC ?= cc
CFLAGS ?= -O2 -Wall
LDLIBS = -lcrypto
ifeq ($(OS),windows)
  BIN = xshen-c.exe
else
  BIN = xshen-c
endif
all: $(BIN)
$(BIN): xshen-c.c
	$(CC) $(CFLAGS) -o $@ xshen-c.c $(LDLIBS)
clean:
	rm -f xshen-c xshen-c.exe
.PHONY: all clean
