CFLAGS = -Wall -Wextra -pedantic -O3 -march=native

LIB_SOURCES = src/quick_fib.c src/quick_fib.h
BIN_SOURCES = src/main.c $(LIB_SOURCES)

LIB_DYNAMIC = libquick-fib.dyn.so
LIB_STATIC = libquick-fib.static.so
BIN = quick-fib-demo
TARGETS = $(BIN) $(LIB_DYNAMIC) $(LIB_STATIC)

ifeq ($(PREFIX),)
    PREFIX := /usr/local
endif

.PHONY: all build clean install

all: build

build: $(TARGETS)

clean:
	rm -f $(TARGETS)

install: $(TARGETS)
	install -d -c $(DESTDIR)$(PREFIX)/lib/
	install -d -c $(DESTDIR)$(PREFIX)/bin/

	install -m 0555 -c $(LIB_DYNAMIC) $(LIB_STATIC) $(DESTDIR)$(PREFIX)/lib/
	install -m 0555 -c $(BIN) $(DESTDIR)$(PREFIX)/bin/

$(BIN): $(BIN_SOURCES)
	$(CC) $(CFLAGS) -o $(BIN) $(BIN_SOURCES)

$(LIB_DYNAMIC): $(LIB_SOURCES)
	$(CC) $(CFLAGS) -shared -o $(LIB_DYNAMIC) $(LIB_SOURCES)

$(LIB_STATIC): $(LIB_SOURCES)
	$(CC) $(CFLAGS) -static -shared -o $(LIB_STATIC) $(LIB_SOURCES)

