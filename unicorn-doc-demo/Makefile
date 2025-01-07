CFLAGS = -lunicorn -Wall -Wextra -pedantic -O3 -march=native

SOURCES = unicorn_doc_demo.c
BIN = unicorn-doc-demo

ifeq ($(PREFIX),)
    PREFIX := /usr/local
endif

.PHONY: all build clean install

all: build

build: $(BIN)

clean:
	rm -f $(BIN)

install: $(BIN)
	install -d -c $(DESTDIR)$(PREFIX)/bin/
	install -m 0555 -c $(BIN) $(DESTDIR)$(PREFIX)/bin/

$(BIN): $(SOURCES)
	$(CC) $(CFLAGS) -o $(BIN) $(SOURCES)

