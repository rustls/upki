CPPFLAGS += $(shell pkg-config --cflags upki)
LDLIBS += $(shell pkg-config --libs upki)
LDFLAGS += -Wl,-rpath,$(shell pkg-config --variable libdir upki)

upki-demo: upki-demo.c demo-certs.h

clean:
	rm -f upki-demo
