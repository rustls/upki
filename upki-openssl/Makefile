CC = gcc
CFLAGS = -Wall -Wextra -fPIC
LDFLAGS = -shared
LIBS = -lssl -lcrypto -ldl -lupkiopenssl -L../target/release/

TARGET = libupkiopenssl-preload.so
SOURCE = preload.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SOURCE) upki-openssl.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SOURCE) $(LIBS)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/lib/

uninstall:
	rm -f /usr/local/lib/$(TARGET)
