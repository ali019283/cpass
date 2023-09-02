SOURCES=cpass.c
EXECUTABLE=cpass
PREFIX=/usr/local
CFLAGS += -O2

all:
	$(CC) $(SOURCES) $(CFLAGS) -l gpgme -o $(EXECUTABLE)

install: all
	cp $(EXECUTABLE) $(DESTDIR)$(PREFIX)/bin
