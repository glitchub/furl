CFLAGS = -Wall -Werror
LDFLAGS = -s
LDLIBS = -lcurl

furl: furl.c

clean:; rm -f furl
