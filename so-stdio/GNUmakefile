CC = gcc
CFLAGS = -Wall -fPIC
LDFLAGS= -shared
LDNAME= libso_stdio.so

all: build

build: so_stdio.o utils.o
	$(CC) $(LDFLAGS) $^ -o $(LDNAME)

so_stdio.o: so_stdio.c
	$(CC) $(CFLAGS) -c $^

utils.o: utils.c
	$(CC) $(CFLAGS) -c $^

clean:
	rm -f *.o $(LDNAME)
