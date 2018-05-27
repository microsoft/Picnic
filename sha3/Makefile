ifeq ($(OS),Windows_NT)
	UNAME_S=Windows
else
	UNAME_S := $(shell uname -s)
endif
CC=gcc
WARNING_FLAGS=-Wall -Wextra -Wpedantic -Werror -Wno-unused-function
CFLAGS= -O2 -march=native $(WARNING_FLAGS) -std=gnu99 

SOURCES=$(wildcard *.c)
OBJECTS=$(patsubst %.c,%.o,$(wildcard *.c))
ifeq ($(UNAME_S),Darwin)
	SHA3LIB=libshake.dylib
else
	SHA3LIB=libshake.a
endif

ifeq ($(UNAME_S),Darwin)
	DYLIBFLAGS=-dynamiclib -undefined suppress -flat_namespace
endif

all: $(SOURCES) $(SHA3LIB)

$(SHA3LIB): $(OBJECTS)
ifeq ($(UNAME_S),Darwin)
	$(CC) $^ -o $@ $(LDFLAGS) $(DYLIBFLAGS)
else
	ar rcs $@ $^
endif

#.c.o: 
#	    $(CC) -c $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm *.o 2>/dev/null || true
	rm $(SHA3LIB) 2>/dev/null || true
