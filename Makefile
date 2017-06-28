
CC=gcc
WARNING_FLAGS=-Wall -Wextra -Wpedantic -Werror
CFLAGS= -O2 -march=native $(WARNING_FLAGS) -std=gnu99 -D__LINUX__ -D__X64__
CFLAGS_DEBUG= -g -march=native $(WARNING_FLAGS) -std=gnu99 -fsanitize=address -D__LINUX__ -D__X64__
LDFLAGS= -lcrypto

SOURCES= LowMC.c test_util.c benchmark_lowmc.c picnic.c LowMCEnc.c
OBJECTS_BENCHMARK= LowMC.o LowMCEnc.o test_util.o picnic.o
OBJECTS_EXAMPLE= LowMC.o picnic.o LowMCEnc.o
EXECUTABLE_BENCHMARK=benchmark_lowmc
EXECUTABLE_EXAMPLE=example

all: $(SOURCES) $(EXECUTABLE_BENCHMARK) $(EXECUTABLE_EXAMPLE)

# debug build
debug: CFLAGS = $(CFLAGS_DEBUG)
debug: all

# avx build
avx: CFLAGS += -DWITH_AVX -mavx2
avx: all

#avx debug build
avx-debug: CFLAGS = $(CFLAGS_DEBUG)
avx-debug: CFLAGS += -DWITH_AVX -mavx2
avx-debug: all

$(EXECUTABLE_BENCHMARK): $(OBJECTS_BENCHMARK)
	    $(CC) $(@).c $(CFLAGS) $(OBJECTS_BENCHMARK) -o $@ $(LDFLAGS)

$(EXECUTABLE_EXAMPLE): $(OBJECTS_EXAMPLE)
	    $(CC) $(@).c $(CFLAGS) $(OBJECTS_EXAMPLE) -o $@ $(LDFLAGS)

.c.o: 
	    $(CC) -c $(CFLAGS) $< -o $@ $(LDFLAGS)


# Build a utility that precomputes data for LowMC 
matrices: $(OBJECTS_EXAMPLE)
	$(CC) -g  preprocessMatrices.c -o preprocessMatrices $(OBJECTS_EXAMPLE) -I /usr/include/m4ri/ -std=c99 -lm4ri $(LDFLAGS)

docs:
	doxygen docs/doxygen.cfg

.PHONY: docs

clean:
	    rm *.o 2>/dev/null || true
	    rm *.exe 2>/dev/null || true
	    rm $(EXECUTABLE_BENCHMARK) 2>/dev/null || true
	    rm $(EXECUTABLE_EXAMPLE) 2>/dev/null || true

# Run the whitespace tool 
# Install with 'sudo apt-get install uncrustify'
# Make sure you have staged your changes, so that you can easily undo changes
# made by uncrustify if necessary
whitespace:
	    uncrustify -c uncrustify.cfg -F uncrustify-file-list.txt --no-backup --replace
	
