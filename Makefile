
CC=gcc
WARNING_FLAGS=-Wall -Wextra -Wpedantic -Werror
CFLAGS= -O2 -march=native $(WARNING_FLAGS) -std=gnu99 -D__LINUX__ -D__X64__ -I./sha3
CFLAGS_DEBUG= -g -march=native $(WARNING_FLAGS) -std=gnu99 -fsanitize=address -D__LINUX__ -D__X64__ -I./sha3
SHA3LIB=libshake.a
SHA3_PATH=sha3
LDFLAGS= $(SHA3_PATH)/$(SHA3LIB) 

SOURCES= picnic_impl.c picnic.c lowmc_constants.c
PICNIC_OBJECTS= picnic_impl.o picnic.o lowmc_constants.o hash.o picnic_types.o
PICNIC_LIB= libpicnic.a
EXECUTABLE_EXAMPLE=example
EXECUTABLE_TESTVECTORS=create_test_vectors
EXECUTABLE_UNITTEST=unit_test
EXECUTABLE_BENCHMARK=bench

all: $(SHA3LIB) $(SOURCES) $(PICNIC_LIB) $(EXECUTABLE_EXAMPLE) $(EXECUTABLE_TESTVECTORS) $(EXECUTABLE_UNITTEST)

$(SHA3LIB):
		$(MAKE) -C $(SHA3_PATH) 

# debug build
debug: CFLAGS = $(CFLAGS_DEBUG)
debug: all

$(EXECUTABLE_EXAMPLE): $(PICNIC_LIB)
	    $(CC) $(@).c $(CFLAGS) $(PICNIC_LIB) -o $@ $(LDFLAGS)

$(EXECUTABLE_UNITTEST): $(PICNIC_LIB)
	    $(CC) $(@).c $(CFLAGS) $(PICNIC_LIB) -o $@ $(LDFLAGS)

$(EXECUTABLE_TESTVECTORS): $(PICNIC_LIB)
	    $(CC) $(@).c $(CFLAGS) $(PICNIC_LIB) -o $@ $(LDFLAGS)

$(EXECUTABLE_BENCHMARK): $(PICNIC_LIB)
	    $(CC) $(@).c $(CFLAGS) $(PICNIC_LIB) -o $@ $(LDFLAGS)


.c.o: 
	    $(CC) -c $(CFLAGS) $< -o $@

$(PICNIC_LIB): $(PICNIC_OBJECTS)
	ar rcs $@ $^


clean:
	    rm *.o 2>/dev/null || true
	    rm *.exe 2>/dev/null || true
	    rm $(EXECUTABLE_TESTVECTORS) 2>/dev/null || true
	    rm $(EXECUTABLE_EXAMPLE) 2>/dev/null || true
	    rm $(EXECUTABLE_UNITTEST) 2>/dev/null || true
	    rm $(EXECUTABLE_TESTVECTORS) 2>/dev/null || true
	    rm $(EXECUTABLE_BENCHMARK) 2>/dev/null || true
		rm $(PICNIC_LIB) 2>/dev/null || true
		$(MAKE) -C $(SHA3_PATH) clean
