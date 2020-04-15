
CC=gcc
WARNING_FLAGS=-Wall -Wextra -Wpedantic -Werror -Wshadow
CFLAGS= -O2 -march=native $(WARNING_FLAGS) -std=gnu99 -D__LINUX__ -D__X64__ -I./sha3
CFLAGS_DEBUG= -g -march=native $(WARNING_FLAGS) -std=gnu99 -D__LINUX__ -D__X64__ -I./sha3
NISTKATFLAGS = -Wno-sign-compare -Wno-unused-but-set-variable -Wno-unused-parameter -Wno-unused-result
SHA3LIB=libshake.a
SHA3_PATH=sha3
LDFLAGS= $(SHA3_PATH)/$(SHA3LIB) 

SOURCES= picnic_impl.c picnic3_impl.c picnic.c lowmc_constants.c
PICNIC_OBJECTS= picnic_impl.o picnic3_impl.o picnic.o lowmc_constants.o hash.o picnic_types.o tree.o
PICNIC_LIB= libpicnic.a
EXECUTABLE_EXAMPLE=example
EXECUTABLE_TESTVECTORS=create_test_vectors
EXECUTABLE_UNITTEST=unit_test
EXECUTABLE_KATSTEST=kats_test
EXECUTABLE_TREETEST=tree_test

all: $(SHA3LIB) $(SOURCES) $(PICNIC_LIB) $(EXECUTABLE_EXAMPLE) $(EXECUTABLE_TESTVECTORS) $(EXECUTABLE_UNITTEST) $(EXECUTABLE_KATSTEST)  $(EXECUTABLE_TREETEST) 

$(SHA3LIB):
		$(MAKE) -C $(SHA3_PATH) 

# debug build
debug: CFLAGS = $(CFLAGS_DEBUG)
debug: all

$(EXECUTABLE_EXAMPLE): $(EXECUTABLE_EXAMPLE).c $(PICNIC_LIB)
	    $(CC) $(@).c $(CFLAGS) $(PICNIC_LIB) -o $@ $(LDFLAGS)

$(EXECUTABLE_UNITTEST): $(EXECUTABLE_UNITTEST).c $(PICNIC_LIB)
	    $(CC) $(@).c $(CFLAGS) $(PICNIC_LIB) -o $@ $(LDFLAGS)

$(EXECUTABLE_TREETEST): $(EXECUTABLE_TREETEST).c $(PICNIC_LIB)
	    $(CC) $(@).c $(CFLAGS) $(PICNIC_LIB) -o $@ $(LDFLAGS)

$(EXECUTABLE_TESTVECTORS): $(EXECUTABLE_TESTVECTORS).c $(PICNIC_LIB)
	    $(CC) $(@).c $(CFLAGS) $(PICNIC_LIB) -o $@ $(LDFLAGS)

$(EXECUTABLE_KATSTEST): $(EXECUTABLE_KATSTEST).c $(PICNIC_LIB)
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
	    rm $(EXECUTABLE_TREETEST) 2>/dev/null || true
	    rm $(EXECUTABLE_KATSTEST) 2>/dev/null || true
	    rm $(EXECUTABLE_TESTVECTORS) 2>/dev/null || true
		rm $(PICNIC_LIB) 2>/dev/null || true
		$(MAKE) -C $(SHA3_PATH) clean

