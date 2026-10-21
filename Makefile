CC      ?= cc
CFLAGS  ?= -O3
CFLAGS  += -std=gnu11 -Wall -Wextra -Wshadow -Wno-unused-parameter
LDLIBS  += -lpthread -lm
# Apple's compiler targets the SHA-256 instructions by default; on Linux the
# ARMv8 backend needs them enabled. The tool still checks the CPU at run time.
# ARCH stays separate from CFLAGS so that the sanitizer builds keep it.
ARCH    :=
ifeq ($(shell uname -s)-$(shell uname -m),Linux-aarch64)
ARCH    := -march=armv8-a+crypto
endif

LIB  = src/sha256.c src/chain.c src/rng.c src/chainseal.c
TOOL = src/cli.c src/util.c src/bench.c src/vectors.c
HDRS = $(wildcard src/*.h)

all: chainseal

chainseal: $(LIB) $(TOOL) $(HDRS)
	$(CC) $(ARCH) $(CFLAGS) -o $@ $(LIB) $(TOOL) $(LDLIBS)

tests/test: tests/test.c $(LIB) $(HDRS)
	$(CC) $(ARCH) $(CFLAGS) -Isrc -o $@ tests/test.c $(LIB) $(LDLIBS)

# The SHA-NI step logic, with the intrinsics emulated: runs on any machine.
tests/shani_emu: tests/shani_emu.c src/chain_shani.h src/sha256.c src/chain.c src/rng.c $(HDRS)
	$(CC) $(ARCH) $(CFLAGS) -Wno-unused-function -Isrc -o $@ tests/shani_emu.c src/sha256.c src/chain.c src/rng.c $(LDLIBS)

# Unit tests, the CLI round trip, and the vectors regression.
test: chainseal tests/test tests/shani_emu
	./tests/test
	./tests/shani_emu
	./chainseal selftest
	./chainseal vectors > tests/vectors.tmp && cmp tests/vectors.tmp tests/vectors.json && rm tests/vectors.tmp
	sh tests/cli.sh ./chainseal
	python3 ref/chainseal_ref.py check tests/vectors.json
	sh tests/cross.sh ./chainseal
	@echo "all tests passed"

# The same under AddressSanitizer and UndefinedBehaviorSanitizer.
sanitize:
	$(MAKE) clean
	$(MAKE) test CFLAGS="-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all"
	$(MAKE) clean

# The threaded paths (building, parallel solving) under ThreadSanitizer.
tsan:
	$(MAKE) clean
	$(MAKE) chainseal tests/test CFLAGS="-O1 -g -fsanitize=thread"
	TSAN_OPTIONS=halt_on_error=1 ./tests/test 2000
	TSAN_OPTIONS=halt_on_error=1 sh tests/cli.sh ./chainseal
	$(MAKE) clean

vectors: chainseal
	./chainseal vectors > tests/vectors.json

bench: chainseal
	./chainseal bench all

clean:
	rm -f chainseal tests/test tests/shani_emu
	rm -rf *.dSYM tests/*.dSYM

.PHONY: all test sanitize tsan vectors bench clean
