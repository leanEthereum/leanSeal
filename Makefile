CC      ?= cc
CFLAGS  ?= -O3
CFLAGS  += -std=gnu11 -Wall -Wextra -Wshadow -Wno-unused-parameter
LDLIBS  += -lpthread -lm

LIB  = src/sha256.c src/chain.c src/rng.c src/chainseal.c
TOOL = src/cli.c src/util.c src/bench.c src/vectors.c
HDRS = $(wildcard src/*.h)

all: chainseal

chainseal: $(LIB) $(TOOL) $(HDRS)
	$(CC) $(CFLAGS) -o $@ $(LIB) $(TOOL) $(LDLIBS)

tests/test: tests/test.c $(LIB) $(HDRS)
	$(CC) $(CFLAGS) -Isrc -o $@ tests/test.c $(LIB) $(LDLIBS)

# Unit tests, the CLI round trip, and the vectors regression.
test: chainseal tests/test
	./tests/test
	./chainseal selftest
	./chainseal vectors | cmp - tests/vectors.json
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
	rm -f chainseal tests/test
	rm -rf *.dSYM tests/*.dSYM

.PHONY: all test sanitize tsan vectors bench clean
