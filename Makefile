CARGO ?= cargo
CHAINSEAL = target/release/chainseal

all:
	$(CARGO) build --release

test: all
	$(CARGO) test --release
	$(CHAINSEAL) selftest
	$(CHAINSEAL) vectors > tests/vectors.tmp && cmp tests/vectors.tmp tests/vectors.json && rm tests/vectors.tmp
	sh tests/cli.sh $(CHAINSEAL)
	python3 ref/chainseal_ref.py check tests/vectors.json
	sh tests/cross.sh $(CHAINSEAL)
	@echo "all tests passed"

bench: all
	$(CHAINSEAL) bench all

vectors: all
	$(CHAINSEAL) vectors > tests/vectors.json

clean:
	$(CARGO) clean

.PHONY: all test bench vectors clean
