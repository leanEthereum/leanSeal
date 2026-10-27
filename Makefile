CARGO ?= cargo
LEANSEAL = target/release/leanseal

all:
	$(CARGO) build --release

test: all
	$(CARGO) test --release
	$(LEANSEAL) selftest
	$(LEANSEAL) vectors > tests/vectors.tmp && cmp tests/vectors.tmp tests/vectors.json && rm tests/vectors.tmp
	sh tests/cli.sh $(LEANSEAL)
	python3 ref/leanseal_ref.py check tests/vectors.json
	sh tests/cross.sh $(LEANSEAL)
	@echo "all tests passed"

bench: all
	$(LEANSEAL) bench all

vectors: all
	$(LEANSEAL) vectors > tests/vectors.json

clean:
	$(CARGO) clean

.PHONY: all test bench vectors clean
