chainseal-metal: main.swift
	swiftc -O main.swift -o chainseal-metal

verify: chainseal-metal
	./chainseal-metal verify

clean:
	rm -f chainseal-metal

.PHONY: verify clean
