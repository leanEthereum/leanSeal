leanseal-metal: main.swift
	swiftc -O main.swift -o leanseal-metal

verify: leanseal-metal
	./leanseal-metal verify

clean:
	rm -f leanseal-metal

.PHONY: verify clean
