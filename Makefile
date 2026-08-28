PREFIX ?= /usr/local
BIN := $(PREFIX)/bin/lanmoon

install:
	cp lanmoon.py $(BIN)
	chmod 755 $(BIN)
	@echo "installed: $(BIN)"
	@echo "run with:  sudo lanmoon   (or just: lanmoon)"

uninstall:
	rm -f $(BIN)
	@echo "removed: $(BIN)"

.PHONY: install uninstall
