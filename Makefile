all: src/all

clean: src/clean

src/all:
	cd src && $(MAKE) all

src/clean:
	cd src && $(MAKE) clean
	cd testing && $(MAKE) clean

check:
	cd testing && $(MAKE) check
