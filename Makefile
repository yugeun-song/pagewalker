all:
	mkdir -p bin/kernel
	mkdir -p bin/user
	$(MAKE) -C kernel
	$(MAKE) -C user

clean:
	$(MAKE) -C kernel clean
	$(MAKE) -C user clean
	rm -rf bin/
