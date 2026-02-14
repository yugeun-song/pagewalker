.PHONY: all clean tags cscope user kernel bin_dir

all: bin_dir kernel user tags cscope

bin_dir:
	mkdir -p bin/kernel
	mkdir -p bin/user

kernel:
	$(MAKE) -C kernel

user:
	$(MAKE) -C user

tags:
	ctags -R .

cscope:
	find . -name "*.[ch]" > cscope.files
	cscope -b -q -i cscope.files

clean:
	$(MAKE) -C kernel clean
	$(MAKE) -C user clean
	rm -rf bin/
	rm -f tags cscope.out cscope.in.out cscope.po.out cscope.files
