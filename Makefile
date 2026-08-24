.PHONY: all clean tags cscope user kernel

# The default build produces only the binaries (module + CLI). Build the source
# indexes explicitly with `make tags cscope`; `make clean` removes them regardless.
all: kernel user

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
	rm -f tags cscope.out cscope.in.out cscope.po.out cscope.files
