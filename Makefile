.PHONY: all clean tags cscope user kernel

all: kernel user tags cscope

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
