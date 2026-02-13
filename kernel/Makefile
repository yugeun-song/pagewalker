obj-m += pagewalk.o

# Detect kernel build path
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	cp pagewalk.ko ../bin/kernel/

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f ../bin/kernel/pagewalk.ko
