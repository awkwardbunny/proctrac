obj-m+=ptrac.o

CFLAGS_ptrac.o := -DDEBUG

all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean

insert: ptrac.ko
	sudo insmod ptrac.ko
remove: ptrac.ko
	sudo rmmod ptrac.ko
