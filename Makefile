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
test:
	echo /etc/passwd 1 | sudo tee /sys/ptrac/filelist > /dev/null
	cat /sys/ptrac/filelist
	dmesg | tail

demo:
	make
	make insert
	echo /tmp/test_file 1 | sudo tee /sys/ptrac/filelist > /dev/null
	cat /sys/ptrac/filelist
	dmesg | tail
	touch /tmp/test_file
	chmod u+x /tmp/test_file
	-/tmp/file_list # doesnt work well in makefiles, but trying to execute files should show up
	echo blah > /tmp/test_file
	rm /tmp/test_file
	make remove
	dmesg | tail
