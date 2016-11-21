kernel ?= $(shell uname -r)
kdir ?= /lib/modules/$(kernel)/build

obj-m = ret2usr.o

all: ret2usr.ko ret2usr_cli

ret2usr.ko: ret2usr.c ret2usr.h
	$(MAKE) -C $(kdir) M=$$(pwd)

ret2usr_cli: ret2usr_cli.c ret2usr.h
	gcc -Wall $< -o $@

clean:
	rm -f ret2usr_cli *.o *.ko
