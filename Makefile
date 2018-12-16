obj-m += tufilter.o

_VER := $(shell uname -r)
_KDIR ?= /lib/modules/$(_VER)/build

_PROG := user
_CC := gcc
_CFLAGS := -std=c99 -Wall -Wextra -Werror -pedantic -O2

all:
	$(MAKE) -C $(_KDIR) M=$(PWD) modules
	$(_CC) $(_CFLAGS) $(_PROG).c -o $(_PROG)

load:
	sudo insmod ./tufilter.ko

unload:
	sudo rmmod tufilter

clean:
	$(MAKE) -C $(_KDIR) M=$(PWD) clean
	rm -f $(_PROG)
