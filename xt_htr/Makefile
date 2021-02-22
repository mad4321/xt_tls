obj-m += xt_HTR.o
xt_tls-objs := xt_HTR.o
KERNEL_VERSION := $(shell uname -r)
IDIR := /lib/modules/$(KERNEL_VERSION)/kernel/net/netfilter/
KDIR := /lib/modules/$(KERNEL_VERSION)/build
DESTDIR ?= /
PWD := $(shell pwd)
VERSION := $(shell git rev-parse HEAD 2>/dev/null)

default:
	    $(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

install:
	    $(MAKE) -C $(KDIR) SUBDIRS=$(PWD) INSTALL_MOD_PATH=$(DESTDIR) modules_install
	    depmod -a

clean:
	    rm -rf Module.markers modules.order Module.symvers \
	           *.ko *.mod.c *.mod.o *.o .*.o.cmd .*.ko.cmd .cache.mk \
	           .tmp_versions

dkms-install:
	. ./dkms.conf; \
		mkdir /usr/src/$${PACKAGE_NAME}-$${PACKAGE_VERSION}; \
		cp -r * /usr/src/$${PACKAGE_NAME}-$${PACKAGE_VERSION}; \
		dkms add -m $${PACKAGE_NAME} -v $${PACKAGE_VERSION}; \
		dkms build -m $${PACKAGE_NAME} -v $${PACKAGE_VERSION}; \
		dkms install -m $${PACKAGE_NAME} -v $${PACKAGE_VERSION}
dkms-uninstall:
	. ./dkms.conf; \
		dkms uninstall -m $${PACKAGE_NAME} -v $${PACKAGE_VERSION}; \
		dkms remove -m $${PACKAGE_NAME} -v $${PACKAGE_VERSION} --all; \
		rm -rf /usr/src/$${PACKAGE_NAME}-$${PACKAGE_VERSION}
