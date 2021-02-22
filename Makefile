DESTDIR ?= /
DESTDIR_TMP := $(shell readlink -f $(DESTDIR))
SHELL = bash

all:
	$(MAKE) -C ipt
	$(MAKE) -C src
	$(MAKE) -C xt_htr
debug:
	$(MAKE) -C ipt
	$(MAKE) -C src debug
	$(MAKE) -C xt_htr
install:
	$(MAKE) -C ipt DESTDIR=$(DESTDIR_TMP) install
	$(MAKE) -C src DESTDIR=$(DESTDIR_TMP) install
	$(MAKE) -C xt_htr DESTDIR=$(DESTDIR_TMP) install
clean:
	$(MAKE) -C src clean
	$(MAKE) -C ipt clean
	$(MAKE) -C xt_htr clean
dkms-install:
	. ./dkms.conf; \
		mkdir /usr/src/$${PACKAGE_NAME}-$${PACKAGE_VERSION}; \
		cp -r * /usr/src/$${PACKAGE_NAME}-$${PACKAGE_VERSION}; \
		dkms add -m $${PACKAGE_NAME} -v $${PACKAGE_VERSION}; \
		dkms build -m $${PACKAGE_NAME} -v $${PACKAGE_VERSION}; \
		dkms install -m $${PACKAGE_NAME} -v $${PACKAGE_VERSION}
	$(MAKE) -C xt_htr
	$(MAKE) -C xt_htr dkms-install
dkms-uninstall:
	. ./dkms.conf; \
		dkms uninstall -m $${PACKAGE_NAME} -v $${PACKAGE_VERSION}; \
		dkms remove -m $${PACKAGE_NAME} -v $${PACKAGE_VERSION} --all; \
		rm -rf /usr/src/$${PACKAGE_NAME}-$${PACKAGE_VERSION}
	$(MAKE) -C xt_htr dkms-uninstall
