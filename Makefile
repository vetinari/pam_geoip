
POD2MAN=pod2man -u -c 'Linux-PAM Manual' -r 'Linux-PAM Manual'
MANPAGES=geoip.conf.5 pam_geoip.8
MAN_5_POD=geoip.conf.5.pod
MAN_8_POD=pam_geoip.8.pod

C_FILES=pam_geoip.c
OBJECTS=pam_geoip.o
MODULE=pam_geoip.so
LDFLAGS=-lpam -lGeoIP -lm -shared
CCFLAGS=-Wall
PAM_LIB_DIR=$(DESTDIR)/lib/security
INSTALL=/usr/bin/install

all: module doc

module: $(MODULE)

doc: $(MANPAGES_POD) $(MANPAGES) 

%.5: $(MAN_5_POD)
	$(POD2MAN) -u -s 5 $@.pod > $@
%.8: $(MAN_8_POD)
	$(POD2MAN) -u -s 8 $@.pod > $@

pam_geoip.o: $(C_FILES)
	$(CC) $(CCFLAGS) -fPIC -c $*.c

pam_geoip.so: pam_geoip.o
	$(CC) $(CCFLAGS) $(LDFLAGS) -o $@ pam_geoip.o

clean:
	rm -f $(MANPAGES)
	rm -f $(OBJECTS) $(MODULE) core *~

install: $(MODULE)
	$(INSTALL) -m 0755 -d $(PAM_LIB_DIR)
	$(INSTALL) -m 0644 $(MODULE) $(PAM_LIB_DIR)
### dev targets:
update:
	svn update
# END