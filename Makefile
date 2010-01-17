
POD2MAN=pod2man -u -c 'Linux-PAM Manual' -r 'Linux-PAM Manual'
MANPAGES=geoip.conf.5 pam_geoip.8

OBJECTS=pam_geoip.o
MODULE=pam_geoip.so
LDFLAGS=-lpam -lGeoIP -lm
CC=gcc -Wall

all: module doc

module: pam_geoip.so

doc: $(MANPAGES)

%.5:
	$(POD2MAN) -u -s 5 $@.pod > $@
%.8:
	$(POD2MAN) -u -s 8 $@.pod > $@

pam_geoip.o:
	$(CC) -fPIC -c $*.c

pam_geoip.so: pam_geoip.o
	$(CC) $(LDFLAGS) -shared -o $@ pam_geoip.o

clean:
	rm -f $(MANPAGES)
	rm -f *.o
	rm -f *.so

### dev targets:
update:
	svn update
# END
