#!/bin/sh

echo "#include <GeoIP.h>
int main () { int have = GEOIP_CITY_EDITION_REV1_V6; }" > version.c
gcc -lGeoIP version.c -shared -o version 2> /dev/null
if [ $? -eq 0 ]; then
	echo "#define HAVE_GEOIP_010408" > pam_geoip.h
else
	cat > pam_geoip.h <<_END
#ifdef HAVE_GEOIP_010408
#undef HAVE_GEOIP_010408
#endif
_END
fi
rm -f version.c version
