#!/bin/sh

TEMP_SRC=$( tempfile -s .c )
TEMP_OUT=$( tempfile )

cat > $TEMP_SRC <<_END
#include <GeoIP.h>
int main () {
    int have = GEOIP_CITY_EDITION_REV1_V6;
}
_END

gcc -lGeoIP $TEMP_SRC -shared -o $TEMP_OUT 2> /dev/null
if [ $? -eq 0 ]; then
    rm -f pam_geoip.h
    echo "#define HAVE_GEOIP_010408" > pam_geoip.h
else
    rm -f pam_geoip.h
    cat > pam_geoip.h <<_END
#ifdef HAVE_GEOIP_010408
#undef HAVE_GEOIP_010408
#endif
_END
fi
rm -f $TEMP_SRC $TEMP_OUT
