/*
 * pam_geoip.c - account module to check GeoIP information
 *
 * $Id$
 *
 */

#define _GNU_SOURCE 
#define _BSD_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/socket.h>
#include <syslog.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <math.h>

#include <GeoIP.h>
#include <GeoIPCity.h>

#define LINE_LENGTH 4095

#define MASK_NO_MASK  -1
#define MASK_TOO_LONG -2
#define MASK_NOT_NUM  -3
#define MASK_TOO_BIG  -4

#include <security/pam_modutil.h> /* pam_modutil_user_in_group_nam_nam() */
#include <security/pam_ext.h>     /* pam_syslog() */
#include <security/pam_appl.h>
#define PAM_SM_ACCOUNT
#include <security/pam_modules.h>

#ifndef PATH_MAX
# define PATH_MAX 1024
#endif /* PATH_MAX */

/* GeoIP locations in geoip.conf */
struct locations {
    char *country;
    char *city;
    float latitude;
    float longitude;
    float radius;     /* in km */
    struct locations *next;
};

/* options set on "command line" in /etc/pam.d/ */
struct options {
    char *system_file;
    char *geoip_db;
    int  charset;
    int  debug;
};

struct locations *
parse_locations(pam_handle_t *pamh, 
                struct options *opts, 
                char *location_string)
{
    struct locations *entry  = NULL;
    struct locations *walker = NULL;
    struct locations *list   = NULL;
    char *single, *end, *next;
    char *country, *city;
    char *string = strdup(location_string);
    float latitude;
    float longitude;
    float radius;

    single = string;
    while (*single) {
        if (isspace(*single)) {
            single++;
            continue;
        }

        country = NULL;
        city    = NULL;
        end     = single;

        while (*end && *end != ';')
            end++;

        if (*end)
            next = end + 1;
        else
            next = end;

        *end = '\0';
        end--;
        while (isspace(*end)) {
            *end = '\0';
            end--;
        }

        if (strlen(single) == 0) {
            single = next;
            continue;
        }
        
        if (sscanf(single, "%f { %f , %f }", &radius, &latitude, &longitude) 
            == 3)
        {
            if (fabsf(latitude) > 90.0 || fabsf(longitude) > 180.0) {
                pam_syslog(pamh, LOG_WARNING, 
                        "illegal value(s) in LAT/LONG: %f, %f", 
                        latitude, longitude);
                single = next;
                continue;
            }
        }
        else {
            country = single;
            while (*single && *single != ',')
                single++;

            /* single is now at the end of country */
            if (*single)
                city = single + 1;
            else
                city = "*";

            *single = '\0';
            single--;
            while (isspace(*single)) {
                *single = '\0';
                single--;
            }
            if (strlen(country) == 0)
                country = "*";

            while (isspace(*city))
                city++;
            if (strlen(city) == 0)
                city = "*";
        }
        single = next;

        entry = malloc(sizeof(struct locations));
        if (entry == NULL) {
            pam_syslog(pamh, LOG_CRIT, "failed to malloc: %m");
            return NULL;
        }
        entry->next    = NULL;

        if (country == NULL) {
            entry->radius    = radius;
            entry->longitude = longitude;
            entry->latitude  = latitude;
            entry->country   = NULL;
            entry->city      = NULL;
        }
        else {
            entry->country = strdup(country);
            if (entry->country == NULL) {
                pam_syslog(pamh, LOG_CRIT, "failed to malloc: %m");
                free(entry);
                return NULL;
            }

            entry->city = strdup(city);  
            if (entry->city == NULL) {
                pam_syslog(pamh, LOG_CRIT, "failed to malloc: %m");
                free(entry);
                return NULL;
            }
        }

        if (list == NULL)
            list = entry;
        else {
            walker = list;
            while (walker->next)
                walker = walker->next;
            walker->next = entry;
        }
    }
    if (string)
        free(string); /* strdup'd */
    return list;
}

void 
free_locations(struct locations *list) {
    struct locations *entry;
    while (list) {
        entry = list;
        list  = list->next;
        if (entry->city != NULL)
            free(entry->city);
        if (entry->country != NULL)
            free(entry->country);
        free(entry);
    }
}

void 
free_opts(struct options *opts) {
    free(opts->system_file);
    free(opts->geoip_db);
    free(opts);
}

int 
parse_line(pam_handle_t *pamh, 
           char *line, 
           char *domain, 
           char *service, 
           char *location) 
{
    char *str;
    char action[LINE_LENGTH+1];
    int  act;

    if (sscanf(line, "%s %s %s %[^\n]", domain, service, action, location) != 4)
    {
        pam_syslog(pamh, LOG_WARNING, "invalid line '%s' - skipped", line);
        return -1;
    }

    if (strcmp(action, "deny") == 0)
        act = PAM_PERM_DENIED;
    else if (strcmp(action, "allow") == 0)
        act = PAM_SUCCESS;
    else if (strcmp(action, "ignore") == 0)
        act = PAM_IGNORE; 
    else {
        pam_syslog(pamh, LOG_WARNING, "invalid action '%s' - skipped", action);
        return -1;
    }

    /* remove white space from the end */
    str = location + strlen(location) - 1;
    while (isspace(*str)) {
            *str = '\0';
            str--;
    }
    
    return act;
}

int check_service(pam_handle_t *pamh, char *services, char *srv) {
    char *str, *next;

    if (strcmp(services, "*") == 0)
        return 1;

    str = services;
    while (*services) {
        while (*str && *str != ',')
            str++;

        if (*str) 
            next = str + 1;
        else 
            next = "";

        *str = '\0';
        if (   (strncmp(services, srv, strlen(services)) == 0)
            || (strcmp(services, "*") == 0))
        {
            return 1;
        }

        services = next;
    }
    return 0;
}

double /* see also: http://en.wikipedia.org/wiki/Great-circle_distance */
calc_distance(float latitude, float longitude, float geo_lat, float geo_long) {
    double distance;
    float earth = 6367.46; /* km avg radius */
    /* convert grad to rad: */
    double la1 = latitude  * M_PI / 180.0,
           la2 = geo_lat   * M_PI / 180.0,
           lo1 = longitude * M_PI / 180.0,
           lo2 = geo_long  * M_PI / 180.0;

    distance = atan2(
            sqrt(
                pow(
                    cos(la2) * sin(lo1-lo2),
                    2.0
                )
                    +
                pow(
                    cos(la1) * sin(la2) - sin(la1) * cos(la2) * cos(lo1-lo2),
                    2.0
                )
            ),
            sin(la1) * sin(la2) + cos(la1) * cos(la2) * cos(lo1-lo2)
        );
    if (distance < 0.0)
        distance += 2 * M_PI;
    distance *= earth;
    return distance;
}


int 
check_location(pam_handle_t *pamh, 
               struct options *opts,
               char *location_string, 
               struct locations *geo)
{
    struct locations *list;
    struct locations *loc;
    double distance;
 
    list = loc = parse_locations(pamh, opts, location_string);

    while (list) {
        if (list->country == NULL) {
            if (strcmp(geo->country, "UNKNOWN") == 0) {
                list = list->next;
                continue;
            }

            distance = calc_distance(list->latitude, list->longitude, 
                                      geo->latitude, geo->longitude);
            if (distance <= list->radius) {
                pam_syslog(pamh, LOG_INFO, "distance(%.3f) < radius(%3.f)", 
                                                    distance, list->radius);
                free_locations(loc);
                return 1;
            } 
        }
        else {
            if (opts->debug) 
                pam_syslog(pamh, LOG_INFO, "location: (%s,%s) geoip: (%s,%s)", 
                            list->country, list->city, geo->country, geo->city);

            if ( 
                (list->country[0] == '*' || 
                 strcmp(list->country, geo->country) == 0) 
                    && 
                (list->city[0]    == '*' || 
                 strcmp(list->city,    geo->city   ) == 0)
            ) 
            {
                pam_syslog(pamh, LOG_INFO, "location matched: %s,%s", 
                                                    list->country, list->city);
                free_locations(loc);
                return 1;
            }
        }
        list = list->next;
    }
    if (loc) /* may be NULL */
         free_locations(loc);
    return 0;
}



void _parse_args(pam_handle_t *pamh,
                 int argc,
                 const char **argv,
                 struct options *opts)
{
    int i = 0;

    for (i=0; i<argc; i++) {
        if (strncmp(argv[i], "system_file=", 12) == 0) {
            if (argv[i]+12 != '\0') 
                opts->system_file = strndup(argv[i]+12, PATH_MAX);
        }
        else if (strncmp(argv[i], "geoip_db=", 9) == 0) {
            if (argv[i]+9 != '\0') 
                opts->geoip_db = strndup(argv[i]+9, PATH_MAX);
        }
        else if (strncmp(argv[i], "charset=", 8) == 0) {
            if (argv[i]+8 != '\0') {
                if (strncasecmp(argv[i]+8, "UTF-8", 5) == 0) {
                    opts->charset = GEOIP_CHARSET_UTF8;
                }
                else if (strncasecmp(argv[i]+8, "UTF8", 4) == 0) {
                    opts->charset = GEOIP_CHARSET_UTF8;
                }
                else if (strncasecmp(argv[i]+8, "iso-8859-1", 10) == 0) {
                    opts->charset = GEOIP_CHARSET_ISO_8859_1;
                }
            }
        }
        else if (strncmp(argv[i], "debug", 5) == 0) {
            opts->debug = 1;
        }
        else {
            pam_syslog(pamh, LOG_WARNING, "unknown parameter %s", argv[i]);
        }
    }
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, 
                int flags,
                int argc, 
                const char **argv)
{
    struct options *opts;
    FILE *fh;
    char *username;        /* username requesting access */
    char *rhost;           /* remote host */
    char *srv;             /* PAM service we're running as */
    char buf[LINE_LENGTH];
    int retval, action;
    struct locations *geo;

    GeoIP       *gi  = NULL;
    GeoIPRecord *rec = NULL;

    opts = malloc(sizeof(struct options));
    if (opts == NULL) {
        pam_syslog(pamh, LOG_CRIT, "malloc error 'opts': %m");
        return PAM_SERVICE_ERR;
    }
    opts->charset     = GEOIP_CHARSET_UTF8;
    opts->debug       = 0;
    opts->system_file = NULL; 
    opts->geoip_db    = NULL; 

    geo = malloc(sizeof(struct locations));
    if (geo == NULL) {
        pam_syslog(pamh, LOG_CRIT, "malloc error 'geo': %m");
        free_opts(opts);
        return PAM_SERVICE_ERR;
    }
    geo->country = NULL;
    geo->city    = NULL;
    geo->next    = NULL;

    _parse_args(pamh, argc, argv, opts);

    if (opts->system_file == NULL)
        opts->system_file = strdup("/etc/security/geoip.conf");/* TODO: strdup->malloc */
    if (opts->geoip_db == NULL)
        opts->geoip_db = strdup("/usr/local/share/GeoIP/GeoIPCity.dat");/* TODO: strdup->malloc */

    retval = pam_get_item(pamh, PAM_USER, (void*) &username);    
    if (username == NULL || retval != PAM_SUCCESS) {     
        pam_syslog(pamh, LOG_CRIT, "error recovering username");
        free_opts(opts);
        free_locations(geo);
        return PAM_SERVICE_ERR;
    }

    retval = pam_get_item(pamh, PAM_RHOST, (void*) &rhost);    
    if (retval != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_CRIT, "error fetching rhost");
        free_opts(opts);
        free_locations(geo);
        return PAM_SERVICE_ERR;
    }
    if (rhost == NULL) {
        pam_syslog(pamh, LOG_INFO, "rhost is NULL, allowing");
        free_opts(opts);
        free_locations(geo);
        return PAM_SUCCESS;
    }

    retval = pam_get_item(pamh, PAM_SERVICE, (void*) &srv);    
    if (srv == NULL || retval != PAM_SUCCESS ) {     
        pam_syslog(pamh, LOG_CRIT, "error requesting service name");
        free_opts(opts);
        return 0;
    }

    gi = GeoIP_open(opts->geoip_db, GEOIP_INDEX_CACHE);
    if (gi == NULL) {
        pam_syslog(pamh, LOG_CRIT, 
                        "failed to open geoip db (%s): %m", opts->geoip_db);
        free_opts(opts);
        free_locations(geo);
        return PAM_SERVICE_ERR;
    }
    GeoIP_set_charset(gi, opts->charset);

    /* TODO: also check IPv6 */
    rec = GeoIP_record_by_name(gi, rhost); 
    if (rec == NULL) {
        pam_syslog(pamh, LOG_INFO, "no record for %s, setting GeoIP to 'UNKNOWN,*'", rhost);

        geo->city    = strdup("*");/* TODO: strdup->malloc */
        geo->country = strdup("UNKNOWN");/* TODO: strdup->malloc */
    } 
    else {
        if (rec->city == NULL) {
            geo->city = strdup("*");/* TODO: strdup->malloc */
        }
        else geo->city = strdup(rec->city);/* TODO: strdup->malloc */ 

        if (rec->country_code == NULL)
            geo->country = strdup("UNKNOWN");/* TODO: strdup->malloc */
        else
            geo->country = strdup(rec->country_code);/* TODO: strdup->malloc */

        geo->latitude  = rec->latitude;
        geo->longitude = rec->longitude;
    }

    if (opts->debug)
        pam_syslog(pamh, LOG_DEBUG, "GeoIP record for %s: %s,%s", 
                                rhost, geo->country, geo->city);

    if (opts->debug && strcmp(geo->country, "UNKNOWN") != 0)
        pam_syslog(pamh, LOG_DEBUG, "GeoIP coordinates for %s: %f,%f", 
                                    rhost, geo->latitude, geo->longitude);

    if ((fh = fopen(opts->system_file, "r")) == NULL) {
        pam_syslog(pamh, LOG_CRIT, "error opening %s: %m", opts->system_file);
        if (gi) GeoIP_delete(gi);
        if (rec) GeoIPRecord_delete(rec);
        free_opts(opts);
        return PAM_SERVICE_ERR;
    }

    action = PAM_PERM_DENIED; /* TODO: set default via argv */
    while (fgets(buf, LINE_LENGTH, fh) != NULL) {
        char *line, *ptr;
        char domain[LINE_LENGTH], 
             service[LINE_LENGTH], 
             location[LINE_LENGTH];
        
        action = PAM_PERM_DENIED;/* TODO: set default via argv */
        line   = buf;
        /* skip the leading white space */
        while (*line && isspace(*line))
            line++;

        /* Rip off the comments */
        ptr = strchr(line,'#');
        if (ptr)
            *ptr = '\0';
        /* Rip off the newline char */
        ptr = strchr(line,'\n');
        if (ptr)
            *ptr = '\0';
        /* Anything left ? */
        if (!strlen(line))
            continue;

        action = parse_line(pamh, line, domain, service, location);
        if (action < 0) { /* parsing failed */ 
            action = PAM_PERM_DENIED;/* TODO: set default via argv */
            continue;
        }

        if (!check_service(pamh, service, srv))
            continue;
         
        if ((strcmp(domain, "*") == 0) || (strcmp(username, domain) == 0)) {
            if (check_location(pamh, opts, location, geo))
                break;
        }
        else if (domain[0] == '@') {
            if (pam_modutil_user_in_group_nam_nam(pamh, username, domain+1)) {
                if (check_location(pamh, opts, location, geo)) 
                    break;
            }
        }
    }    

    fclose(fh);
    if (gi) GeoIP_delete(gi);
    if (rec) GeoIPRecord_delete(rec);
    free_locations(geo);

    if (opts->debug) {
        switch (action) {
            case PAM_SUCCESS:
                pam_syslog(pamh, LOG_DEBUG, "location allowed");
                break;
            case PAM_PERM_DENIED:
                pam_syslog(pamh, LOG_DEBUG, "location denied");
                break;
            case PAM_IGNORE:
                pam_syslog(pamh, LOG_DEBUG, "location ignored");
                break;
            default: /* should not happen */
                pam_syslog(pamh, LOG_DEBUG, "location status: %d", action);
                break;
        };
    }
    free_opts(opts);
    return action;
}

/* 
 * vim: ts=4 sw=4 expandtab
 */
