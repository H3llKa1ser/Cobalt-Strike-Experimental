#include <windows.h>

/* data API */
typedef struct {
    char* original;
    char* buffer;
    int   length;
    int   size;
} datap;

DECLSPEC_IMPORT void   BeaconDataParse(datap* parser, char* buffer, int size);
DECLSPEC_IMPORT char*  BeaconDataExtract(datap* parser, int* size);
DECLSPEC_IMPORT int    BeaconDataInt(datap* parser);
DECLSPEC_IMPORT short  BeaconDataShort(datap* parser);
DECLSPEC_IMPORT int    BeaconDataLength(datap* parser);

/* output API */
#define CALLBACK_OUTPUT 0x0
#define CALLBACK_ERROR  0x0d
DECLSPEC_IMPORT void   BeaconOutput(int type, char* data, int len);
DECLSPEC_IMPORT void   BeaconPrintf(int type, char* fmt, ...);
