// Spelfix bugfixing! Davilex had a horrid Q'n'A department, after all. Just kidding :p
// Written by Martin Turski. Use this for whatever.
#include "main.h"

static char* _temporaryBuffer = NULL;

template <typename dataType>
inline void MemPut( void *ptr, const dataType& data )
{
    // Enable writing access.
    DWORD oldProt;

    VirtualProtect( ptr, sizeof( dataType ), PAGE_READWRITE, &oldProt );

    *(dataType*)ptr = data;

    VirtualProtect( ptr, sizeof( dataType ), oldProt, &oldProt );
}

#define NUMELMS(a)	( sizeof(a) / sizeof(*a) )

static void OnInitialize( void )
{
    // Fix some stupid addresses.
    size_t bufSize = sizeof(char) * 65536;

    char *temporaryBuffer = (char*)malloc( bufSize );

    memset( temporaryBuffer, 0, bufSize );

    typedef void* memAddr_t;

    memAddr_t memAddrArray[] =
    {
        (void*)0x00403950,
        (void*)0x00405808,
        (void*)0x00405849,
        (void*)0x004058E4,
        (void*)0x0040C445,
        (void*)0x0040C462,
        (void*)0x0040C49A,
        (void*)0x00410CA4,
        (void*)0x00410CD8,
        (void*)0x0041141C,
        (void*)0x00411437,
        (void*)0x00411454,
        (void*)0x00411481,
        (void*)0x004114E9,
        (void*)0x00411504,
        (void*)0x00411521,
        (void*)0x0041154D,
        (void*)0x004115B3,
        (void*)0x004115CE,
        (void*)0x004115EB,
        (void*)0x0041161B,
        (void*)0x004116A8,
        (void*)0x004116C3,
        (void*)0x004116E0,
        (void*)0x00411714,
        (void*)0x0041179E,
        (void*)0x004117B9,
        (void*)0x004117D6,
        (void*)0x00411807,
        (void*)0x0041206D,
        (void*)0x00412088,
        (void*)0x004120C2,
        (void*)0x004143CA,
        (void*)0x004143EF,
        (void*)0x00414414,
        (void*)0x00414438,
        (void*)0x00414544,
        (void*)0x00414562,
        (void*)0x004145DB,
        (void*)0x004145E7,
        (void*)0x0041461D,
        (void*)0x00414651,
        (void*)0x0041466A,
        (void*)0x00414B1C,
        (void*)0x00414B36,
        (void*)0x00414B8E,
        (void*)0x004154A1,
        (void*)0x004154BC,
        (void*)0x004154EF,
        (void*)0x0041555A,
        (void*)0x00415575,
        (void*)0x004155A8,
        (void*)0x00415613,
        (void*)0x0041562E,
        (void*)0x00415661,
        (void*)0x00418C02,
        (void*)0x00418C5A,
        (void*)0x00418C73,
        (void*)0x0041B908,
        (void*)0x0041BB74,
        (void*)0x0041D4AF,
        (void*)0x0041D4D1,
        (void*)0x0041E095,
        (void*)0x0041E0B7,
        (void*)0x004279F7,
        (void*)0x00427AB9,
        (void*)0x00433292,
        (void*)0x004334AF,
        (void*)0x004334D1,
        (void*)0x0043350E,
        (void*)0x00433533,
        (void*)0x00433555,
        (void*)0x00433593,
        (void*)0x00436162,
        (void*)0x0044381E,
        (void*)0x00443B91,
        (void*)0x00443F01,
        (void*)0x00452AA5,
        (void*)0x00452B4F,
        (void*)0x00452D0A,
        (void*)0x00453793,
        (void*)0x0045384D,
        (void*)0x004538EF,
        (void*)0x0045390A,
        (void*)0x0045393D,
        (void*)0x004539F1,
        (void*)0x00453A0C,
        (void*)0x00453A40,
        (void*)0x00453AB8,
        (void*)0x00453AD2,
        (void*)0x00453DFA,
        (void*)0x0045410D,
        (void*)0x00471358
    };

    unsigned int numelmsArray = NUMELMS( memAddrArray );

    for ( unsigned int n = 0; n < numelmsArray; n++ )
    {
        void *addr = memAddrArray[n];

        MemPut( addr, temporaryBuffer );
    }

    _temporaryBuffer = temporaryBuffer;
}

static void OnShutdown( void )
{

}

BOOL WINAPI DllMain( HINSTANCE hInstDLL, DWORD fdwReason, LPVOID reserved )
{
    switch( fdwReason )
    {
    case DLL_PROCESS_ATTACH:
        OnInitialize();
        break;
    case DLL_PROCESS_DETACH:
        OnShutdown();
        break;
    }

    return TRUE;
}