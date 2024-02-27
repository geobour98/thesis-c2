#ifndef _HTTP_COMMUNICATION_H
#define _HTTP_COMMUNICATION_H

#include <stdio.h>
#include <windows.h>
#include <winhttp.h>
#include <wchar.h>

extern wchar_t cookie[225];
extern LPSTR bufferResponse;

// GET request to get a task (/taskings)
void get_task( char * encryptedResource, size_t encResSize );
// GET request to download the DLL (/download)
void download( char * encryptedResource, size_t encResSize );
// POST request on /login
void post_login( char * encryptedResource, size_t encResSize );
// POST request with command results on /taskings
void post_command_results( char * encryptedResource, size_t encResSize, char * jsonData );

// Cookie processing (removal of 18 characters)
void cookieProcess( LPVOID buffer );

// WinHttp functions
HINTERNET open_winhttp();
HINTERNET connect_winhttp( HINTERNET hSes );
HINTERNET open_request_winhttp_get( HINTERNET hCon, char * encryptedResource, size_t encResSize );
HINTERNET open_request_winhttp_post( HINTERNET hCon, char * encryptedResource, size_t encResSize );
BOOL set_option_winhttp( HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength );
BOOL add_header_winhttp( HINTERNET hReq, LPCWSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwModifiers );
BOOL send_request_winhttp_get( HINTERNET hReq );
BOOL login_request_winhttp_post( HINTERNET hReq );
BOOL command_request_winhttp_post( HINTERNET hReq, char * jsonData );
BOOL receive_response_winhttp( HINTERNET hReq );
BOOL query_headers_winhttp( HINTERNET hReq, DWORD info, LPVOID buf, LPDWORD bufSize );
BOOL query_data_winhttp( HINTERNET hRes, LPDWORD bytesToRead );
BOOL read_data_winhttp( HINTERNET hReq, LPVOID buffer, DWORD bytesToRead, LPDWORD bytesRead );
BOOL close_request_winhttp( HINTERNET hReq );
BOOL close_conenction_winhttp( HINTERNET hCon );
BOOL close_session_handle( HINTERNET hSes );

#endif // _HTTP_COMMUNICATION_H