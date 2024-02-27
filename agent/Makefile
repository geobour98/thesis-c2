# compiler
CC     := x86_64-w64-mingw32-gcc

# build flags for agent
CFLAGS := -Wall -s -m64 -fno-asynchronous-unwind-tables
CFLAGS += -Os -ffunction-sections -fno-ident -fPIC -lwinhttp
CFLAGS += -Wl,-s,--no-seh,--enable-stdcall-fixup

# build flags for injection
CFLAGS_INJ := -mconsole -I/usr/share/mingw-w64/include/ 
CFLAGS_INJ += -s -ffunction-sections -fdata-sections
CFLAGS_INJ += -Wno-write-strings 

# build flags for DLL
CFLAGS_DLL := -Wall -s -static -shared port-monitors/src/port.def
CFLAGS_DLL += -ffunction-sections -fno-ident -fPIC

# executable names
AGENT_OUT    := core-agent.exe
INJECT_OUT   := implant-inject.exe
DLL_OUT      := port.dll

all: clean shellcode inject dll

shellcode:
	@ echo "[+] Compiling the agent..."
	@ $(CC) core-agent/src/*.c -o core-agent/bin/$(AGENT_OUT) $(CFLAGS)

inject:
	@ echo "[+] Compiling the injection technique..."
	@ $(CC) injection/src/*.c -o injection/bin/$(INJECT_OUT) $(CFLAGS_INJ)

dll:
	@ echo "[+] Compiling the Port Monitors DLL..."
	@ $(CC) port-monitors/src/*.c -o port-monitors/bin/$(DLL_OUT) $(CFLAGS_DLL)

clean:
	@ echo "[+] Cleaning up..."
	@ rm -f core-agent/bin/*.exe
	@ rm -f injection/bin/*.exe
	@ rm -f port-monitors/bin/*.dll