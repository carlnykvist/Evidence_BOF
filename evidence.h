#include <windows.h>
#include "beacon.h"
#include <iphlpapi.h>

#define printf(format, args...) { BeaconPrintf(CALLBACK_OUTPUT, format, ## args); }


WINBASEAPI VOID WINAPI KERNEL32$GetLocalTime (LPSYSTEMTIME lpSystemTime);
WINBASEAPI void * WINAPI KERNEL32$HeapAlloc (HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree (HANDLE, DWORD, PVOID);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError();
WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileMappingA(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName);
WINBASEAPI LPVOID WINAPI KERNEL32$MapViewOfFile(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh,DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap);
WINBASEAPI BOOL WINAPI KERNEL32$UnmapViewOfFile(LPCVOID lpBaseAddress);
WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
WINBASEAPI DWORD WINAPI IPHLPAPI$GetNetworkParams(PFIXED_INFO,PULONG);
WINBASEAPI HLOCAL WINAPI KERNEL32$LocalFree (HLOCAL);
WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentProcess (VOID);
WINBASEAPI int __cdecl MSVCRT$sprintf(char *__stream, const char *__format, ...);

WINADVAPI WINBOOL WINAPI ADVAPI32$LookupAccountSidA (LPCSTR lpSystemName, PSID Sid, LPSTR Name, LPDWORD cchName, LPSTR ReferencedDomainName, LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse);
WINADVAPI WINBOOL WINAPI ADVAPI32$ConvertSidToStringSidA(PSID Sid,LPSTR *StringSid);
WINADVAPI WINBOOL WINAPI ADVAPI32$OpenProcessToken (HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
WINADVAPI WINBOOL WINAPI ADVAPI32$GetTokenInformation (HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength);







