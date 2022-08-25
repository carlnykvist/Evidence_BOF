#include "evidence.h"

typedef struct
{
    UINT Rows;
    UINT Cols;
    LPWSTR Content[1];
} WhoamiTable;


void getTime() {
    SYSTEMTIME localTime;
    KERNEL32$GetLocalTime(&localTime);
    printf("%d-%02d-%02d", localTime.wYear, localTime.wMonth, localTime.wDay);
    printf("%02d:%02d", localTime.wHour, localTime.wMinute);
}

void getDomainInfo() {
    PFIXED_INFO pFixedInfo = NULL;
    ULONG netOutBufLen = 0;
    if(IPHLPAPI$GetNetworkParams(pFixedInfo, &netOutBufLen) == ERROR_BUFFER_OVERFLOW){ 
        pFixedInfo = (FIXED_INFO *)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, netOutBufLen);
    }
    
    if (IPHLPAPI$GetNetworkParams(pFixedInfo, &netOutBufLen) != NO_ERROR){
        printf("could not get network adapter info");
    }
    printf("%s.%s", pFixedInfo->HostName,pFixedInfo->DomainName);
}


VOID* WhoamiGetTokenInfo(TOKEN_INFORMATION_CLASS TokenType)
{
    HANDLE hToken = 0;
    DWORD dwLength = 0;
    VOID* pTokenInfo = 0;

    if (ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_READ, &hToken))
    {
        ADVAPI32$GetTokenInformation(hToken,
                            TokenType,
                            NULL,
                            dwLength,
                            &dwLength);

        if (KERNEL32$GetLastError() == ERROR_INSUFFICIENT_BUFFER)
        {
            pTokenInfo = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, dwLength);
            if (pTokenInfo == NULL)
            {
                KERNEL32$CloseHandle(hToken);
                return NULL;
            }
        }

        if (!ADVAPI32$GetTokenInformation(hToken, TokenType,
                                 (LPVOID)pTokenInfo,
                                 dwLength,
                                 &dwLength))
        {
            KERNEL32$CloseHandle(hToken);
            KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pTokenInfo);
            return NULL;
        }

        KERNEL32$CloseHandle(hToken);
    }

    return pTokenInfo;
}



int WhoamiGroups(void)
{
    DWORD dwIndex = 0;
    char* pSidStr = NULL;

    char szGroupName[255] = {0};
    char szDomainName[255] = {0};

    DWORD cchGroupName  = _countof(szGroupName);
    DWORD cchDomainName = _countof(szDomainName);

    SID_NAME_USE Use = 0;

    PTOKEN_GROUPS pGroupInfo = (PTOKEN_GROUPS)WhoamiGetTokenInfo(TokenGroups);
    WhoamiTable *GroupTable = NULL;

    if (pGroupInfo == NULL)
    {
        return 1;
    }

    /* the header is the first (0) row, so we start in the second one (1) */


    //printf("\n%-50s%-25s%-45s%-25s\n", "GROUP INFORMATION", "Type", "SID", "Attributes");
    //printf("================================================= ===================== ============================================= ==================================================\n");

    for (dwIndex = 0; dwIndex < pGroupInfo->GroupCount; dwIndex++)
    {
        if(ADVAPI32$LookupAccountSidA(NULL,
                          pGroupInfo->Groups[dwIndex].Sid,
                          (LPSTR)&szGroupName,
                          &cchGroupName,
                          (LPSTR)&szDomainName,
                          &cchDomainName,
                          &Use) == 0)
        {
            //If we fail lets try to get the next entry
            continue;
        }

        /* the original tool seems to limit the list to these kind of SID items */
        if ((Use == SidTypeLabel) && !(pGroupInfo->Groups[dwIndex].Attributes & SE_GROUP_LOGON_ID))
        {
                char tmpBuffer[1024] = {0};

            /* looks like windows treats 0x60 as 0x7 for some reason, let's just nod and call it a day:
               0x60 is SE_GROUP_INTEGRITY | SE_GROUP_INTEGRITY_ENABLED
               0x07 is SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED */

            if (pGroupInfo->Groups[dwIndex].Attributes == 0x60)
                pGroupInfo->Groups[dwIndex].Attributes = 0x07;

            /* 3- turn that SID into text-form */
            ADVAPI32$ConvertSidToStringSidA(pGroupInfo->Groups[dwIndex].Sid, &pSidStr);

            /* 1- format it as DOMAIN\GROUP if the domain exists, or just GROUP if not */
            MSVCRT$sprintf((char*)&tmpBuffer, "%s%s%s", szDomainName, cchDomainName ? "\\" : "", szGroupName);
            printf("%-50s\t%-25s\t%-45s", tmpBuffer, "Label", pSidStr);

            
            KERNEL32$LocalFree(pSidStr);
            pSidStr = NULL;
            

            /* 4- reuse that buffer for appending the attributes in text-form at the very end */
            ZeroMemory(tmpBuffer, sizeof(tmpBuffer));

        }
        /* reset the buffers so that we can reuse them */
        ZeroMemory(szGroupName, sizeof(szGroupName));
        ZeroMemory(szDomainName, sizeof(szDomainName));

        cchGroupName = 255;
        cchDomainName = 255;
    }


    /* cleanup our allocations */
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pGroupInfo);

    return 0;
}

void catFile(char *args, int length){
    datap parser;
    BeaconDataParse(&parser, args, length);
    CHAR *file = BeaconDataExtract(&parser, NULL);
    printf("type %s",file);


    HANDLE hFile = KERNEL32$CreateFileA(file,    
        GENERIC_READ,
        FILE_SHARE_READ,              
        NULL,           
        OPEN_EXISTING,  
        0x00100000,              
        NULL);          

    if (hFile == INVALID_HANDLE_VALUE)
    {        
        printf("Failed to open handle to file");
        printf("Last error: 0x%X", KERNEL32$GetLastError());
        return;
    }
    
    HANDLE hMapping = KERNEL32$CreateFileMappingA(hFile, 0, PAGE_READONLY, 0, 0 ,0);
    BYTE* fileBytes = KERNEL32$MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    
    printf("%s", fileBytes);

    KERNEL32$UnmapViewOfFile(fileBytes);
    KERNEL32$CloseHandle(hMapping);
    KERNEL32$CloseHandle(hFile);

}

void go(char *args, int length) {

printf("date /t && time /t");
(void)getTime();
printf("echo %%COMPUTERNAME%%.%%USERDNSDOMAIN%%");
(void)getDomainInfo();
printf("whoami /all | findstr /i label");
(void)WhoamiGroups();
(void)catFile(args, length);

}