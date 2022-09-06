#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>


#pragma comment(lib,"Ws2_32.lib")

#define DEBUGLOG TRUE
#define EVENTLOG TRUE
#define SYSLOG FALSE
#define HOSTNAME "192.168.0.31"
#define PORT 514
#define SYSLOG_DGRAM_SIZE 1024

#define MAX_NAME 256

#if EVENTLOG == TRUE
HANDLE hEventLog;
PSID sidCurrentAccount = NULL;
#endif

#if SYSLOG == TRUE
// copy&pasta&edit from https://github.com/asankah/syslog-win32/blob/master/syslogc.c
static SOCKET socketSyslog = INVALID_SOCKET;
BOOL bSyslogConnected = FALSE;
CHAR szComputerName[256];

void vsyslog(int pri, char* fmt, va_list ap)
{
    static char month[12][4] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                            "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    char  datagramm[SYSLOG_DGRAM_SIZE];
    SYSTEMTIME stm;
    int len;
    char* p;

    if (!bSyslogConnected)
        return;

    GetLocalTime(&stm);
    len = sprintf_s(datagramm, sizeof(datagramm),
        "<%d>%s %2d %02d:%02d:%02d %s %s%s: ",
        pri,
        month[stm.wMonth - 1], stm.wDay, stm.wHour, stm.wMinute, stm.wSecond,
        szComputerName, "umdf2", "[0]");
    len += vsprintf_s(datagramm + len, SYSLOG_DGRAM_SIZE - len, fmt, ap);
    p = strchr(datagramm, '\n');
    if (p)
        *p = 0;
    p = strchr(datagramm, '\r');
    if (p)
        *p = 0;

    sendto(socketSyslog, datagramm, len, 0, NULL, 0);

    return;
}

void syslog(int pri, char* fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vsyslog(pri, fmt, ap);
    va_end(ap);
}

#endif


INT GetSid(PSID* ppSid)
{
    // Validate the input parameter.
    if (ppSid == NULL)
    {
        return -1;
    }

    // Create buffers that may be large enough.  
    // If a buffer is too small, the count parameter will be set to the size needed.  
    DWORD cbSid = 0;
    DWORD dwSidBufferSize = 32;
    SID_NAME_USE eSidType;
    DWORD dwErrorCode = 0;
    DWORD dwUserNameLength = 256, dwDomainSize = 256;
    TCHAR szUserName[256], szDomainName[256];
    

    // Create buffers for the SID and the domain name.  
    *ppSid = (PSID) new BYTE[dwSidBufferSize];
    if (*ppSid == NULL)
    {
        return -1;
    }
    memset(*ppSid, 0, dwSidBufferSize);

    if (!GetUserNameW(szUserName, &dwUserNameLength)) {
        return -1;
    }

    // Obtain the SID for the account name passed.  
    for (; ; )
    {

        // Set the count variables to the buffer sizes and retrieve the SID.  
        cbSid = dwSidBufferSize;
        if (LookupAccountNameW(
            NULL,            // Computer name. NULL for the local computer  
            szUserName,
            *ppSid,          // Pointer to the SID buffer. Use NULL to get the size needed,  
            &cbSid,          // Size of the SID buffer needed.  
            szDomainName,   // wszDomainName,  
            &dwDomainSize,
            &eSidType
        ))
        {
            if (IsValidSid(*ppSid) == FALSE)
            {
                //wprintf(L"The SID for %s is invalid.\n", wszAccName);
                dwErrorCode = -2;
            }
            break;
        }
        dwErrorCode = GetLastError();

        // Check if one of the buffers was too small.  
        if (dwErrorCode == ERROR_INSUFFICIENT_BUFFER)
        {
            if (cbSid > dwSidBufferSize)
            {

                // Reallocate memory for the SID buffer.  
                //wprintf(L"The SID buffer was too small. It will be reallocated.\n");
                FreeSid(*ppSid);
                *ppSid = (PSID) new BYTE[cbSid];
                if (*ppSid == NULL)
                {
                    return -1;
                }
                memset(*ppSid, 0, cbSid);
                dwSidBufferSize = cbSid;
            }
        }
        else
        {
            return -1;
            break;
        }
    }

    return 0;
}



void DebugOut(wchar_t* fmt, ...)
{
    va_list argp;
    va_start(argp, fmt);
    wchar_t dbg_out[4096];
    vswprintf_s(dbg_out, fmt, argp);
    va_end(argp);
    OutputDebugString(dbg_out);
}

VOID init()
{
#if EVENTLOG == TRUE
    GetSid(&sidCurrentAccount);
    
    hEventLog = OpenEventLogA(NULL, "Application");
    if (hEventLog == NULL)
    {
        OutputDebugStringA(("Eventlog source failed to open\n"));
    }
#endif
#if SYSLOG == TRUE
    WSADATA wsd;
    struct hostent* phe = NULL;
    struct addrinfo hints, *res;
    SOCKADDR_IN syslog_hostaddr;
    PADDRINFOA addr = NULL;

    if (WSAStartup(MAKEWORD(2, 2), &wsd)) {
        OutputDebugStringA(("WSAStartup failed\n"));
        return;
    }

    memset(&syslog_hostaddr, 0, sizeof(SOCKADDR_IN));
    memset(&hints, 0, sizeof(hints));
    syslog_hostaddr.sin_family = AF_INET;
    syslog_hostaddr.sin_port = htons(PORT);

    DWORD a = -1;
    if (a = getaddrinfo(HOSTNAME, NULL, &hints, &res))
    {
        DebugOut((wchar_t*)L"getaddrinfo failed %d %d\n", a, GetLastError());
        return;
    }

    syslog_hostaddr.sin_addr.s_addr = (unsigned int)((struct sockaddr_in*)(res->ai_addr))->sin_addr.s_addr;
    freeaddrinfo(res);
    
    socketSyslog = socket(AF_INET, SOCK_DGRAM, 0);
    if (INVALID_SOCKET == socketSyslog)
    {
        OutputDebugStringA(("socket failed\n"));
        return;
    }

    if (connect(socketSyslog, (struct sockaddr*)&syslog_hostaddr, sizeof(syslog_hostaddr)) < 0)
    {
        OutputDebugStringA(("connect failed\n"));
        return;
    }

    DWORD length = 256;
    if (!GetComputerNameA(szComputerName, &length))
    {
        OutputDebugStringA(("GetComputerNameA failed\n"));
        return;
    }

    bSyslogConnected = TRUE;

#endif
}

VOID deinit()
{
#if SYSLOG == TRUE
    if (socketSyslog != INVALID_SOCKET)
    { 
        closesocket(socketSyslog);
        socketSyslog = INVALID_SOCKET;
        bSyslogConnected = FALSE;
    }
    WSACleanup();
#endif
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        init();
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        deinit();
        break;
    }
    return TRUE;
}

BOOL GetLogonFromToken(HANDLE hToken, CHAR *szUser, CHAR *szDomain)
{
    DWORD dwSize = MAX_NAME;
    BOOL bSuccess = FALSE;
    DWORD dwLength = 0;
    PTOKEN_USER ptu = NULL;
    SID_NAME_USE SidType;

    if (NULL == hToken)
        return FALSE;

    if (!GetTokenInformation(hToken, TokenUser, (LPVOID)ptu, 0, &dwLength))
    {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
            return FALSE;
          
        ptu = (PTOKEN_USER)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwLength);

        if (ptu == NULL)
            return FALSE;
            
    }

    if (!GetTokenInformation(hToken, TokenUser, (LPVOID)ptu, dwLength, &dwLength))
    {
        HeapFree(GetProcessHeap(), NULL, (LPVOID)ptu);
        return FALSE;
    }

    if (!LookupAccountSidA(NULL, ptu->User.Sid, (LPSTR)szUser, &dwSize, (LPSTR)szDomain, &dwSize, &SidType))
    {
            DWORD dwResult = GetLastError();
            if (dwResult == ERROR_NONE_MAPPED)
                strncpy_s(szUser, MAX_NAME, "NONE_MAPPED", strlen("NONE_MAPPED"));
            else
            {
                return FALSE;
            }
    }
    
    return TRUE;
}

BOOL GetUserFromProcess(const DWORD procId, CHAR *szUser, CHAR *szDomain)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, procId);
    if (hProcess == NULL)
        return FALSE;
        
    HANDLE hToken = NULL;

    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
    {
        CloseHandle(hProcess);
        return FALSE;
    }
    BOOL bres = GetLogonFromToken(hToken, szUser, szDomain);

    CloseHandle(hToken);
    CloseHandle(hProcess);
  
    return bres;
}

extern "C" __declspec(dllexport) VOID start(ULONG ulPid)
{
    char* szDebugMessage = NULL;
    char szUser[MAX_NAME];
    char szDomain[MAX_NAME];

    memset(szUser, 0, MAX_NAME);
    memset(szDomain, 0, MAX_NAME);

    if ((szDebugMessage = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024)) == NULL)
    {
        return;
    }

    if (GetUserFromProcess(ulPid, szUser, szDomain))
        sprintf_s(szDebugMessage, 1024, "Tool started. PID: %lu User: %s\\%s", ulPid, szDomain, szUser);
    else
        sprintf_s(szDebugMessage, 1024, "Tool started. PID: %lu", ulPid);
    

#if DEBUGLOG == TRUE
    OutputDebugStringA((szDebugMessage));
#endif
#if EVENTLOG == TRUE
    if (hEventLog != NULL)
    {
        ReportEventA(hEventLog, EVENTLOG_WARNING_TYPE, 0, 0, sidCurrentAccount, 1, 0, (LPCSTR *)&szDebugMessage, NULL);
    }
#endif
#if SYSLOG == TRUE
    vsyslog(0, szDebugMessage, 0);
#endif
    HeapFree(GetProcessHeap(), NULL, szDebugMessage);
}

extern "C" __declspec(dllexport) VOID keepalive(ULONG ulPid)
{
    char* szDebugMessage = NULL;
    char szUser[MAX_NAME];
    char szDomain[MAX_NAME];

    memset(szUser, 0, MAX_NAME);
    memset(szDomain, 0, MAX_NAME);

    if ((szDebugMessage = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024)) == NULL)
    {
        return;
    }

    if (GetUserFromProcess(ulPid, szUser, szDomain))
        sprintf_s(szDebugMessage, 1024, "Tool sent keepalive. PID: %lu User: %s\\%s", ulPid, szDomain, szUser);
    else
        sprintf_s(szDebugMessage, 1024, "Tool sent keepalive. PID: %lu", ulPid);
#if DEBUGLOG == TRUE
    OutputDebugStringA((szDebugMessage));
#endif
#if EVENTLOG == TRUE
    if (hEventLog != NULL)
    {
        ReportEventA(hEventLog, EVENTLOG_WARNING_TYPE, 0, 0, sidCurrentAccount, 1, 0, (LPCSTR*)&szDebugMessage, NULL);
    }
#endif
#if SYSLOG == TRUE
    vsyslog(0, szDebugMessage, 0);
#endif
    HeapFree(GetProcessHeap(), NULL, szDebugMessage);
}

extern "C" __declspec(dllexport) VOID stop(ULONG ulPid)
{
    char* szDebugMessage = NULL;
    char szUser[MAX_NAME];
    char szDomain[MAX_NAME];

    memset(szUser, 0, MAX_NAME);
    memset(szDomain, 0, MAX_NAME);

    if ((szDebugMessage = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024)) == NULL)
    {
        return;
    }

    if (GetUserFromProcess(ulPid, szUser, szDomain))
        sprintf_s(szDebugMessage, 1024, "Tool stopped. PID: %lu User: %s\\%s", ulPid, szDomain, szUser);
    else
        sprintf_s(szDebugMessage, 1024, "Tool stopped. PID: %lu", ulPid);
#if DEBUGLOG == TRUE
    OutputDebugStringA((szDebugMessage));
#endif
#if EVENTLOG == TRUE
    if (hEventLog != NULL)
    {
        ReportEventA(hEventLog, EVENTLOG_WARNING_TYPE, 0, 0, sidCurrentAccount, 1, 0, (LPCSTR*)&szDebugMessage, NULL);
    }
#endif
#if SYSLOG == TRUE
    vsyslog(0, szDebugMessage, 0);
#endif
    HeapFree(GetProcessHeap(), NULL, szDebugMessage);
}
