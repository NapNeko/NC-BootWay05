#include <Windows.h>
#include <mutex>

#include <stdio.h>
#include <Windows.h>

BYTE OldCode[12] = {0x00};
BYTE HookCode[12] = {0x48, 0xB8, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xFF, 0xE0};

bool HookFunction64(const char *moduleName, LPCSTR lpFuncName, LPVOID lpFunction)
{
    DWORD_PTR FuncAddress = (UINT64)GetProcAddress(GetModuleHandleA(moduleName), lpFuncName);
    DWORD OldProtect = 0;

    if (VirtualProtect((LPVOID)FuncAddress, 12, PAGE_EXECUTE_READWRITE, &OldProtect))
    {
        memcpy(OldCode, (LPVOID)FuncAddress, 12);     // 拷贝原始机器码指令
        *(PINT64)(HookCode + 2) = (UINT64)lpFunction; // 填充90为指定跳转地址
    }
    memcpy((LPVOID)FuncAddress, &HookCode, sizeof(HookCode)); // 拷贝Hook机器指令
    VirtualProtect((LPVOID)FuncAddress, 12, OldProtect, &OldProtect);
    return true;
}
void UnHookFunction64(const char *moduleName, LPCSTR lpFuncName)
{
    DWORD OldProtect = 0;
    UINT64 FuncAddress = (UINT64)GetProcAddress(GetModuleHandleA(moduleName), lpFuncName);
    if (VirtualProtect((LPVOID)FuncAddress, 12, PAGE_EXECUTE_READWRITE, &OldProtect))
    {
        memcpy((LPVOID)FuncAddress, OldCode, sizeof(OldCode));
    }
    VirtualProtect((LPVOID)FuncAddress, 12, OldProtect, &OldProtect);
}
char tempPathA[MAX_PATH];
wchar_t tempPath[MAX_PATH];
extern HANDLE WINAPI MyCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
bool Init()
{
    // 获取临时目录"require('./launcher.node').load('external_index', module);"写到文件

    GetTempPathW(MAX_PATH, tempPath);
    GetTempPathA(MAX_PATH, tempPathA);

    wcscat(tempPath, L"external_index.js");
    strcat(tempPathA, "external_index.js");

    HANDLE hFile = CreateFileA(tempPathA, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        char buffer[1024] = "require('./launcher.node').load('external_index', module);";
        DWORD dwWrite;
        WriteFile(hFile, buffer, strlen(buffer), &dwWrite, NULL);
        CloseHandle(hFile);
    }
    bool hook = HookFunction64("Kernel32.dll", "CreateFileW", MyCreateFileW);
    return hook;
}

std::mutex lock;

bool inited = Init();
int Timer = 0;
HANDLE WINAPI MyCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{

    lock.lock();
    if (Timer > 2)
    {
        UnHookFunction64("Kernel32.dll", "CreateFileW");
        auto ret = CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
        return ret;
    }
    UnHookFunction64("Kernel32.dll", "CreateFileW");
    if (wcsstr(lpFileName, L"app_launcher\\index.js") && Timer > 2)
    {
        // 获取命令行参数
        LPWSTR CommandLine = GetCommandLineW();
        if (wcsstr(CommandLine, L"--enable-logging") != NULL)
        {
            // 获取环境变量NAPCAT_PATH
            LPWSTR napcatPath = _wgetenv(L"NAPCAT_PATH");
            lpFileName = napcatPath;
        }
    }
    if (wcsstr(lpFileName, L"app_launcher\\index.js") != NULL && Timer == 0)
    {
        lpFileName = tempPath;
        Timer++;
    }
    auto ret = CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    HookFunction64("Kernel32.dll", "CreateFileW", MyCreateFileW);
    lock.unlock();
    return ret;
}
//"require('./launcher.node').load('external_index', module);"