#include <stdafx.h>
#include <globals.h>
#include <ConsoleHandler.h>
#include <filesystem>
#include <winternl.h>
#include <tlhelp32.h>
#include <logger/logger.h>
#include <psapi.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "psapi.lib")

using namespace globals;

HMODULE g_loadedModule = nullptr;
std::filesystem::path g_currentPath;

// Глобальные переменные для хранения выделенной памяти
void *g_allocatedMemory = nullptr;
SIZE_T g_allocatedSize = 0;

// Добавляем глобальную переменную для контроля потока мониторинга
std::atomic<bool> g_monitoringActive = true;

bool EnablePrivilege(const char *privilegeName)
{
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    LUID luid;
    if (!LookupPrivilegeValueA(nullptr, privilegeName, &luid))
    {
        CloseHandle(hToken);
        return false;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr);
    DWORD error = GetLastError();

    CloseHandle(hToken);
    return (result && error == ERROR_SUCCESS);
}

void CheckProcessPrivileges()
{
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        DWORD length;
        GetTokenInformation(hToken, TokenPrivileges, nullptr, 0, &length);
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
        {
            std::vector<BYTE> buffer(length);
            if (GetTokenInformation(hToken, TokenPrivileges, buffer.data(), length, &length))
            {
                TOKEN_PRIVILEGES *privileges = reinterpret_cast<TOKEN_PRIVILEGES *>(buffer.data());
                LOG_INFO("Current process has %lu privileges", privileges->PrivilegeCount);

                // Выведем все привилегии
                for (DWORD i = 0; i < privileges->PrivilegeCount; i++)
                {
                    LUID_AND_ATTRIBUTES &priv = privileges->Privileges[i];
                    char privName[256];
                    DWORD nameLen = sizeof(privName);
                    if (LookupPrivilegeNameA(nullptr, &priv.Luid, privName, &nameLen))
                    {
                        LOG_INFO("Privilege %lu: %s (Enabled: %d)",
                                 i,
                                 privName,
                                 (priv.Attributes & SE_PRIVILEGE_ENABLED) != 0);
                    }
                }
            }
        }
        CloseHandle(hToken);
    }

    // Проверим также текущий процесс
    HANDLE hProcess = GetCurrentProcess();
    DWORD processFlags;
    if (GetProcessMitigationPolicy(hProcess, ProcessDynamicCodePolicy, &processFlags, sizeof(processFlags)))
    {
        LOG_INFO("Dynamic Code Policy: 0x%08X", processFlags);
    }

    // Проверим уровень доступа процесса
    BOOL isElevated = FALSE;
    TOKEN_ELEVATION elevation;
    DWORD size = sizeof(elevation);
    if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size))
    {
        isElevated = elevation.TokenIsElevated;
        LOG_INFO("Process Elevation Status: %s", isElevated ? "Elevated" : "Not Elevated");
    }
}

void MonitorLoadLibraryFailure(const std::wstring &dllPath)
{
    DWORD error = GetLastError();
    LOG_ERROR("LoadLibrary failed with error: %lu", error);

    // Проверим загружен ли модуль частично
    HMODULE hModule = GetModuleHandleW(dllPath.c_str());
    if (hModule)
    {
        LOG_ERROR("Module partially loaded at address: 0x%p", hModule);

        // Получим информацию о секциях DLL
        MODULEINFO modInfo;
        if (GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo)))
        {
            LOG_INFO("Module size: %lu bytes", modInfo.SizeOfImage);
            LOG_INFO("Entry point: 0x%p", modInfo.EntryPoint);
        }
    }

    // Проверим текущие модули процесса
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
    if (snapshot != INVALID_HANDLE_VALUE)
    {
        MODULEENTRY32W me;
        me.dwSize = sizeof(me);
        if (Module32FirstW(snapshot, &me))
        {
            do
            {
                LOG_INFO("Loaded module: %ls", me.szModule);
            } while (Module32NextW(snapshot, &me));
        }
        CloseHandle(snapshot);
    }

    // Остальные проверки оставим как есть...
    HANDLE hFile = CreateFileW(dllPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        LOG_ERROR("Cannot access file. Error: %lu", GetLastError());
    }
    else
    {
        LOG_INFO("File is accessible");
        CloseHandle(hFile);
    }

    if (IsDebuggerPresent())
    {
        LOG_ERROR("Debugger detected!");
    }

    DWORD dep_enabled;
    BOOL permanent;
    if (GetProcessDEPPolicy(GetCurrentProcess(), &dep_enabled, &permanent))
    {
        LOG_INFO("DEP Status - Enabled: %lu, Permanent: %d", dep_enabled, permanent);
    }
}

bool PrepareDllSpace()
{
    auto dllPath = g_currentPath / "example.dll";
    if (!std::filesystem::exists(dllPath))
    {
        LOG_ERROR("example.dll not found in directory: %s", g_currentPath.string().c_str());
        return false;
    }

    // Получаем размер DLL
    HANDLE hFile = CreateFileW(dllPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        LOG_ERROR("Failed to open DLL file. Error: %lu", GetLastError());
        return false;
    }

    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS ntHeaders;
    DWORD bytesRead;

    if (!ReadFile(hFile, &dosHeader, sizeof(dosHeader), &bytesRead, nullptr))
    {
        LOG_ERROR("Failed to read DOS header. Error: %lu", GetLastError());
        CloseHandle(hFile);
        return false;
    }

    SetFilePointer(hFile, dosHeader.e_lfanew, nullptr, FILE_BEGIN);
    if (!ReadFile(hFile, &ntHeaders, sizeof(ntHeaders), &bytesRead, nullptr))
    {
        LOG_ERROR("Failed to read NT headers. Error: %lu", GetLastError());
        CloseHandle(hFile);
        return false;
    }

    g_allocatedSize = ntHeaders.OptionalHeader.SizeOfImage;
    CloseHandle(hFile);

    // Генерируем случайный адрес в диапазоне
    SYSTEM_INFO si;
    GetSystemInfo(&si);

    // Случайное смещение в пределах доступного адресного пространства
    uintptr_t minAddr = (uintptr_t)si.lpMinimumApplicationAddress;
    uintptr_t maxAddr = (uintptr_t)si.lpMaximumApplicationAddress - g_allocatedSize;

    // Генерируем случайный адрес с выравниванием по странице
    uintptr_t randomAddr = minAddr + (rand() % (maxAddr - minAddr));
    randomAddr &= ~(si.dwPageSize - 1); // Выравнивание по размеру страницы

    // Пытаемся выделить память по случайному адресу
    g_allocatedMemory = VirtualAlloc((LPVOID)randomAddr, g_allocatedSize,
                                     MEM_RESERVE | MEM_COMMIT,
                                     PAGE_EXECUTE_READWRITE);

    if (!g_allocatedMemory)
    {
        // Если не удалось выделить по случайному адресу, пробуем без указания адреса
        g_allocatedMemory = VirtualAlloc(nullptr, g_allocatedSize,
                                         MEM_RESERVE | MEM_COMMIT,
                                         PAGE_EXECUTE_READWRITE);
    }

    if (g_allocatedMemory)
    {
        LOG_INFO("Pre-allocated %lu bytes at address: 0x%p", g_allocatedSize, g_allocatedMemory);
        return true;
    }

    LOG_ERROR("Failed to allocate memory. Error: %lu", GetLastError());
    return false;
}

void HandleKey()
{
    while (!g_break)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        if (GetAsyncKeyState(VK_F6) & 1)
        {
            if (!g_loadedModule && g_allocatedMemory)
            {
                auto dllPath = g_currentPath / "example.dll";

                // Загружаем DLL без DONT_RESOLVE_DLL_REFERENCES
                g_loadedModule = LoadLibraryW(dllPath.wstring().c_str());

                if (g_loadedModule)
                {
                    MODULEINFO modInfo;
                    if (GetModuleInformation(GetCurrentProcess(), g_loadedModule, &modInfo, sizeof(modInfo)))
                    {
                        LOG_INFO("DLL loaded and initialized at: 0x%p", g_loadedModule);
                        LOG_INFO("Entry point executed at: 0x%p", modInfo.EntryPoint);
                    }
                }
                else
                {
                    LOG_ERROR("Failed to load DLL. Error: %lu", GetLastError());
                }
            }
        }

        // Unload DLL on F7
        if (GetAsyncKeyState(VK_F7) & 1)
        {
            if (g_loadedModule)
            {
                if (FreeLibrary(g_loadedModule))
                {
                    LOG_INFO("example.dll successfully unloaded!");
                    g_loadedModule = nullptr;
                }
                else
                {
                    LOG_ERROR("Failed to unload example.dll. Error: %lu", GetLastError());
                }
            }
        }

        // Exit loader on F9
        if (GetAsyncKeyState(VK_F9) & 1)
        {
            if (g_loadedModule)
            {
                FreeLibrary(g_loadedModule);
                g_loadedModule = nullptr;
            }
            LOG_INFO("Unloading loader...");
            g_break = true;
            break;
        }
    }
}

void MonitorMemoryProtection()
{
    while (g_monitoringActive && !g_break)
    {
        if (g_allocatedMemory)
        {
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery(g_allocatedMemory, &mbi, sizeof(mbi)))
            {
                // Проверя��м, есть ли права на запись
                if (!(mbi.Protect & PAGE_EXECUTE_READWRITE))
                {
                    LOG_WARN("Memory protection changed at 0x%p! Current protection: 0x%X",
                             g_allocatedMemory, mbi.Protect);

                    DWORD oldProtect;
                    if (VirtualProtect(g_allocatedMemory, g_allocatedSize,
                                       PAGE_EXECUTE_READWRITE, &oldProtect))
                    {
                        LOG_INFO("Successfully restored PAGE_EXECUTE_READWRITE protection");
                    }
                    else
                    {
                        LOG_ERROR("Failed to restore memory protection. Error: %lu", GetLastError());
                    }
                }
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

DWORD WINAPI MainThread(HMODULE hmod, LPVOID lpParam)
{
    if (!ConsoleHandler::Instance().Initialize())
    {
        LOG_ERROR("Failed to initialize console");
        return 1;
    }

    // Get path to current DLL
    wchar_t dllPath[MAX_PATH];
    GetModuleFileNameW(hmod, dllPath, MAX_PATH);
    g_currentPath = std::filesystem::path(dllPath).parent_path();

    // Подготавливаем память сразу при ��апуске
    srand((unsigned)time(nullptr));
    if (!PrepareDllSpace())
    {
        LOG_ERROR("Failed to prepare space for DLL");
        return 1;
    }

    LOG_INFO("DLL loader started!");
    LOG_INFO("F6 - Load example.dll");
    LOG_INFO("F7 - Unload example.dll");
    LOG_INFO("F9 - Exit");

    std::thread keyThread(HandleKey);
    std::thread monitorThread(MonitorMemoryProtection);
    keyThread.detach();
    monitorThread.detach();

    while (!g_break.load(std::memory_order_relaxed))
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    g_monitoringActive = false; // Останавливаем мониторинг перед выходом
    LOG_INFO("Loader unloaded!");
    FreeLibraryAndExitThread(hmod, 0);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        ConsoleHandler::Init();
        DisableThreadLibraryCalls(hModule);
        CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)MainThread, hModule, 0, nullptr);
        break;

    case DLL_PROCESS_DETACH:
        g_monitoringActive = false; // Останавливаем мониторинг
        if (g_loadedModule)
        {
            FreeLibrary(g_loadedModule);
        }
        if (g_allocatedMemory)
        {
            VirtualFree(g_allocatedMemory, 0, MEM_RELEASE);
        }
        ConsoleHandler::Cleanup();
        ConsoleHandler::Destroy();
        break;
    }
    return TRUE;
}
