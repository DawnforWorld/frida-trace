#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <TlHelp32.h>

#include <cstdint>
#include <cstdio>

namespace
{
struct SharedState
{
    DWORD version;
    DWORD hitThreadId;
    uint64_t breakpointAddress;
};

volatile LONG gArmed = FALSE;
uint8_t gOriginalByte = 0;
uint64_t gBreakpointAddress = 0;
PVOID gVeh = nullptr;
HANDLE gHitEvent = nullptr;
HANDLE gReadyEvent = nullptr;
HANDLE gMapping = nullptr;
SharedState* gSharedState = nullptr;

bool ChangeByte(uint64_t address, uint8_t value, uint8_t* previous)
{
    void* location = reinterpret_cast<void*>(static_cast<uintptr_t>(address));
    DWORD oldProtection = 0;
    if (!VirtualProtect(location, 1, PAGE_EXECUTE_READWRITE, &oldProtection)) return false;
    if (previous != nullptr) *previous = *static_cast<volatile uint8_t*>(location);
    *static_cast<volatile uint8_t*>(location) = value;
    FlushInstructionCache(GetCurrentProcess(), location, 1);
    DWORD unused = 0;
    const BOOL restored = VirtualProtect(location, 1, oldProtection, &unused);
    return restored != FALSE;
}

bool RestoreBreakpoint()
{
    if (InterlockedCompareExchange(&gArmed, FALSE, TRUE) != TRUE) return true;
    if (ChangeByte(gBreakpointAddress, gOriginalByte, nullptr)) return true;
    InterlockedExchange(&gArmed, TRUE);
    return false;
}

void SuspendOtherThreads()
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;
    const DWORD pid = GetCurrentProcessId();
    const DWORD currentTid = GetCurrentThreadId();
    THREADENTRY32 entry = { sizeof(entry) };
    if (Thread32First(snapshot, &entry))
    {
        do
        {
            if (entry.th32OwnerProcessID != pid || entry.th32ThreadID == currentTid) continue;
            HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, entry.th32ThreadID);
            if (thread != nullptr)
            {
                SuspendThread(thread);
                CloseHandle(thread);
            }
        } while (Thread32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);
}

void ResumeOtherThreads()
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;
    const DWORD pid = GetCurrentProcessId();
    const DWORD currentTid = GetCurrentThreadId();
    THREADENTRY32 entry = { sizeof(entry) };
    if (Thread32First(snapshot, &entry))
    {
        do
        {
            if (entry.th32OwnerProcessID != pid || entry.th32ThreadID == currentTid) continue;
            HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, entry.th32ThreadID);
            if (thread != nullptr)
            {
                ResumeThread(thread);
                CloseHandle(thread);
            }
        } while (Thread32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);
}

LONG CALLBACK VehHandler(EXCEPTION_POINTERS* pointers)
{
    if (pointers == nullptr || pointers->ExceptionRecord == nullptr || pointers->ContextRecord == nullptr)
        return EXCEPTION_CONTINUE_SEARCH;
    if (pointers->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT)
        return EXCEPTION_CONTINUE_SEARCH;

    const uint64_t exceptionAddress = reinterpret_cast<uintptr_t>(pointers->ExceptionRecord->ExceptionAddress);
    const uint64_t contextAddress = pointers->ContextRecord->Rip;
    if (exceptionAddress != gBreakpointAddress ||
        (contextAddress != gBreakpointAddress && contextAddress != gBreakpointAddress + 1))
        return EXCEPTION_CONTINUE_SEARCH;
    if (!RestoreBreakpoint()) return EXCEPTION_CONTINUE_SEARCH;

    pointers->ContextRecord->Rip = gBreakpointAddress;
    if (gSharedState != nullptr)
    {
        gSharedState->hitThreadId = GetCurrentThreadId();
        gSharedState->breakpointAddress = gBreakpointAddress;
        MemoryBarrier();
    }

    SuspendOtherThreads();
    SetEvent(gHitEvent);
    WaitForSingleObject(gReadyEvent, INFINITE);
    ResumeOtherThreads();
    return EXCEPTION_CONTINUE_EXECUTION;
}

bool CreateSynchronizationObjects()
{
    const DWORD pid = GetCurrentProcessId();
    wchar_t hitName[96] = {};
    wchar_t readyName[96] = {};
    wchar_t mappingName[96] = {};
    swprintf_s(hitName, L"Local\\InjectVehHit_%lu", pid);
    swprintf_s(readyName, L"Local\\InjectVehFridaReady_%lu", pid);
    swprintf_s(mappingName, L"Local\\InjectVehState_%lu", pid);
    gHitEvent = CreateEventW(nullptr, FALSE, FALSE, hitName);
    gReadyEvent = CreateEventW(nullptr, TRUE, FALSE, readyName);
    gMapping = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE,
                                  0, sizeof(SharedState), mappingName);
    if (gHitEvent == nullptr || gReadyEvent == nullptr || gMapping == nullptr) return false;
    gSharedState = static_cast<SharedState*>(MapViewOfFile(
        gMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, sizeof(SharedState)));
    if (gSharedState == nullptr) return false;
    ZeroMemory(gSharedState, sizeof(*gSharedState));
    gSharedState->version = 1;
    return true;
}

bool ArmConfiguredExport()
{
    char moduleName[MAX_PATH] = "ucrtbase.dll";
    char symbolName[256] = "__p___argv";
    GetEnvironmentVariableA("FRIDA_TRACE_TRIGGER_MODULE", moduleName, MAX_PATH);
    GetEnvironmentVariableA("FRIDA_TRACE_TRIGGER_SYMBOL", symbolName, 256);
    HMODULE module = GetModuleHandleA(moduleName);
    FARPROC symbol = module == nullptr ? nullptr : GetProcAddress(module, symbolName);
    if (symbol == nullptr) return false;
    gBreakpointAddress = reinterpret_cast<uintptr_t>(symbol);
    if (!ChangeByte(gBreakpointAddress, 0xcc, &gOriginalByte)) return false;
    InterlockedExchange(&gArmed, TRUE);
    return true;
}

void Cleanup()
{
    RestoreBreakpoint();
    if (gVeh != nullptr) RemoveVectoredExceptionHandler(gVeh);
    if (gSharedState != nullptr) UnmapViewOfFile(gSharedState);
    if (gMapping != nullptr) CloseHandle(gMapping);
    if (gHitEvent != nullptr) CloseHandle(gHitEvent);
    if (gReadyEvent != nullptr) CloseHandle(gReadyEvent);
}
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(module);
        SuspendOtherThreads();
        const bool ready = CreateSynchronizationObjects();
        gVeh = AddVectoredExceptionHandler(1, VehHandler);
        const bool armed = ready && gVeh != nullptr && ArmConfiguredExport();
        ResumeOtherThreads();
        return armed ? TRUE : FALSE;
    }
    if (reason == DLL_PROCESS_DETACH) Cleanup();
    return TRUE;
}
