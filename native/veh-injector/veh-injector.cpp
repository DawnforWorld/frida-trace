#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
// Native launch and VEH handoff helper for frida-instr-trace.
#include <Windows.h>
#include <cstdint>
#include <cstdio>
#include <cwchar>
#include <filesystem>
#include <string>
#include <vector>

namespace
{
struct Options
{
    std::wstring exe;
    std::wstring dll;
    std::wstring frida;
    std::wstring module;
    std::wstring startModule;
    std::wstring stopModule;
    std::wstring out;
    std::wstring cwd;
    std::wstring triggerModule;
    std::wstring triggerSymbol;
    std::vector< std::wstring > targetArgs;
    uint64_t startRva = 0;
    uint64_t endRva = 0;
    uint64_t triggerRva = 0;
    bool hasTriggerRva = false;
    int targetOnly = 1;
    DWORD flushEvery = 1024;
    DWORD hitTimeoutMs = 60000;
    DWORD readyTimeoutMs = 30000;
    DWORD traceTimeoutMs = 0;
};

struct Handles
{
    PROCESS_INFORMATION process = {};
    HANDLE hitEvent = 0;
    HANDLE readyEvent = 0;
    PROCESS_INFORMATION frida = {};

    ~Handles()
    {
        if (frida.hThread) CloseHandle(frida.hThread);
        if (frida.hProcess) CloseHandle(frida.hProcess);
        if (hitEvent) CloseHandle(hitEvent);
        if (readyEvent) CloseHandle(readyEvent);
        if (process.hThread) CloseHandle(process.hThread);
        if (process.hProcess) CloseHandle(process.hProcess);
    }
};

struct SharedState
{
    DWORD version;
    DWORD hitThreadId;
    uint64_t breakpointAddress;
};

void PrintUsage()
{
    std::fwprintf(stderr,
        L"Usage: veh-injector --exe <path> [--dll <path>] [--frida <path>] "
        L"[--module <name>] [--start-rva <rva>] [--end-rva <rva>] [--out <path>] "
        L"[--trigger-module <name>] [--trigger-symbol <name>] [--trigger-rva <rva>] "
        L"[--start-module <name>] [--stop-module <name>] [--target-only 0|1] "
        L"[--cwd <path>] [--hit-timeout-ms <ms>] [--ready-timeout-ms <ms>] "
        L"[--trace-timeout-ms <ms>] [-- <target args>]\n");
}

std::filesystem::path RepositoryRoot();
std::wstring Hex(uint64_t value);

bool ParseUnsigned(const wchar_t* text, uint64_t* value)
{
    wchar_t* end = 0;
    const unsigned long long parsed = std::wcstoull(text, &end, 0);
    if (text == end || *end != L'\0') return false;
    *value = static_cast< uint64_t >(parsed);
    return true;
}

bool ParseOptions(int argc, wchar_t** argv, Options* options)
{
    for (int i = 1; i < argc; ++i)
    {
        const std::wstring arg = argv[i];
        if (arg == L"--")
        {
            for (++i; i < argc; ++i) options->targetArgs.push_back(argv[i]);
            break;
        }

        if (i + 1 >= argc) return false;
        const wchar_t* value = argv[++i];
        if (arg == L"--exe") options->exe = value;
        else if (arg == L"--dll") options->dll = value;
        else if (arg == L"--frida") options->frida = value;
        else if (arg == L"--module") options->module = value;
        else if (arg == L"--start-module") options->startModule = value;
        else if (arg == L"--stop-module") options->stopModule = value;
        else if (arg == L"--out") options->out = value;
        else if (arg == L"--target-only")
        {
            uint64_t parsed = 0;
            if (!ParseUnsigned(value, &parsed) || parsed > 1) return false;
            options->targetOnly = static_cast<int>(parsed);
        }
        else if (arg == L"--flush")
        {
            uint64_t parsed = 0;
            if (!ParseUnsigned(value, &parsed) || parsed > MAXDWORD) return false;
            options->flushEvery = parsed == 0 ? 16384 : static_cast<DWORD>(parsed);
        }
        else if (arg == L"--cwd") options->cwd = value;
        else if (arg == L"--trigger-module") options->triggerModule = value;
        else if (arg == L"--trigger-symbol") options->triggerSymbol = value;
        else if (arg == L"--trigger-rva")
        {
            if (!ParseUnsigned(value, &options->triggerRva)) return false;
            options->hasTriggerRva = true;
        }
        else if (arg == L"--start-rva")
        {
            if (!ParseUnsigned(value, &options->startRva)) return false;
        }
        else if (arg == L"--end-rva" || arg == L"--stop-rva")
        {
            if (!ParseUnsigned(value, &options->endRva)) return false;
        }
        else if (arg == L"--hit-timeout-ms")
        {
            uint64_t parsed = 0;
            if (!ParseUnsigned(value, &parsed) || parsed > MAXDWORD) return false;
            options->hitTimeoutMs = static_cast< DWORD >(parsed);
        }
        else if (arg == L"--ready-timeout-ms")
        {
            uint64_t parsed = 0;
            if (!ParseUnsigned(value, &parsed) || parsed > MAXDWORD) return false;
            options->readyTimeoutMs = static_cast< DWORD >(parsed);
        }
        else if (arg == L"--trace-timeout-ms")
        {
            uint64_t parsed = 0;
            if (!ParseUnsigned(value, &parsed) || parsed > MAXDWORD) return false;
            options->traceTimeoutMs = static_cast< DWORD >(parsed);
        }
        else return false;
    }

    if (options->exe.empty())
        return false;
    const std::filesystem::path root = RepositoryRoot();
    if (root.empty()) return false;
    if (options->module.empty())
        options->module = std::filesystem::path(options->exe).filename().wstring();
    if (options->dll.empty())
        options->dll = (root / L"native" / L"veh-dll" / L"x64" / L"Release" / L"veh-dll.dll").wstring();
    if (options->frida.empty())
        options->frida = (root / L".venv" / L"Scripts" / L"frida-rva-trace.exe").wstring();
    if (options->out.empty()) options->out = (root / L"traces" / L"native-trace.txt").wstring();
    if (options->startModule.empty()) options->startModule = options->module;
    if (options->stopModule.empty()) options->stopModule = options->module;

    if (options->cwd.empty())
        options->cwd = std::filesystem::path(options->exe).parent_path().wstring();
    return true;
}

std::filesystem::path RepositoryRoot()
{
    wchar_t buffer[MAX_PATH] = {};
    const DWORD length = GetModuleFileNameW(nullptr, buffer, MAX_PATH);
    if (length == 0 || length == MAX_PATH) return {};
    std::filesystem::path root(buffer);
    for (int i = 0; i < 5; ++i) root = root.parent_path();
    return root;
}

std::wstring Quote(const std::wstring& value)
{
    if (value.find_first_of(L" \t\"") == std::wstring::npos) return value;

    std::wstring result = L"\"";
    size_t slashes = 0;
    for (wchar_t ch : value)
    {
        if (ch == L'\\')
        {
            ++slashes;
            continue;
        }
        if (ch == L'\"')
        {
            result.append(slashes * 2 + 1, L'\\');
            result.push_back(ch);
            slashes = 0;
            continue;
        }
        result.append(slashes, L'\\');
        slashes = 0;
        result.push_back(ch);
    }
    result.append(slashes * 2, L'\\');
    result.push_back(L'\"');
    return result;
}

std::wstring BuildTargetCommand(const Options& options)
{
    std::wstring command = Quote(options.exe);
    for (const std::wstring& arg : options.targetArgs)
    {
        command.push_back(L' ');
        command += Quote(arg);
    }
    return command;
}

std::vector<wchar_t> BuildEnvironmentBlock(const Options& options)
{
    std::vector<wchar_t> block;
    wchar_t* environment = GetEnvironmentStringsW();
    if (environment != nullptr)
    {
        for (const wchar_t* p = environment; *p != L'\0'; p += std::wcslen(p) + 1)
        {
            const wchar_t* equals = std::wcschr(p, L'=');
            const bool isTriggerVar = equals != nullptr &&
                _wcsnicmp(p, L"FRIDA_TRACE_TRIGGER_", 20) == 0;
            if (isTriggerVar)
                continue;

            const size_t len = std::wcslen(p) + 1;
            block.insert(block.end(), p, p + len);
        }
        FreeEnvironmentStringsW(environment);
    }

    if (!options.triggerModule.empty())
    {
        const std::wstring moduleVar = L"FRIDA_TRACE_TRIGGER_MODULE=" + options.triggerModule;
        block.insert(block.end(), moduleVar.begin(), moduleVar.end());
        block.push_back(L'\0');
    }

    if (options.hasTriggerRva)
    {
        const std::wstring rvaVar = L"FRIDA_TRACE_TRIGGER_RVA=" + Hex(options.triggerRva);
        block.insert(block.end(), rvaVar.begin(), rvaVar.end());
        block.push_back(L'\0');
    }

    if (!options.triggerSymbol.empty())
    {
        const std::wstring symbolVar = L"FRIDA_TRACE_TRIGGER_SYMBOL=" + options.triggerSymbol;
        block.insert(block.end(), symbolVar.begin(), symbolVar.end());
        block.push_back(L'\0');
    }

    block.push_back(L'\0');
    return block;
}

bool InjectDll(HANDLE process, const std::wstring& dllPath)
{
    const SIZE_T bytes = (dllPath.size() + 1) * sizeof(wchar_t);
    void* remotePath = VirtualAllocEx(process, 0, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remotePath)
    {
        std::fwprintf(stderr, L"VirtualAllocEx failed: %lu\n", GetLastError());
        return false;
    }

    bool success = false;
    SIZE_T written = 0;
    if (!WriteProcessMemory(process, remotePath, dllPath.c_str(), bytes, &written) || written != bytes)
    {
        std::fwprintf(stderr, L"WriteProcessMemory failed: %lu\n", GetLastError());
    }
    else
    {
        const HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
        const FARPROC loadLibrary = kernel32 ? GetProcAddress(kernel32, "LoadLibraryW") : 0;
        if (!loadLibrary)
        {
            std::fwprintf(stderr, L"GetProcAddress(LoadLibraryW) failed: %lu\n", GetLastError());
        }
        else
        {
            HANDLE thread = CreateRemoteThread(process, 0, 0,
                reinterpret_cast< LPTHREAD_START_ROUTINE >(loadLibrary), remotePath, 0, 0);
            if (!thread)
            {
                std::fwprintf(stderr, L"CreateRemoteThread failed: %lu\n", GetLastError());
            }
            else
            {
                const DWORD wait = WaitForSingleObject(thread, 30000);
                DWORD exitCode = 0;
                if (wait == WAIT_OBJECT_0 && GetExitCodeThread(thread, &exitCode) && exitCode != 0)
                    success = true;
                else
                    std::fwprintf(stderr, L"remote LoadLibraryW failed: wait=%lu exit=0x%08lx error=%lu\n",
                                  wait, exitCode, GetLastError());
                CloseHandle(thread);
            }
        }
    }

    VirtualFreeEx(process, remotePath, 0, MEM_RELEASE);
    return success;
}

std::wstring Hex(uint64_t value)
{
    wchar_t buffer[32] = {};
    std::swprintf(buffer, sizeof(buffer) / sizeof(buffer[0]), L"0x%llx",
                  static_cast< unsigned long long >(value));
    return buffer;
}

bool ReadSharedState(DWORD pid, SharedState* state)
{
    const std::wstring name = L"Local\\InjectVehState_" + std::to_wstring(pid);
    HANDLE mapping = OpenFileMappingW(FILE_MAP_READ, FALSE, name.c_str());
    if (!mapping) return false;

    const void* view = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, sizeof(*state));
    if (!view)
    {
        CloseHandle(mapping);
        return false;
    }

    MemoryBarrier();
    *state = *static_cast< const SharedState* >(view);
    UnmapViewOfFile(view);
    CloseHandle(mapping);
    return state->version == 1 && state->hitThreadId != 0;
}

std::wstring BuildFridaCommand(const Options& options, DWORD pid, DWORD hitThreadId,
                               uint64_t breakpointAddress,
                               const std::wstring& readyEvent)
{
    std::wstring command = Quote(options.frida);
    command += L" --pid " + std::to_wstring(pid);
    command += L" --module " + Quote(options.module);
    command += L" --start-module " + Quote(options.startModule);
    command += L" --stop-module " + Quote(options.stopModule);
    command += L" --start-rva " + Hex(options.startRva);
    command += L" --end-rva " + Hex(options.endRva);
    command += L" --out " + Quote(options.out);
    command += L" --target-only " + std::to_wstring(options.targetOnly);
    command += L" --flush " + std::to_wstring(options.flushEvery);
    command += L" --thread-id " + std::to_wstring(hitThreadId);
    command += L" --gate-address " + Hex(breakpointAddress);
    command += L" --ready-event " + Quote(readyEvent);
    return command;
}

bool StartFrida(const Options& options, DWORD pid, DWORD hitThreadId,
                uint64_t breakpointAddress,
                const std::wstring& readyEvent,
                PROCESS_INFORMATION* process)
{
    std::wstring command = BuildFridaCommand(options, pid, hitThreadId,
                                             breakpointAddress, readyEvent);
    std::vector< wchar_t > buffer(command.begin(), command.end());
    buffer.push_back(L'\0');

    STARTUPINFOW startup = {};
    startup.cb = sizeof(startup);
    return CreateProcessW(options.frida.c_str(), buffer.data(), 0, 0, FALSE,
                          CREATE_NEW_PROCESS_GROUP, 0,
                          std::filesystem::path(options.frida).parent_path().parent_path().c_str(),
                          &startup, process) != FALSE;
}
}

int wmain(int argc, wchar_t** argv)
{
    Options options;
    if (!ParseOptions(argc, argv, &options))
    {
        PrintUsage();
        return 2;
    }

    if (!std::filesystem::is_regular_file(options.exe) ||
        !std::filesystem::is_regular_file(options.dll) ||
        !std::filesystem::is_regular_file(options.frida) ||
        !std::filesystem::is_directory(options.cwd))
    {
        std::fwprintf(stderr, L"invalid EXE, DLL, Frida executable, or cwd path\n");
        return 2;
    }

    Handles handles;
    STARTUPINFOW startup = {};
    startup.cb = sizeof(startup);
    std::wstring targetCommand = BuildTargetCommand(options);
    std::vector< wchar_t > targetBuffer(targetCommand.begin(), targetCommand.end());
    targetBuffer.push_back(L'\0');
    std::vector< wchar_t > environment = BuildEnvironmentBlock(options);

    if (!CreateProcessW(options.exe.c_str(), targetBuffer.data(), 0, 0, FALSE,
                        CREATE_SUSPENDED | CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT,
                        environment.data(), options.cwd.c_str(),
                        &startup, &handles.process))
    {
        std::fwprintf(stderr, L"CreateProcessW failed: %lu\n", GetLastError());
        return 3;
    }

    std::wprintf(L"created suspended target: pid=%lu\n", handles.process.dwProcessId);

    const std::wstring hitEventName = L"Local\\InjectVehHit_" +
                                      std::to_wstring(handles.process.dwProcessId);
    const std::wstring readyEventName = L"Local\\InjectVehFridaReady_" +
                                        std::to_wstring(handles.process.dwProcessId);
    handles.hitEvent = CreateEventW(0, FALSE, FALSE, hitEventName.c_str());
    handles.readyEvent = CreateEventW(0, TRUE, FALSE, readyEventName.c_str());
    if (!handles.hitEvent || !handles.readyEvent)
    {
        std::fwprintf(stderr, L"creating synchronization events failed: %lu\n", GetLastError());
        TerminateProcess(handles.process.hProcess, 3);
        return 3;
    }

    if (!InjectDll(handles.process.hProcess, std::filesystem::absolute(options.dll).wstring()))
    {
        TerminateProcess(handles.process.hProcess, 3);
        return 4;
    }
    std::wprintf(L"injected: %ls\n", options.dll.c_str());

    if (ResumeThread(handles.process.hThread) == MAXDWORD)
    {
        std::fwprintf(stderr, L"ResumeThread failed: %lu\n", GetLastError());
        TerminateProcess(handles.process.hProcess, 4);
        return 5;
    }
    std::wprintf(L"target resumed; waiting for DLL breakpoint event\n");
    HANDLE hitWaits[] = { handles.hitEvent, handles.process.hProcess };
    const DWORD hit = WaitForMultipleObjects(2, hitWaits, FALSE, options.hitTimeoutMs);
    if (hit != WAIT_OBJECT_0)
    {
        DWORD exitCode = STILL_ACTIVE;
        GetExitCodeProcess(handles.process.hProcess, &exitCode);
        std::fwprintf(stderr, L"breakpoint event not observed: wait=%lu process exit=0x%08lx\n",
                      hit, exitCode);
        return 6;
    }
    std::wprintf(L"breakpoint event observed; target is paused inside VEH\n");

    SharedState sharedState = {};
    if (!ReadSharedState(handles.process.dwProcessId, &sharedState))
    {
        SetEvent(handles.readyEvent);
        std::fwprintf(stderr, L"failed to read VEH hit thread state: %lu\n", GetLastError());
        return 7;
    }
    std::wprintf(L"VEH hit thread=%lu breakpoint=%p\n", sharedState.hitThreadId,
                 reinterpret_cast< void* >(static_cast< uintptr_t >(sharedState.breakpointAddress)));

    if (!StartFrida(options, handles.process.dwProcessId, sharedState.hitThreadId,
                    sharedState.breakpointAddress, readyEventName, &handles.frida))
    {
        SetEvent(handles.readyEvent);
        std::fwprintf(stderr, L"starting frida-rva-trace failed: %lu\n", GetLastError());
        return 9;
    }

    HANDLE readyWaits[] = { handles.readyEvent, handles.frida.hProcess, handles.process.hProcess };
    const DWORD ready = WaitForMultipleObjects(3, readyWaits, FALSE, options.readyTimeoutMs);
    if (ready != WAIT_OBJECT_0)
    {
        SetEvent(handles.readyEvent);
        if (WaitForSingleObject(handles.frida.hProcess, 0) == WAIT_TIMEOUT)
            TerminateProcess(handles.frida.hProcess, 10);
        std::fwprintf(stderr, L"Frida did not become ready: wait=%lu\n", ready);
        return 10;
    }

    std::wprintf(L"Frida ready event observed; DLL resumed target threads\n");

    const DWORD traceWait = WaitForSingleObject(handles.frida.hProcess,
        options.traceTimeoutMs == 0 ? INFINITE : options.traceTimeoutMs);
    if (traceWait != WAIT_OBJECT_0)
    {
        std::fwprintf(stderr, L"trace timeout; stopping Frida controller\n");
        TerminateProcess(handles.frida.hProcess, 11);
        return 11;
    }

    DWORD fridaExit = 0;
    GetExitCodeProcess(handles.frida.hProcess, &fridaExit);
    std::wprintf(L"frida-rva-trace exited: %lu\n", fridaExit);
    DWORD targetExit = STILL_ACTIVE;
    GetExitCodeProcess(handles.process.hProcess, &targetExit);
    std::wprintf(L"target exit state: 0x%08lx\n", targetExit);
    return static_cast< int >(fridaExit);
}
