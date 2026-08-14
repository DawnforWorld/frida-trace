#include "pin.H"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

using std::cerr;
using std::endl;
using std::ofstream;
using std::ostream;
using std::ostringstream;
using std::string;

namespace
{

const char* const kSchemaName = "pintrace-jsonl/2.0";
const char* const kExternalSchemaName = "pintrace-external-jsonl/1.0";
const UINT32 kMaxStaticMemoryOperands = 16;
const UINT32 kMaxDynamicMemoryAccesses = 32;
const UINT32 kHardMaxMemoryBytes = 256;
const UINT32 kMaxExternalMemoryCaptures = 8;

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "", "output JSONL file");
KNOB<string> KnobTargetModule(KNOB_MODE_WRITEONCE, "pintool", "module", "", "target module basename or path; empty selects the main executable");
KNOB<UINT64> KnobStartRva(KNOB_MODE_WRITEONCE, "pintool", "start", "0", "first traced target-module RVA; 0 starts at the first target-module instruction");
KNOB<UINT64> KnobEndRva(KNOB_MODE_WRITEONCE, "pintool", "end", "0", "last traced target-module RVA; 0 traces until process exit");
KNOB<BOOL> KnobTraceOnce(KNOB_MODE_WRITEONCE, "pintool", "once", "1", "trace only the first start/end interval");
KNOB<UINT32> KnobMaxMemoryBytes(KNOB_MODE_WRITEONCE, "pintool", "maxmem", "64", "maximum bytes captured per memory access (1-256)");
KNOB<UINT32> KnobFlushEvery(KNOB_MODE_WRITEONCE, "pintool", "flush", "1024", "flush after this many instruction events; 0 flushes only at exit");
KNOB<BOOL> KnobExternalEvents(KNOB_MODE_WRITEONCE, "pintool", "external", "0", "capture external-call return values and candidate pointer memory");
KNOB<string> KnobExternalOutputFile(KNOB_MODE_WRITEONCE, "pintool", "external-o", "", "external-call sidecar JSONL file");

enum RegisterIndex
{
    kRax,
    kRbx,
    kRcx,
    kRdx,
    kRsi,
    kRdi,
    kRbp,
    kRsp,
    kR8,
    kR9,
    kR10,
    kR11,
    kR12,
    kR13,
    kR14,
    kR15,
    kRflags,
    kFsBase,
    kGsBase,
    kRegisterCount
};

const REG kRegisters[kRegisterCount] = {
    REG_RAX, REG_RBX, REG_RCX, REG_RDX,
    REG_RSI, REG_RDI, REG_RBP, REG_RSP,
    REG_R8, REG_R9, REG_R10, REG_R11,
    REG_R12, REG_R13, REG_R14, REG_R15,
    REG_RFLAGS, REG_SEG_FS_BASE, REG_SEG_GS_BASE
};

const char* const kRegisterNames[kRegisterCount] = {
    "rax", "rbx", "rcx", "rdx",
    "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11",
    "r12", "r13", "r14", "r15",
    "rflags", "fs_base", "gs_base"
};

const UINT32 kXmmRegisterCount = 16;
const UINT32 kXmmRegisterBytes = 16;

const REG kXmmRegisters[kXmmRegisterCount] = {
    REG_XMM0, REG_XMM1, REG_XMM2, REG_XMM3,
    REG_XMM4, REG_XMM5, REG_XMM6, REG_XMM7,
    REG_XMM8, REG_XMM9, REG_XMM10, REG_XMM11,
    REG_XMM12, REG_XMM13, REG_XMM14, REG_XMM15
};

const char* const kXmmRegisterNames[kXmmRegisterCount] = {
    "xmm0", "xmm1", "xmm2", "xmm3",
    "xmm4", "xmm5", "xmm6", "xmm7",
    "xmm8", "xmm9", "xmm10", "xmm11",
    "xmm12", "xmm13", "xmm14", "xmm15"
};

struct MemoryOperandInfo
{
    UINT32 pinIndex;
    UINT32 size;
    BOOL read;
    BOOL write;
};

struct InstructionInfo
{
    ADDRINT address;
    UINT32 size;
    string bytes;
    string mnemonic;
    string category;
    string disassembly;
    BOOL controlFlow;
    BOOL conditionalBranch;
    BOOL call;
    BOOL ret;
    BOOL syscall;
    BOOL directTargetValid;
    ADDRINT directTarget;
    UINT32 rflagsReadMask;
    UINT32 rflagsWrittenMask;
    UINT32 rflagsUndefinedMask;
    UINT32 memoryOperandCount;
    UINT32 omittedStaticMemoryOperands;
    MemoryOperandInfo memoryOperands[kMaxStaticMemoryOperands];
};

struct MemoryCapture
{
    UINT32 operand;
    ADDRINT address;
    UINT32 size;
    BOOL read;
    BOOL write;
    UINT32 beforeCopied;
    UINT32 afterCopied;
    UINT8 before[kHardMaxMemoryBytes];
    UINT8 after[kHardMaxMemoryBytes];
};

struct ExternalMemoryCapture
{
    ADDRINT address;
    UINT32 size;
    UINT32 beforeCopied;
    UINT32 afterCopied;
    UINT8 before[kHardMaxMemoryBytes];
    UINT8 after[kHardMaxMemoryBytes];
};

struct ExternalCallCapture
{
    BOOL valid;
    UINT64 callSequence;
    string module;
    string symbol;
    ADDRINT arguments[4];
    UINT32 memoryCount;
    ExternalMemoryCapture memory[kMaxExternalMemoryCaptures];
};

struct ExtendedRegisterCapture
{
    BOOL valid;
    UINT8 xmm[kXmmRegisterCount][kXmmRegisterBytes];
    ADDRINT mxcsr;
};

enum SyncReason
{
    kSyncNone,
    kSyncTraceStart,
    kSyncExternalReturn
};

struct ThreadState
{
    BOOL tracing;
    BOOL finished;
    BOOL active;
    BOOL awaitingExternalReturn;
    UINT64 threadSequence;
    const InstructionInfo* instruction;
    ADDRINT registers[kRegisterCount];
    ExtendedRegisterCapture extendedRegisters;
    UINT32 memoryCount;
    UINT32 droppedMemoryAccesses;
    MemoryCapture memory[kMaxDynamicMemoryAccesses];
    SyncReason syncReason;
    ExternalCallCapture externalCall;
};

struct ResolvedTarget
{
    string module;
    string symbol;
};

ADDRINT gMainLow = 0;
ADDRINT gMainHigh = 0;
ADDRINT gTraceStart = 0;
ADDRINT gTraceEnd = 0;
string gMainPath;
string gMainModuleName;
string gTargetModuleRequest;
BOOL gTargetIsMainExecutable = TRUE;
ostream* gOutput = &cerr;
ofstream* gOwnedOutput = 0;
ostream* gExternalOutput = 0;
ofstream* gOwnedExternalOutput = 0;
TLS_KEY gTlsKey = INVALID_TLS_KEY;
PIN_LOCK gOutputLock;
UINT32 gMaxMemoryBytes = 64;
UINT64 gGlobalSequence = 0;
UINT64 gInstructionEvents = 0;
UINT64 gDroppedMemoryAccesses = 0;
UINT64 gThreadCount = 0;
UINT64 gExternalEvents = 0;
BOOL gMetadataWritten = FALSE;
BOOL gExternalMetadataWritten = FALSE;

string HexAddress(ADDRINT value)
{
    char buffer[32];
    snprintf(buffer, sizeof(buffer), "0x%016llx", static_cast<unsigned long long>(value));
    return string(buffer);
}

string HexBytes(const UINT8* data, UINT32 size)
{
    static const char digits[] = "0123456789abcdef";
    string result;
    result.reserve(size * 2);
    for (UINT32 index = 0; index < size; ++index)
    {
        const UINT8 value = data[index];
        result.push_back(digits[value >> 4]);
        result.push_back(digits[value & 0x0f]);
    }
    return result;
}

void WriteJsonString(ostream& output, const string& value)
{
    output << '"';
    for (string::const_iterator it = value.begin(); it != value.end(); ++it)
    {
        const unsigned char ch = static_cast<unsigned char>(*it);
        switch (ch)
        {
            case '"': output << "\\\""; break;
            case '\\': output << "\\\\"; break;
            case '\b': output << "\\b"; break;
            case '\f': output << "\\f"; break;
            case '\n': output << "\\n"; break;
            case '\r': output << "\\r"; break;
            case '\t': output << "\\t"; break;
            default:
                if (ch < 0x20)
                {
                    char escaped[8];
                    snprintf(escaped, sizeof(escaped), "\\u%04x", static_cast<unsigned>(ch));
                    output << escaped;
                }
                else
                {
                    output << static_cast<char>(ch);
                }
                break;
        }
    }
    output << '"';
}

string BaseName(const string& path)
{
    string::size_type position = path.find_last_of("\\/");
    return position == string::npos ? path : path.substr(position + 1);
}

string LowerAscii(const string& value)
{
    string result = value;
    for (string::size_type index = 0; index < result.size(); ++index)
    {
        if (result[index] >= 'A' && result[index] <= 'Z')
            result[index] = static_cast<char>(result[index] - 'A' + 'a');
    }
    return result;
}

BOOL ModuleMatchesRequest(const string& imagePath, BOOL isMainExecutable)
{
    if (gTargetModuleRequest.empty())
        return isMainExecutable;

    const string requested = LowerAscii(BaseName(gTargetModuleRequest));
    const string imageName = LowerAscii(BaseName(imagePath));
    const string imageFull = LowerAscii(imagePath);
    const string requestedFull = LowerAscii(gTargetModuleRequest);
    return imageName == requested || imageFull == requestedFull;
}

BOOL IsMainAddress(ADDRINT address)
{
    return gMainLow != 0 && address >= gMainLow && address <= gMainHigh;
}

const char* AddressRegion(ADDRINT address)
{
    return IsMainAddress(address) ? "main" : "other";
}

ThreadState* GetThreadState(THREADID threadId)
{
    return static_cast<ThreadState*>(PIN_GetThreadData(gTlsKey, threadId));
}

UINT32 CopyApplicationBytes(UINT8* destination, ADDRINT address, UINT32 requested)
{
    if (address == 0 || requested == 0)
        return 0;

    UINT32 limited = requested;
    if (limited > gMaxMemoryBytes)
        limited = gMaxMemoryBytes;
    return static_cast<UINT32>(PIN_SafeCopy(destination, reinterpret_cast<const VOID*>(address), limited));
}

ResolvedTarget ResolveTarget(ADDRINT address)
{
    ResolvedTarget result;
    PIN_LockClient();
    IMG image = IMG_FindByAddress(address);
    if (IMG_Valid(image))
    {
        result.module = BaseName(IMG_Name(image));
        RTN routine = RTN_FindByAddress(address);
        if (RTN_Valid(routine))
            result.symbol = PIN_UndecorateSymbolName(RTN_Name(routine), UNDECORATION_NAME_ONLY);
    }
    PIN_UnlockClient();
    return result;
}

void CaptureRegisters(const CONTEXT* context, ADDRINT* registers)
{
    if (!context)
        return;
    for (UINT32 index = 0; index < kRegisterCount; ++index)
        registers[index] = PIN_GetContextReg(context, kRegisters[index]);
}

void CaptureExtendedRegisters(const CONTEXT* context, ExtendedRegisterCapture* capture)
{
    if (!capture)
        return;
    std::memset(capture, 0, sizeof(*capture));
    if (!context)
        return;
    for (UINT32 index = 0; index < kXmmRegisterCount; ++index)
        PIN_GetContextRegval(context, kXmmRegisters[index], capture->xmm[index]);
    capture->mxcsr = PIN_GetContextReg(context, REG_MXCSR);
    capture->valid = TRUE;
}

void WriteRegistersObject(ostream& output, const ADDRINT* registers)
{
    output << '{';
    for (UINT32 index = 0; index < kRegisterCount; ++index)
    {
        if (index)
            output << ',';
        WriteJsonString(output, kRegisterNames[index]);
        output << ':';
        WriteJsonString(output, HexAddress(registers[index]));
    }
    output << '}';
}

void WriteExtendedRegistersObject(ostream& output, const ExtendedRegisterCapture* capture)
{
    if (!capture || !capture->valid)
    {
        output << "null";
        return;
    }
    output << '{';
    output << "\"mxcsr\":";
    WriteJsonString(output, HexAddress(capture->mxcsr));
    output << ",\"xmm\":{";
    for (UINT32 index = 0; index < kXmmRegisterCount; ++index)
    {
        if (index)
            output << ',';
        WriteJsonString(output, kXmmRegisterNames[index]);
        output << ':';
        WriteJsonString(output, HexBytes(capture->xmm[index], kXmmRegisterBytes));
    }
    output << "}}";
}

BOOL IsLikelyPointer(ADDRINT value)
{
    return value >= static_cast<ADDRINT>(0x10000) && value != static_cast<ADDRINT>(-1);
}

BOOL ContainsText(const string& value, const char* needle)
{
    return value.find(needle) != string::npos;
}

void AddExternalMemory(ExternalCallCapture* capture, ADDRINT address, UINT32 size)
{
    if (!IsLikelyPointer(address) || capture->memoryCount >= kMaxExternalMemoryCaptures)
        return;
    if (size == 0)
        size = 8;
    if (size > gMaxMemoryBytes)
        size = gMaxMemoryBytes;

    ExternalMemoryCapture& memory = capture->memory[capture->memoryCount++];
    memory.address = address;
    memory.size = size;
    memory.beforeCopied = CopyApplicationBytes(memory.before, address, size);
    memory.afterCopied = 0;
}

void PrepareExternalMemory(ExternalCallCapture* capture, const ADDRINT* registers)
{
    capture->memoryCount = 0;
    const ADDRINT arguments[4] = {
        registers[kRcx], registers[kRdx], registers[kR8], registers[kR9]
    };

    if (ContainsText(capture->symbol, "_Random_device"))
        return;

    const BOOL sizedBuffer = ContainsText(capture->symbol, "memcpy") ||
        ContainsText(capture->symbol, "memmove") ||
        ContainsText(capture->symbol, "memset") ||
        ContainsText(capture->symbol, "sputn");
    if (sizedBuffer)
    {
        const UINT32 requestedSize = static_cast<UINT32>(arguments[2] <= kHardMaxMemoryBytes
            ? arguments[2] : gMaxMemoryBytes);
        AddExternalMemory(capture, arguments[0], requestedSize);
        if (!ContainsText(capture->symbol, "memset"))
            AddExternalMemory(capture, arguments[1], requestedSize);
        return;
    }

    for (UINT32 index = 0; index < 4; ++index)
        AddExternalMemory(capture, arguments[index], 8);
}

void WriteExternalReturnEvent(THREADID threadId, ThreadState* state, const CONTEXT* context)
{
    if (!KnobExternalEvents.Value() || !state->externalCall.valid || !context || !gExternalOutput)
    {
        state->externalCall.valid = FALSE;
        return;
    }
    ADDRINT returned[kRegisterCount];
    CaptureRegisters(context, returned);
    for (UINT32 index = 0; index < state->externalCall.memoryCount; ++index)
    {
        ExternalMemoryCapture& memory = state->externalCall.memory[index];
        memory.afterCopied = CopyApplicationBytes(memory.after, memory.address, memory.size);
    }
    ostringstream line;
    line << '{' << "\"schema\":";
    WriteJsonString(line, kExternalSchemaName);
    line << ",\"type\":\"external_return\",\"external_seq\":" << ++gExternalEvents;
    line << ",\"tid\":" << static_cast<unsigned>(threadId);
    line << ",\"call_seq\":" << state->externalCall.callSequence;
    line << ",\"module\":"; WriteJsonString(line, state->externalCall.module);
    line << ",\"symbol\":"; WriteJsonString(line, state->externalCall.symbol);
    line << ",\"arguments\":{\"rcx\":\"" << HexAddress(state->externalCall.arguments[0]);
    line << "\",\"rdx\":\"" << HexAddress(state->externalCall.arguments[1]);
    line << "\",\"r8\":\"" << HexAddress(state->externalCall.arguments[2]);
    line << "\",\"r9\":\"" << HexAddress(state->externalCall.arguments[3]) << "\"}";
    line << ",\"return_registers\":"; WriteRegistersObject(line, returned);
    line << ",\"memory\":[";
    for (UINT32 index = 0; index < state->externalCall.memoryCount; ++index)
    {
        if (index) line << ',';
        const ExternalMemoryCapture& memory = state->externalCall.memory[index];
        line << "{\"addr\":\"" << HexAddress(memory.address) << "\",\"size\":" << memory.size;
        line << ",\"before\":\"" << HexBytes(memory.before, memory.beforeCopied);
        line << "\",\"after\":\"" << HexBytes(memory.after, memory.afterCopied) << "\"}";
    }
    line << "]}\n";
    PIN_GetLock(&gOutputLock, threadId + 1);
    *gExternalOutput << line.str();
    if (KnobFlushEvery.Value()) gExternalOutput->flush();
    PIN_ReleaseLock(&gOutputLock);
    state->externalCall.valid = FALSE;
}

const char* FlowKind(const InstructionInfo* instruction)
{
    if (instruction->syscall)
        return "syscall";
    if (instruction->call)
        return "call";
    if (instruction->ret)
        return "return";
    if (instruction->conditionalBranch)
        return "branch";
    if (instruction->controlFlow)
        return "jump";
    return "fallthrough";
}

void WriteMetadata()
{
    if (gMetadataWritten || !gMainLow)
        return;

    *gOutput << '{';
    *gOutput << "\"schema\":";
    WriteJsonString(*gOutput, kSchemaName);
    *gOutput << ",\"type\":\"metadata\"";
    *gOutput << ",\"arch\":\"x86_64\",\"endianness\":\"little\"";
    *gOutput << ",\"pid\":" << static_cast<unsigned long>(PIN_GetPid());
    *gOutput << ",\"module\":{";
    *gOutput << "\"path\":";
    WriteJsonString(*gOutput, gMainPath);
    *gOutput << ",\"name\":";
    WriteJsonString(*gOutput, gMainModuleName);
    *gOutput << ",\"base\":";
    WriteJsonString(*gOutput, HexAddress(gMainLow));
    *gOutput << ",\"high\":";
    WriteJsonString(*gOutput, HexAddress(gMainHigh));
    *gOutput << ",\"target_is_main_executable\":" << (gTargetIsMainExecutable ? "true" : "false");
    *gOutput << '}';
    *gOutput << ",\"selection\":{";
    *gOutput << "\"requested_module\":";
    WriteJsonString(*gOutput, gTargetModuleRequest);
    *gOutput << ",\"resolved_module\":";
    WriteJsonString(*gOutput, gMainModuleName);
    *gOutput << ",\"start_rva\":";
    WriteJsonString(*gOutput, HexAddress(static_cast<ADDRINT>(KnobStartRva.Value())));
    *gOutput << ",\"end_rva\":";
    WriteJsonString(*gOutput, HexAddress(static_cast<ADDRINT>(KnobEndRva.Value())));
    *gOutput << ",\"once\":" << (KnobTraceOnce.Value() ? "true" : "false");
    *gOutput << '}';
    *gOutput << ",\"capture\":{";
    *gOutput << "\"registers\":";
    WriteJsonString(*gOutput, "pre+post");
    *gOutput << ",\"memory_before\":\"pre\",\"memory_after\":\"post\"";
    *gOutput << ",\"memory_byte_order\":\"increasing-address\"";
    *gOutput << ",\"max_memory_bytes\":" << gMaxMemoryBytes;
    *gOutput << ",\"post_registers\":true";
    *gOutput << ",\"extended_registers\":true";
    *gOutput << ",\"extended_register_set\":\"xmm0-xmm15+mxcsr\"";
    *gOutput << ",\"rflags_semantics\":\"xed-read+written+undefined-masks\"";
    *gOutput << ",\"external_events\":" << (KnobExternalEvents.Value() ? "true" : "false");
    *gOutput << '}';
    *gOutput << "}\n";
    gOutput->flush();
    gMetadataWritten = TRUE;
}

void WriteExternalMetadata()
{
    if (gExternalMetadataWritten || !gExternalOutput || !gMainLow)
        return;

    *gExternalOutput << '{';
    *gExternalOutput << "\"schema\":";
    WriteJsonString(*gExternalOutput, kExternalSchemaName);
    *gExternalOutput << ",\"type\":\"metadata\"";
    *gExternalOutput << ",\"arch\":\"x86_64\",\"endianness\":\"little\"";
    *gExternalOutput << ",\"pid\":" << static_cast<unsigned long>(PIN_GetPid());
    *gExternalOutput << ",\"module\":{";
    *gExternalOutput << "\"path\":";
    WriteJsonString(*gExternalOutput, gMainPath);
    *gExternalOutput << ",\"name\":";
    WriteJsonString(*gExternalOutput, gMainModuleName);
    *gExternalOutput << ",\"base\":";
    WriteJsonString(*gExternalOutput, HexAddress(gMainLow));
    *gExternalOutput << ",\"high\":";
    WriteJsonString(*gExternalOutput, HexAddress(gMainHigh));
    *gExternalOutput << ",\"target_is_main_executable\":" << (gTargetIsMainExecutable ? "true" : "false");
    *gExternalOutput << '}';
    *gExternalOutput << ",\"trace_path\":";
    WriteJsonString(*gExternalOutput, KnobOutputFile.Value());
    *gExternalOutput << ",\"capture\":{";
    *gExternalOutput << "\"arguments\":[\"rcx\",\"rdx\",\"r8\",\"r9\"]";
    *gExternalOutput << ",\"return_registers\":\"all_scalar\"";
    *gExternalOutput << ",\"memory\":\"candidate_pointer_pre+return\"";
    *gExternalOutput << ",\"max_memory_bytes\":" << gMaxMemoryBytes;
    *gExternalOutput << "}}\n";
    gExternalOutput->flush();
    gExternalMetadataWritten = TRUE;
}

void WriteInstructionEvent(THREADID threadId, ThreadState* state, ADDRINT nextAddress,
                           BOOL branchDecisionKnown, BOOL branchTaken, BOOL postStateAvailable,
                           const CONTEXT* postContext)
{
    const InstructionInfo* instruction = state->instruction;
    if (!instruction)
        return;

    for (UINT32 index = 0; index < state->memoryCount; ++index)
    {
        MemoryCapture& memory = state->memory[index];
        memory.afterCopied = 0;
        if (postStateAvailable && memory.write)
            memory.afterCopied = CopyApplicationBytes(memory.after, memory.address, memory.size);
    }

    ResolvedTarget external;
    const BOOL entersExternal = instruction->controlFlow && !IsMainAddress(nextAddress);
    if (entersExternal)
        external = ResolveTarget(nextAddress);

    ostringstream line;
    line << '{';
    line << "\"schema\":";
    WriteJsonString(line, kSchemaName);
    line << ",\"type\":\"instruction\"";

    PIN_GetLock(&gOutputLock, threadId + 1);
    const UINT64 sequence = ++gGlobalSequence;
    line << ",\"seq\":" << sequence;
    line << ",\"tid\":" << static_cast<unsigned>(threadId);
    line << ",\"thread_seq\":" << ++state->threadSequence;
    line << ",\"addr\":";
    WriteJsonString(line, HexAddress(instruction->address));
    line << ",\"rva\":";
    WriteJsonString(line, HexAddress(instruction->address - gMainLow));
    line << ",\"size\":" << instruction->size;
    line << ",\"bytes\":";
    WriteJsonString(line, instruction->bytes);
    line << ",\"mnemonic\":";
    WriteJsonString(line, instruction->mnemonic);
    line << ",\"category\":";
    WriteJsonString(line, instruction->category);
    line << ",\"disasm\":";
    WriteJsonString(line, instruction->disassembly);
    line << ",\"rflags_semantics\":{";
    line << "\"read_mask\":";
    WriteJsonString(line, HexAddress(instruction->rflagsReadMask));
    line << ",\"written_mask\":";
    WriteJsonString(line, HexAddress(instruction->rflagsWrittenMask));
    line << ",\"undefined_mask\":";
    WriteJsonString(line, HexAddress(instruction->rflagsUndefinedMask));
    line << '}';
    line << ",\"sync\":";
    if (state->syncReason == kSyncTraceStart)
        WriteJsonString(line, "trace_start");
    else if (state->syncReason == kSyncExternalReturn)
        WriteJsonString(line, "external_return");
    else
        line << "null";

    line << ",\"regs\":";
    WriteRegistersObject(line, state->registers);
    line << ",\"extended_regs\":";
    WriteExtendedRegistersObject(line, &state->extendedRegisters);
    {
        line << ",\"post_regs\":";
        if (postStateAvailable && postContext)
        {
            ADDRINT postRegisters[kRegisterCount];
            CaptureRegisters(postContext, postRegisters);
            WriteRegistersObject(line, postRegisters);
        }
        else
        {
            line << "null";
        }
        line << ",\"post_extended_regs\":";
        if (postStateAvailable && postContext)
        {
            ExtendedRegisterCapture postExtendedRegisters;
            CaptureExtendedRegisters(postContext, &postExtendedRegisters);
            WriteExtendedRegistersObject(line, &postExtendedRegisters);
        }
        else
        {
            line << "null";
        }
    }

    line << ",\"memory\":[";
    for (UINT32 index = 0; index < state->memoryCount; ++index)
    {
        if (index)
            line << ',';
        const MemoryCapture& memory = state->memory[index];
        line << '{';
        line << "\"operand\":" << memory.operand;
        line << ",\"addr\":";
        WriteJsonString(line, HexAddress(memory.address));
        line << ",\"region\":";
        WriteJsonString(line, AddressRegion(memory.address));
        line << ",\"rva\":";
        if (IsMainAddress(memory.address))
            WriteJsonString(line, HexAddress(memory.address - gMainLow));
        else
            line << "null";
        line << ",\"size\":" << memory.size;
        line << ",\"access\":";
        WriteJsonString(line, memory.read && memory.write ? "rw" : (memory.read ? "r" : "w"));
        line << ",\"before\":";
        WriteJsonString(line, HexBytes(memory.before, memory.beforeCopied));
        line << ",\"before_captured\":" << memory.beforeCopied;
        if (memory.write)
        {
            line << ",\"after\":";
            if (postStateAvailable)
                WriteJsonString(line, HexBytes(memory.after, memory.afterCopied));
            else
                line << "null";
            line << ",\"after_captured\":" << memory.afterCopied;
        }
        line << ",\"truncated\":" << ((memory.size > memory.beforeCopied) ? "true" : "false");
        line << '}';
    }
    line << ']';
    line << ",\"memory_dropped\":" << (state->droppedMemoryAccesses + instruction->omittedStaticMemoryOperands);

    line << ",\"flow\":{";
    line << "\"kind\":";
    WriteJsonString(line, FlowKind(instruction));
    line << ",\"taken\":";
    if (branchDecisionKnown)
        line << (branchTaken ? "true" : "false");
    else
        line << "null";
    line << ",\"next\":";
    WriteJsonString(line, HexAddress(nextAddress));
    line << ",\"next_rva\":";
    if (IsMainAddress(nextAddress))
        WriteJsonString(line, HexAddress(nextAddress - gMainLow));
    else
        line << "null";
    line << ",\"direct_target\":";
    if (instruction->directTargetValid)
        WriteJsonString(line, HexAddress(instruction->directTarget));
    else
        line << "null";
    line << ",\"post_state\":" << (postStateAvailable ? "true" : "false");
    line << ",\"external\":";
    if (entersExternal)
    {
        line << '{';
        line << "\"module\":";
        WriteJsonString(line, external.module);
        line << ",\"symbol\":";
        WriteJsonString(line, external.symbol);
        line << '}';
    }
    else
    {
        line << "null";
    }
    line << '}';
    line << "}\n";

    *gOutput << line.str();
    ++gInstructionEvents;
    gDroppedMemoryAccesses += state->droppedMemoryAccesses + instruction->omittedStaticMemoryOperands;
    const UINT32 flushEvery = KnobFlushEvery.Value();
    if (flushEvery && (gInstructionEvents % flushEvery) == 0)
        gOutput->flush();
    PIN_ReleaseLock(&gOutputLock);

    if (entersExternal)
    {
        state->externalCall.valid = KnobExternalEvents.Value();
        if (state->externalCall.valid)
        {
            state->externalCall.callSequence = sequence;
            state->externalCall.module = external.module;
            state->externalCall.symbol = external.symbol;
            state->externalCall.arguments[0] = state->registers[kRcx];
            state->externalCall.arguments[1] = state->registers[kRdx];
            state->externalCall.arguments[2] = state->registers[kR8];
            state->externalCall.arguments[3] = state->registers[kR9];
            PrepareExternalMemory(&state->externalCall, state->registers);
        }
        state->awaitingExternalReturn = TRUE;
    }
}

VOID BeginInstruction(THREADID threadId, const InstructionInfo* instruction, const CONTEXT* context)
{
    ThreadState* state = GetThreadState(threadId);
    if (!state)
        return;

    BOOL startedNow = FALSE;
    if (!state->tracing && (!state->finished || !KnobTraceOnce.Value()))
    {
        if (KnobStartRva.Value() == 0 || instruction->address == gTraceStart)
        {
            state->tracing = TRUE;
            startedNow = TRUE;
        }
    }

    if (!state->tracing)
        return;

    state->active = TRUE;
    state->instruction = instruction;
    state->memoryCount = 0;
    state->droppedMemoryAccesses = 0;
    state->syncReason = startedNow ? kSyncTraceStart :
        (state->awaitingExternalReturn ? kSyncExternalReturn : kSyncNone);
    if (state->syncReason == kSyncExternalReturn)
        WriteExternalReturnEvent(threadId, state, context);
    state->awaitingExternalReturn = FALSE;

    CaptureRegisters(context, state->registers);
    CaptureExtendedRegisters(context, &state->extendedRegisters);
}

VOID CaptureMemory(THREADID threadId, const InstructionInfo* instruction, UINT32 operandIndex, ADDRINT address)
{
    ThreadState* state = GetThreadState(threadId);
    if (!state || !state->active || state->instruction != instruction)
        return;
    if (operandIndex >= instruction->memoryOperandCount)
        return;
    if (state->memoryCount >= kMaxDynamicMemoryAccesses)
    {
        ++state->droppedMemoryAccesses;
        return;
    }

    const MemoryOperandInfo& descriptor = instruction->memoryOperands[operandIndex];
    MemoryCapture& memory = state->memory[state->memoryCount++];
    memory.operand = descriptor.pinIndex;
    memory.address = address;
    memory.size = descriptor.size;
    memory.read = descriptor.read;
    memory.write = descriptor.write;
    memory.beforeCopied = CopyApplicationBytes(memory.before, address, descriptor.size);
    memory.afterCopied = 0;
}

VOID FinishInstruction(THREADID threadId, const InstructionInfo* instruction, ADDRINT nextAddress,
                       BOOL branchDecisionKnown, BOOL branchTaken, BOOL postStateAvailable,
                       const CONTEXT* postContext)
{
    ThreadState* state = GetThreadState(threadId);
    if (!state || !state->active || state->instruction != instruction)
        return;

    WriteInstructionEvent(threadId, state, nextAddress, branchDecisionKnown, branchTaken, postStateAvailable, postContext);
    state->active = FALSE;
    state->instruction = 0;

    if (KnobEndRva.Value() != 0 && instruction->address == gTraceEnd)
    {
        state->tracing = FALSE;
        if (KnobTraceOnce.Value())
            state->finished = TRUE;
    }
}

VOID ImageLoad(IMG image, VOID*)
{
    const string imagePath = IMG_Name(image);
    if (!ModuleMatchesRequest(imagePath, IMG_IsMainExecutable(image)))
        return;
    if (gMainLow != 0)
        return;

    gMainLow = IMG_LowAddress(image);
    gMainHigh = IMG_HighAddress(image);
    gMainPath = imagePath;
    gMainModuleName = BaseName(gMainPath);
    gTargetIsMainExecutable = IMG_IsMainExecutable(image);
    gTraceStart = gMainLow + static_cast<ADDRINT>(KnobStartRva.Value());
    gTraceEnd = gMainLow + static_cast<ADDRINT>(KnobEndRva.Value());

    if (!gOwnedOutput && KnobOutputFile.Value().empty())
    {
        ostringstream fileName;
        fileName << "trace_" << BaseName(gMainPath) << "_" << HexAddress(gMainLow) << ".jsonl";
        gOwnedOutput = new ofstream(fileName.str().c_str(), std::ios::out | std::ios::binary);
        if (gOwnedOutput->good())
            gOutput = gOwnedOutput;
        else
            cerr << "[pintrace] failed to open " << fileName.str() << "; using stderr" << endl;
    }

    if (KnobExternalEvents.Value() && !gOwnedExternalOutput)
    {
        string externalFileName = KnobExternalOutputFile.Value();
        if (externalFileName.empty())
        {
            if (!KnobOutputFile.Value().empty())
                externalFileName = KnobOutputFile.Value() + ".external.jsonl";
            else
            {
                ostringstream generated;
                generated << "trace_" << BaseName(gMainPath) << "_" << HexAddress(gMainLow)
                          << ".external.jsonl";
                externalFileName = generated.str();
            }
        }
        gOwnedExternalOutput = new ofstream(externalFileName.c_str(), std::ios::out | std::ios::binary);
        if (gOwnedExternalOutput->good())
            gExternalOutput = gOwnedExternalOutput;
        else
            cerr << "[pintrace] failed to open external sidecar " << externalFileName << endl;
    }

    WriteMetadata();
    WriteExternalMetadata();
}

VOID InstrumentInstruction(INS instruction, VOID*)
{
    const ADDRINT address = INS_Address(instruction);
    if (!IsMainAddress(address))
        return;

    InstructionInfo* info = new InstructionInfo;
    info->address = address;
    info->size = static_cast<UINT32>(INS_Size(instruction));
    info->mnemonic = INS_Mnemonic(instruction);
    info->category = CATEGORY_StringShort(INS_Category(instruction));
    info->disassembly = INS_Disassemble(instruction);
    info->controlFlow = INS_IsControlFlow(instruction);
    info->conditionalBranch = INS_IsBranch(instruction) && INS_HasFallThrough(instruction);
    info->call = INS_IsCall(instruction);
    info->ret = INS_IsRet(instruction);
    info->syscall = INS_IsSyscall(instruction);
    info->directTargetValid = INS_IsDirectControlFlow(instruction);
    info->directTarget = 0;
    info->rflagsReadMask = 0;
    info->rflagsWrittenMask = 0;
    info->rflagsUndefinedMask = 0;
    info->memoryOperandCount = 0;
    info->omittedStaticMemoryOperands = 0;
    if (info->directTargetValid)
        info->directTarget = INS_DirectControlFlowTargetAddress(instruction);

    const xed_simple_flag_t* rflags =
        xed_decoded_inst_get_rflags_info(INS_XedDec(instruction));
    if (rflags)
    {
        info->rflagsReadMask =
            xed_flag_set_mask(xed_simple_flag_get_read_flag_set(rflags));
        info->rflagsWrittenMask =
            xed_flag_set_mask(xed_simple_flag_get_written_flag_set(rflags));
        info->rflagsUndefinedMask =
            xed_flag_set_mask(xed_simple_flag_get_undefined_flag_set(rflags));
    }

    UINT8 opcode[16];
    UINT32 opcodeSize = info->size;
    if (opcodeSize > sizeof(opcode))
        opcodeSize = sizeof(opcode);
    const UINT32 opcodeCopied = static_cast<UINT32>(PIN_SafeCopy(opcode, reinterpret_cast<const VOID*>(address), opcodeSize));
    info->bytes = HexBytes(opcode, opcodeCopied);

    const UINT32 pinMemoryOperands = INS_MemoryOperandCount(instruction);
    info->memoryOperandCount = pinMemoryOperands;
    if (info->memoryOperandCount > kMaxStaticMemoryOperands)
    {
        info->omittedStaticMemoryOperands = info->memoryOperandCount - kMaxStaticMemoryOperands;
        info->memoryOperandCount = kMaxStaticMemoryOperands;
    }

    for (UINT32 index = 0; index < info->memoryOperandCount; ++index)
    {
        MemoryOperandInfo& operand = info->memoryOperands[index];
        operand.pinIndex = index;
        operand.size = static_cast<UINT32>(INS_MemoryOperandSize(instruction, index));
        operand.read = INS_MemoryOperandIsRead(instruction, index);
        operand.write = INS_MemoryOperandIsWritten(instruction, index);
    }

    INS_InsertCall(instruction, IPOINT_BEFORE, AFUNPTR(BeginInstruction),
                   IARG_THREAD_ID,
                   IARG_PTR, info,
                   IARG_CONST_CONTEXT,
                   IARG_END);

    for (UINT32 index = 0; index < info->memoryOperandCount; ++index)
    {
        INS_InsertPredicatedCall(instruction, IPOINT_BEFORE, AFUNPTR(CaptureMemory),
                                 IARG_THREAD_ID,
                                 IARG_PTR, info,
                                 IARG_UINT32, index,
                                 IARG_MEMORYOP_EA, info->memoryOperands[index].pinIndex,
                                 IARG_END);
    }

    const ADDRINT fallthrough = address + info->size;
    BOOL finishInserted = FALSE;

    if (info->conditionalBranch)
    {
        if (INS_IsValidForIpointAfter(instruction))
        {
            INS_InsertCall(instruction, IPOINT_AFTER, AFUNPTR(FinishInstruction),
                           IARG_THREAD_ID, IARG_PTR, info,
                           IARG_ADDRINT, fallthrough,
                           IARG_BOOL, TRUE, IARG_BOOL, FALSE, IARG_BOOL, TRUE,
                           IARG_CONST_CONTEXT,
                           IARG_END);
            finishInserted = TRUE;
        }
        if (INS_IsValidForIpointTakenBranch(instruction))
        {
            INS_InsertCall(instruction, IPOINT_TAKEN_BRANCH, AFUNPTR(FinishInstruction),
                           IARG_THREAD_ID, IARG_PTR, info,
                           IARG_BRANCH_TARGET_ADDR,
                           IARG_BOOL, TRUE, IARG_BOOL, TRUE, IARG_BOOL, TRUE,
                           IARG_CONST_CONTEXT,
                           IARG_END);
            finishInserted = TRUE;
        }
    }
    else if (info->controlFlow && INS_IsValidForIpointTakenBranch(instruction))
    {
        INS_InsertCall(instruction, IPOINT_TAKEN_BRANCH, AFUNPTR(FinishInstruction),
                       IARG_THREAD_ID, IARG_PTR, info,
                       IARG_BRANCH_TARGET_ADDR,
                       IARG_BOOL, TRUE, IARG_BOOL, TRUE, IARG_BOOL, TRUE,
                       IARG_CONST_CONTEXT,
                       IARG_END);
        finishInserted = TRUE;
    }
    else if (INS_IsValidForIpointAfter(instruction))
    {
        INS_InsertCall(instruction, IPOINT_AFTER, AFUNPTR(FinishInstruction),
                       IARG_THREAD_ID, IARG_PTR, info,
                       IARG_ADDRINT, fallthrough,
                       IARG_BOOL, FALSE, IARG_BOOL, FALSE, IARG_BOOL, TRUE,
                       IARG_CONST_CONTEXT,
                       IARG_END);
        finishInserted = TRUE;
    }

    if (!finishInserted)
    {
        INS_InsertCall(instruction, IPOINT_BEFORE, AFUNPTR(FinishInstruction),
                       IARG_THREAD_ID, IARG_PTR, info,
                       IARG_ADDRINT, fallthrough,
                       IARG_BOOL, FALSE, IARG_BOOL, FALSE, IARG_BOOL, FALSE,
                       IARG_CONST_CONTEXT,
                       IARG_END);
    }
}

VOID ThreadStart(THREADID threadId, CONTEXT*, INT32, VOID*)
{
    ThreadState* state = new ThreadState;
    std::memset(state, 0, sizeof(ThreadState));
    PIN_SetThreadData(gTlsKey, state, threadId);
    PIN_GetLock(&gOutputLock, threadId + 1);
    ++gThreadCount;
    PIN_ReleaseLock(&gOutputLock);
}

VOID ThreadFini(THREADID threadId, const CONTEXT*, INT32, VOID*)
{
    ThreadState* state = GetThreadState(threadId);
    delete state;
    PIN_SetThreadData(gTlsKey, 0, threadId);
}

VOID Fini(INT32 exitCode, VOID*)
{
    PIN_GetLock(&gOutputLock, 1);
    *gOutput << '{';
    *gOutput << "\"schema\":";
    WriteJsonString(*gOutput, kSchemaName);
    *gOutput << ",\"type\":\"summary\"";
    *gOutput << ",\"exit_code\":" << exitCode;
    *gOutput << ",\"instructions\":" << gInstructionEvents;
    *gOutput << ",\"threads\":" << gThreadCount;
    *gOutput << ",\"memory_accesses_dropped\":" << gDroppedMemoryAccesses;
    *gOutput << "}\n";
    gOutput->flush();

    if (gExternalOutput)
    {
        *gExternalOutput << '{';
        *gExternalOutput << "\"schema\":";
        WriteJsonString(*gExternalOutput, kExternalSchemaName);
        *gExternalOutput << ",\"type\":\"summary\"";
        *gExternalOutput << ",\"exit_code\":" << exitCode;
        *gExternalOutput << ",\"external_events\":" << gExternalEvents;
        *gExternalOutput << "}\n";
        gExternalOutput->flush();
    }
    PIN_ReleaseLock(&gOutputLock);

    if (gOwnedOutput)
    {
        gOwnedOutput->close();
        delete gOwnedOutput;
        gOwnedOutput = 0;
    }
    if (gOwnedExternalOutput)
    {
        gOwnedExternalOutput->close();
        delete gOwnedExternalOutput;
        gOwnedExternalOutput = 0;
        gExternalOutput = 0;
    }
}

INT32 Usage()
{
    cerr << "Versioned x86-64 JSONL instruction tracer for deterministic replay." << endl;
    cerr << "Usage: pin.exe -t MyPinTool.dll -start 0xRVA -end 0xRVA -o trace.jsonl -- app.exe [args]" << endl;
    cerr << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

} // namespace

int main(int argc, char* argv[])
{
    PIN_InitSymbols();
    if (PIN_Init(argc, argv))
        return Usage();

    gMaxMemoryBytes = KnobMaxMemoryBytes.Value();
    if (gMaxMemoryBytes == 0)
        gMaxMemoryBytes = 1;
    if (gMaxMemoryBytes > kHardMaxMemoryBytes)
        gMaxMemoryBytes = kHardMaxMemoryBytes;
    gTargetModuleRequest = KnobTargetModule.Value();

    PIN_InitLock(&gOutputLock);
    gTlsKey = PIN_CreateThreadDataKey(0);
    if (gTlsKey == INVALID_TLS_KEY)
    {
        cerr << "[pintrace] failed to allocate a TLS key" << endl;
        return 1;
    }

    if (!KnobOutputFile.Value().empty())
    {
        gOwnedOutput = new ofstream(KnobOutputFile.Value().c_str(), std::ios::out | std::ios::binary);
        if (!gOwnedOutput->good())
        {
            cerr << "[pintrace] failed to open " << KnobOutputFile.Value() << endl;
            return 1;
        }
        gOutput = gOwnedOutput;
    }

    IMG_AddInstrumentFunction(ImageLoad, 0);
    INS_AddInstrumentFunction(InstrumentInstruction, 0);
    PIN_AddThreadStartFunction(ThreadStart, 0);
    PIN_AddThreadFiniFunction(ThreadFini, 0);
    PIN_AddFiniFunction(Fini, 0);

    cerr << "[pintrace] schema=" << kSchemaName
         << " module=" << (gTargetModuleRequest.empty() ? string("<main>") : gTargetModuleRequest)
         << " start_rva=" << HexAddress(static_cast<ADDRINT>(KnobStartRva.Value()))
         << " end_rva=" << HexAddress(static_cast<ADDRINT>(KnobEndRva.Value())) << endl;

    PIN_StartProgram();
    return 0;
}
