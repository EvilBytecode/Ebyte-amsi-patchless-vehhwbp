# Ebyte-amsi-patchless-vehhwbp

Patchless AMSI bypass using hardware breakpoints and a vectored exception handler to intercept AmsiScanBuffer and AmsiScanString before they execute. The bypass reads the 5th parameter (the AMSI result pointer) from the untouched stack frame, forces a clean result, and returns to the caller without modifying AMSI code in memory.

---

## Background

### AMSI Architecture

AMSI provides content scanning via `AmsiScanBuffer` and `AmsiScanString` exported from `amsi.dll`.

### Hardware Breakpoints (HWBP)

x64 debug registers (DR0-DR7) enable CPU-level breakpoints:
- **DR0-DR3**: Breakpoint addresses (4 available)
- **DR6**: Debug status register
- **DR7**: Debug control register (enables breakpoints, sets type/length)

For execution breakpoints (configured in DR7), the CPU raises `STATUS_SINGLE_STEP` (NTSTATUS 0x80000004) **before** executing the instruction at the breakpoint address.

### Vectored Exception Handlers (VEH)

VEH handlers registered via `AddVectoredExceptionHandler()` are called before SEH handlers. They receive `EXCEPTION_POINTERS` with full CPU context (RIP, RSP, RAX, etc.) and can modify it to redirect control flow.

---

## Reverse Engineering Analysis

### AmsiScanBuffer Function Prologue

Disassembly at entry point (Ctrl + G in x64dbg -> AmsiScanbuffer/AmsiScanString)`0x00007FFB30778160`:

```asm
00007FFB30778160 | 48:895C24 08    | mov qword ptr ss:[rsp+8],rbx
00007FFB30778165 | 48:896C24 10    | mov qword ptr ss:[rsp+10],rbp
00007FFB3077816A | 48:897424 18    | mov qword ptr ss:[rsp+18],rsi
00007FFB3077816F | 57              | push rdi
00007FFB30778170 | 41:56           | push r14
00007FFB30778172 | 41:57           | push r15
00007FFB30778174 | 48:83EC 70      | sub rsp,70
```

### x64 Calling Convention

At function entry (before prologue), stack layout:

```
[rsp+0x00]  = Return address
[rsp+0x08]  = Shadow space
[rsp+0x10]  = Shadow space
[rsp+0x18]  = Shadow space
[rsp+0x20]  = 5th parameter (AMSI_RESULT* result pointer)
```

Register parameters: `RCX` (HAMSICONTEXT), `RDX` (buffer), `R8` (length), `R9` (name).

**Critical Finding:** Result pointer is at `[rsp+0x20]` before prologue modifies the stack.

---

## Technical Implementation

### Phase 1: Initialization

1. Resolve `amsi.dll` and obtain `AmsiScanBuffer`/`AmsiScanString` addresses
2. Register VEH handler via `AddVectoredExceptionHandler(1, VehHandler)`
3. Enumerate all threads using `CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)`

**Limitation:** Threads created after initialization won't have breakpoints unless additional monitoring is implemented.

### Phase 2: Hardware Breakpoint Installation

For each existing thread:
1. Open thread with `THREAD_GET_CONTEXT | THREAD_SET_CONTEXT`
2. Get context with `CONTEXT_DEBUG_REGISTERS` flag
3. Set `DR0 = AmsiScanBuffer`, `DR1 = AmsiScanString`
4. Configure `DR7` to enable local execution breakpoints
5. Write context back with `SetThreadContext()`

**Note:** Some EDRs and protected processes may restrict debug register writes. This technique may not work in all Windows versions or process protection contexts.

### Phase 3: Exception-Based Interception

When AMSI functions are called:
1. Hardware breakpoint triggers → CPU raises `STATUS_SINGLE_STEP` (0x80000004)
2. VEH handler receives exception with full context
3. Validate exception address matches target function
4. Read result pointer from `[rsp+0x20]` (5th parameter)
5. Zero out `AMSI_RESULT` structure
6. Redirect control flow:
   - `RIP = return address` (from `[rsp+0x00]`)
   - `RSP += 8` (simulate `RET`)
   - `RAX = 0` (success)
7. Return `EXCEPTION_CONTINUE_EXECUTION`

---

## Attack Flow

```
DLL Load → InitializeThread() → Thread Enumeration → HWBP Installation
    ↓
Application calls AmsiScanBuffer()
    ↓
HWBP triggers → STATUS_SINGLE_STEP → VEH Handler
    ↓
PoisonScanResult() + ModifyReturnFlow()
    ↓
Execution resumes at return address (RAX=0, result=clean)
```

---

## PoC
<img width="936" height="684" alt="image" src="https://github.com/user-attachments/assets/4e7f0266-b1eb-423d-b3fd-a422e06fa9c9" />


---

## References
- [Microsoft x64 Calling Convention](https://docs.microsoft.com/en-us/cpp/build/x64-calling-convention)
- [Hardware Debug Registers](https://wiki.osdev.org/CPU_Registers_x86-64#Debug_Registers)
- [Vectored Exception Handling](https://docs.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling)
- [AMSI Documentation](https://docs.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal)
- [CS Patchless AMSI bypass](https://www.crowdstrike.com/en-us/blog/crowdstrike-investigates-threat-of-patchless-amsi-bypass-attacks/)
---

## Disclaimer

This research is intended for educational and defensive security purposes only. Use only in authorized security testing environments.

---

**Author:** Evilbytecode  
**Date:** 2025 June  
