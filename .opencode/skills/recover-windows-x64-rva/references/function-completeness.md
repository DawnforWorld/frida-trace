# Complete Function Recovery Contract

Use this reference whenever a user asks for a complete C++ reconstruction of a Windows x64 function.

## Definition

`complete` means the candidate is a proven behavioral twin of the selected function interval over the declared machine-state domain. It is not a claim that original source spelling, local names, comments, inlining choices, or exact high-level types were recovered.

The recovery contract must cover all of these domains:

- ABI and calling convention: argument locations, widths, signedness, return channel, stack alignment, shadow space, preserved registers, varargs, and hidden return pointers.
- Input domain and aliasing: accepted ranges, null/invalid pointer behavior, overlapping buffers, callback contracts, object lifetime, and ownership.
- Normal returns and output bits: return values, output buffers, length/error stores, sentinel preservation, and all byte/bit representations.
- Memory side effects and ownership: stack/global/heap writes, allocation/free order, writes before failure, and untouched bytes.
- Control flow and loop exits: every conditional edge, all exits, loop zero/one/exhaustion cases, and solver-proven infeasible edges.
- External calls and callbacks: call order, arguments, return use, clobbers, LastError/errno/floating flags, and modeled environmental inputs.
- Errors, exceptions, and crashes: return-code failures, allocation failures, SEH, C++ EH type/category/message when observable, processor exceptions, abort/exit, and side effects before the exceptional transfer.
- Floating point and machine state: exact IEEE-754 bits, MXCSR/x87 state, rounding, exception flags, FTZ/DAZ, NaN payload/sign, and vector state.
- Environment assumptions: OS/CRT/compiler assumptions that affect behavior, each validated or proven irrelevant.

Any unknown item in these domains blocks a complete claim. Use `verified`, `inferred`, and `unknown` labels in reports; only `verified` and solver-proven infeasible items may enter the complete C++ artifact.

## Required evidence shape

Each function in `recovery-gate.json` must include:

```json
{
  "completeness_contract": {
    "definition": "recover-function-behavior/1.0",
    "complete": true,
    "domains": {
      "abi_and_calling_convention": {"status": "complete", "evidence": ["..."], "unknown": []},
      "input_domain_and_aliasing": {"status": "complete", "evidence": ["..."], "unknown": []},
      "normal_returns_and_output_bits": {"status": "complete", "evidence": ["..."], "unknown": []},
      "memory_side_effects_and_ownership": {"status": "complete", "evidence": ["..."], "unknown": []},
      "control_flow_and_loop_exits": {"status": "complete", "evidence": ["..."], "unknown": []},
      "external_calls_and_callbacks": {"status": "complete", "evidence": ["..."], "unknown": []},
      "errors_exceptions_and_crashes": {"status": "complete", "evidence": ["..."], "unknown": []},
      "floating_point_and_machine_state": {"status": "complete", "evidence": ["..."], "unknown": []},
      "environment_assumptions": {"status": "complete", "evidence": ["..."], "unknown": []}
    },
    "machine_state_domain": {
      "registers": "captured",
      "stack": "captured",
      "flags": "captured",
      "memory": "captured",
      "external_state": "captured"
    },
    "environment_assumptions": [
      {"name": "Windows x64 user-mode ABI", "validated": true}
    ]
  }
}
```

Use `"proven_irrelevant"` instead of `"captured"` only when Triton slices, branch constraints, and original-target trace evidence prove the state cannot affect any sink in scope.

## Win64 exception and unwind requirements

For Windows x64, exception behavior is part of the function body contract because stack unwinding is table-driven. Parse the PE exception directory before claiming completeness:

- Locate the Exception data directory and parse `.pdata` `RUNTIME_FUNCTION` rows: `BeginAddress`, `EndAddress`, and `UnwindInfoAddress`.
- Map every target RVA and executed return interval to its owning runtime function. A missing row is acceptable only for a proven leaf interval that never adjusts nonvolatile state or stack; otherwise it is unknown.
- Parse `.xdata` `UNWIND_INFO`: version, flags, prolog size, unwind codes, frame register, chained unwind info, exception handler RVA, and handler data.
- If flags contain `UNW_FLAG_CHAININFO`, recursively resolve the chained runtime function.
- If flags contain `UNW_FLAG_EHANDLER` or `UNW_FLAG_UHANDLER`, identify the handler target. Treat unparsed handler data as unknown.
- Detect MSVC C++ EH where possible by handler symbol/import/signature (`__CxxFrameHandler3`, `__CxxFrameHandler4`) and parse or report the FuncInfo, unwind map, try block map, catch handlers, throw info, and type descriptors. Unknown language-specific data blocks complete.
- Capture runtime exceptions with the target: exception code, address/RVA, first/second chance, flags, parameters, stack pointer, selected handler, unwind path, final result, and side effects before transfer.
- Original-target exception traces plus Triton replay must distinguish normal return vs SEH vs C++ exception vs process exit, including thrown type/category and raw exception code where observable.

Required inventory:

```json
{
  "exception_inventory": {
    "complete": true,
    "pe_unwind": {
      "path": "pe-unwind.json",
      "sha256": "<64-hex>",
      "exception_directory_parsed": true,
      "function_covered": true,
      "runtime_function_mapped": true,
      "unknown_unwind_info": false,
      "unknown_handlers": false,
      "unknown_language_specific_data": false
    },
    "cxx_eh": {"status": "not_present"},
    "seh": {"status": "not_present"},
    "runtime_exception_matrix": [],
    "no_runtime_exceptions_proven": true
  }
}
```

If any runtime exception is reachable, add it to `runtime_exception_matrix` and require trace/replay evidence for the exception path.

## Callback and allocation traps

Do not assume mathematically equivalent code is behavior-equivalent when callbacks or allocation exist. A reconstruction must preserve:

- callback argument order and count, even when pure-math results match;
- whether validation happens before allocation or callback invocation;
- allocation size, overflow behavior, and the exception type/category produced by the target runtime;
- stores or sentinels that remain unchanged when an exception transfers control;
- undefined-looking return paths as observed machine behavior, not as source-style cleanup.

Use cheap ABI probes with side-effect callbacks first, then confirm any mismatch with a focused trace and Triton slice before claiming the candidate is fixed.
