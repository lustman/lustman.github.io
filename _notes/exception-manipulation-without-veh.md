---
layout: post
title: "Exception manipulation without VEH"
---

Let's abuse the process instrumentation callback for personal gain, this time as VEH-like exception manipulation without registering a single VEH or hooking anything :D.

Idea was inspired by stuff found in `distort.wtf`:

```
process_instrumentation_callback_handler proc near
                                        ; DATA XREF: install_process_instrumentation_callback+4E↑o
4C 3B 15 09 EC 06 00                    cmp     r10, cs:KiUserExceptionDispatcher
75 27                                   jnz     short loc_CD420
FC                                      cld
48 8B CC                                mov     rcx, rsp
48 81 C1 F0 04 00 00                    add     rcx, 4F0h       ; record
48 8B D4                                mov     rdx, rsp        ; ctx
41 52                                   push    r10
55                                      push    rbp
48 8B EC                                mov     rbp, rsp
48 83 EC 20                             sub     rsp, 20h
48 83 E4 F0                             and     rsp, 0FFFFFFFFFFFFFFF0h
E8 36 A1 F7 FF                          call    dump_ctx
48 8B E5                                mov     rsp, rbp
5D                                      pop     rbp
41 5A                                   pop     r10

loc_CD420:                              ; CODE XREF: process_instrumentation_callback_handler+7↑j
41 FF E2                                jmp     r10
process_instrumentation_callback_handler endp
```

The implementation below takes this a step further: instead of only inspecting the exception context, it allows us to modify it and choose whether execution should continue through the normal exception dispatcher or resume directly from a modified `CONTEXT`.

## Theory

Windows provides the `ProcessInstrumentationCallback` (`40`) information class for `NtSetInformationProcess`. It allows a process to register a UM callback that is invoked when execution transitions back from kernel mode.

Registration looks like this:

```cpp
PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION info = { 0, 0, &callback };
::NtSetInformationProcess( ::GetCurrentProcess( ), ProcessInstrumentationCallback, &info, sizeof( info ) );
```

The structure is defined as:

```cpp
struct PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION {
    ULONG Version;
    ULONG Reserved;
    PVOID Callback;
};
```

On the return-to-um path, the kernel transfers control to the registered callback, placing the original return address in `r10`:

```
mov r10, <original rip>
jmp callback
```

The original address can be either the instruction following a syscall or `ntdll!KiUserExceptionDispatcher`, depending on the transition.

On the exception path, the callback also receives the exception dispatch frame on the stack. In the layout used by this implementation:

- `r10` contains the original return address.
- `[rsp]` points to the `CONTEXT`.
- `[rsp+4F0h]` points to the `EXCEPTION_RECORD`.

This gives us access to the exception context before the normal UM exception dispatcher processes it.

## Detecting exception dispatch

The distinction between an ordinary syscall return and an exception dispatch comes down to the original return address.

For exceptions, it points to `KiUserExceptionDispatcher`. We can resolve that address during initialization:

```cpp
g_KiUserExceptionDispatcher = ::GetProcAddress( ::GetModuleHandleA( "ntdll.dll" ), "KiUserExceptionDispatcher" );
```

The callback can then distinguish the two paths:

```
callback proc
    cmp     r10, g_KiUserExceptionDispatcher
    jne     skip
```

If the addresses don't match, there is no exception dispatch to handle. We simply transfer execution to the original return address:

```
skip:
    jmp     r10
```

Otherwise, we have an exception frame to inspect before execution reaches `RtlDispatchException`.

## Calling the handler

For exception dispatches, we pass the stack frame, original return address, and entry value of `rax` to a C handler.

The assembly stub is responsible for preserving the original return address and setting up the arguments:

```
    push    rbp
    mov     rbp, rsp
    mov     r14, r10
    lea     rcx, [rbp+8]
    mov     rdx, r14
    mov     r8,  rax
    sub     rsp, 38h
    and     rsp, -16
    call    handler
```

The arguments are:

- `rcx` receives the stack pointer from callback entry. The handler uses it to access the `CONTEXT` and `EXCEPTION_RECORD`.
- `rdx` receives the original return address, preserved in `r14`.
- `r8` receives the entry value of `rax`. It is not meaningful for exception handling, but is passed through for completeness.

The original register state is available in the saved `CONTEXT`, so using `r14` as temporary storage does not discard the interrupted thread's original value.

The handler returns either `0` or a pointer to a `CONTEXT`. Returning `0` leaves the exception on the normal dispatch path, returning a context requests a direct restoration instead.

```cpp
CONTEXT* __cdecl handler( uintptr_t rsp, uintptr_t rip, uintptr_t rax ) {
    CONTEXT* resume = {};

    auto* ctx = reinterpret_cast< CONTEXT* >( rsp );
    auto* record = reinterpret_cast< EXCEPTION_RECORD* >( rsp + 0x4F0 );

    if ( !ctx || g_in_handler )
        return 0;

    g_in_handler = 1;

    if ( record->ExceptionCode == STATUS_ACCESS_VIOLATION ) {
        ctx->Rcx = 0xdead;
        ctx->Rip = reinterpret_cast< uintptr_t >( &::ExitProcess );

        resume = ctx;
    }

    g_in_handler = 0;
    return resume;
}
```

In this example, an access violation causes the saved instruction pointer to be replaced with `ExitProcess`. The modified context is then returned to the assembly stub for restoration.

The `g_in_handler` check is intended to prevent recursive handler execution. If the handler itself triggers another exception, the nested invocation falls back to the normal dispatch path.

## Restoring the context

When the handler returns a `CONTEXT*`, execution takes a different path: instead of returning to `KiUserExceptionDispatcher`, we restore the supplied context and transfer control to its saved instruction pointer.

The restoration routine is implemented in assembly:

```
ctx_return PROC
    fxrstor  [rcx+100h]
    ldmxcsr  DWORD PTR [rcx+34h]

    push     QWORD PTR [rcx+4Ch]
    popfq

    mov      rax, [rcx+78h]
    mov      rdx, [rcx+88h]
    mov      rbx, [rcx+90h]
    mov      rbp, [rcx+0A0h]
    mov      rsi, [rcx+0A8h]
    mov      rdi, [rcx+0B0h]
    mov      r8,  [rcx+0B8h]
    mov      r9,  [rcx+0C0h]
    mov      r10, [rcx+0C8h]
    mov      r11, [rcx+0D0h]
    mov      r12, [rcx+0D8h]
    mov      r13, [rcx+0E0h]
    mov      r14, [rcx+0E8h]
    mov      r15, [rcx+0F0h]

    mov      rsp, [rcx+98h]
    push     QWORD PTR [rcx+0F8h]

    mov      rcx, [rcx+80h]
    ret
ctx_return ENDP
```

The routine restores the FP state, flags, GP registers, and SP before transferring control to the saved `Rip`.

## The fallback path

If the handler returns `0`, we leave the context untouched by the restoration routine and resume the original exception dispatch:

```
to_dispatcher:
    jmp     r14
```

`r14` still contains the original return address, `KiUserExceptionDispatcher`.

This preserves the original dispatch path, allowing `RtlDispatchException` to process the exception normally. Any changes the handler made directly to the saved context remain visible to subsequent exception handling.

## Caveats

There are several limitations worth keeping in mind:

- The process has only 1 callback slot.
- The current implementation is only available on x64.
- The current implementation does not handle concurrency well.