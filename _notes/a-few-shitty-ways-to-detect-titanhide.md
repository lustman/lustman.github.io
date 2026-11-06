---
layout: post
title: "A few shitty ways to detect TitanHide"
---

An analysis of TitanHide's behavior revealed a number of flaws in the implementation of its detours. Below are 3 ways to detect the presence of this anti-anti-debug driver.

### ThreadHideFromDebugger

In the `NtQueryInformationThread` hook, the following is implemented for the `ThreadHideFromDebugger` class:

```cpp
NTSTATUS Status = Undocumented::NtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);
if(NT_SUCCESS(Status) && ThreadInformationClass == ThreadHideFromDebugger)
{
    if(Hider::IsHidden(pid, HideThreadHideFromDebugger) &&
            Hider::IsHidden(targetPid, HideThreadHideFromDebugger))
    {
        Log("[TITANHIDE] NtQueryInformationThread(ThreadHideFromDebugger) by %d\r\n", pid);
        __try
        {
            BACKUP_RETURNLENGTH();
            // Since they're asking, assume they're expecting "yes"
            *(BOOLEAN*)ThreadInformation = TRUE;
            RESTORE_RETURNLENGTH();
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            Status = GetExceptionCode();
        }
    }
}
return Status;
```

Developer has decided to skimp, so the value is always set to `1` for ANY thread.

Algorithm:
- Create a normal thread (or use an existing one).
- Call ThreadHideFromDebugger.
- Expect 0.

Implementation example:
```cpp
void shit( ) {
    while ( 1 );
}

detect_status_t ret_status = dsOk;

HANDLE thread_handle = ::CreateThread( nullptr, 0, reinterpret_cast< LPTHREAD_START_ROUTINE >( shit ), nullptr, 0, nullptr );
if ( !thread_handle )
	return dsOk;

int is_hidden = 0;
NTSTATUS query_status = ::NtQueryInformationThread( thread_handle, ThreadHideFromDebugger, &is_hidden, sizeof( is_hidden ), nullptr );

if ( NT_SUCCESS( query_status ) && is_hidden )
	ret_status = dsFail;

::TerminateThread( thread_handle, 0 );
::CloseHandle( thread_handle );

return ret_status;
```

### NtClose

The current implementation of the `NtClose` hook:
```cpp
static NTSTATUS NTAPI HookNtClose(
    IN HANDLE Handle)
{
    ULONG pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    if(Hider::IsHidden(pid, HideNtClose))
    {
        KeWaitForSingleObject(&gDebugPortMutex, Executive, KernelMode, FALSE, nullptr);

        // Check if this is a valid handle without raising exceptionss
        BOOLEAN AuditOnClose;
        NTSTATUS ObStatus = ObQueryObjectAuditingByHandle(Handle, &AuditOnClose);

        NTSTATUS Status;
        if(ObStatus != STATUS_INVALID_HANDLE)  // Don't change the return path for any status except this one
        {
            BOOLEAN BeingDebugged = PsGetProcessDebugPort(PsGetCurrentProcess()) != nullptr;
            OBJECT_HANDLE_INFORMATION HandleInfo = { 0 };

            if(BeingDebugged)
            {
                // Get handle info so we can check if the handle has the ProtectFromClose bit set
                PVOID Object = nullptr;
                ObStatus = ObReferenceObjectByHandle(Handle,
                                                     0,
                                                     nullptr,
                                                     PreviousMode,
                                                     &Object,
                                                     &HandleInfo);
                if(Object != nullptr)
                    ObDereferenceObject(Object);
            }

            if(BeingDebugged && NT_SUCCESS(ObStatus) &&
                    (HandleInfo.HandleAttributes & OBJ_PROTECT_CLOSE))
            {
                // Return STATUS_HANDLE_NOT_CLOSABLE instead of raising an exception
                Log("[TITANHIDE] NtClose(0x%p) (protected handle) by %d\r\n", Handle, pid);
                Status = STATUS_HANDLE_NOT_CLOSABLE;
            }
            else
            {
                Status = ObCloseHandle(Handle, PreviousMode);
            }
        }
        else
        {
            Log("[TITANHIDE] NtClose(0x%p) by %d\r\n", Handle, pid);
            Status = STATUS_INVALID_HANDLE;
        }

        KeReleaseMutex(&gDebugPortMutex, FALSE);

        return Status;
    }
    return ObCloseHandle(Handle, PreviousMode);
}
```

The hook checks whether the handle is valid and whether the OBJ_PROTECT_CLOSE flag is set. On an invalid handle it returns STATUS_INVALID_HANDLE.

There is one caveat. There is a `ProcessHandleCheckingMode` option. It controls the behavior of invalid handle processing (e.g., `NtClose`, `WaitForSingleObject`, `SetEvent`, etc.). When enabled, the kernel generates a UM exception instead of returning a status code. The hook doesn't take this into account, there will be no exception.

Check:
```cpp
ULONG enabled = 0;
int raised = 0;
int toggled = 0;

NTSTATUS status = ::NtQueryInformationProcess( ::GetCurrentProcess( ), ProcessHandleCheckingMode, &enabled, sizeof( enabled ), nullptr );
if ( !NT_SUCCESS( status ) )
    return dsUnsupported;

if ( !enabled ) {
    ULONG enable = 1;
    status = ::NtSetInformationProcess( ::GetCurrentProcess( ), ProcessHandleCheckingMode, &enable, sizeof( enable ) );
    if ( !NT_SUCCESS( status ) )
        return dsUnsupported;
    toggled = 1;
}

__try {
    ::NtClose( reinterpret_cast< HANDLE >( 0xDEADD00D ) );
} __except ( GetExceptionCode( ) == STATUS_INVALID_HANDLE ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH ) {
    raised = 1;
}

/// However, enabling this option is like a slow-acting bomb, so it's better to turn it off right after you've checked it.
if ( toggled ) {
    ULONG disable = 0;
    ::NtSetInformationProcess( ::GetCurrentProcess( ), ProcessHandleCheckingMode, &disable, sizeof( disable ) );
}

return raised ? dsOk : dsFail;
```

There is also another option, `ProcessRaiseUMExceptionOnInvalidHandleClose`. Unlike `ProcessHandleCheckingMode`, it affects only `NtClose`.
To enable it, one of the following conditions must be met:
- `NtGlobalFlag` & 0x400000.
- `CurrentProcess->DebugPort` != 0.
- `ObjectTable->DebugInfo` != 0.

Maybe someone will be able to refine this idea.

### HWBP

In the `NtSetInformationThread` hook the `CONTEXT_DEBUG_REGISTERS` flag is stripped before calling the original function and restored afterwards:
```cpp
 __try
 {
    ProbeForWrite(&Wow64Context->ContextFlags, sizeof(ULONG), 1);
    OriginalContextFlags = Wow64Context->ContextFlags;
    Wow64Context->ContextFlags = OriginalContextFlags & ~0x10; //CONTEXT_DEBUG_REGISTERS ^ CONTEXT_AMD64/CONTEXT_i386
 }
 __except(EXCEPTION_EXECUTE_HANDLER)
 {
    NOTHING;
 }

 const NTSTATUS Status = Undocumented::NtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);

 __try
 {
    ProbeForWrite(&Wow64Context->ContextFlags, sizeof(ULONG), 1);
    Wow64Context->ContextFlags = OriginalContextFlags;
 }
 __except(EXCEPTION_EXECUTE_HANDLER)
 {
    NOTHING;
 }

 return Status;
 ```

On query (`NtQueryInformationThread`) the debug registers are cleared:
```cpp
if(DebugRegistersRequested)
{
    Wow64Context->Dr0 = 0;
    Wow64Context->Dr1 = 0;
    Wow64Context->Dr2 = 0;
    Wow64Context->Dr3 = 0;
    Wow64Context->Dr6 = 0;
    Wow64Context->Dr7 = 0;
}
```

Detection:
```cpp
CONTEXT ctx = {};
ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

ctx.Dr0 = reinterpret_cast< uintptr_t >( &shit );
ctx.Dr7 = 1;

::SetThreadContext( ::GetCurrentThread( ), &ctx );

ctx = {};
ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

::GetThreadContext( ::GetCurrentThread( ), &ctx );
if ( ctx.Dr0 != reinterpret_cast< uintptr_t >( &shit ) ) {
    return dsFail;
}

return dsOk;
```

### Conclusion

All of the 3 methods examined are based on predictable differences between TitanHide’s behavior and the actual kernel behavior. The author’s methodology simplifies implementation but, in turn, creates easily reproducible artifacts. The methods don’t require complicated structures, run in UM, and produce stable results. As long as the author does not correct the noted simplifications, these detection vectors will remain relevant.