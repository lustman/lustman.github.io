---
layout: post
title: "Windows VEH manipulation"
---

Let’s manipulate VEHs for personal gain :D.

> Note that these structures and patterns were tested on Windows 11 26H2. They may differ on other OS versions.

## Dispatch path

Vectored exception handlers are called before frame-based SEH handlers and before stack unwinding begins.

The relevant dispatch path looks like this:

```text
ntdll!KiUserExceptionDispatcher
    RtlDispatchException
        RtlpCallVectoredHandlers    ; Walk the VEH list first.
        RtlLookupFunctionEntry      ; Frame-based SEH after.
        RtlVirtualUnwind
        RtlpExecuteHandlerForException
```

The VEH list is traversed from front to back. Returning `EXCEPTION_CONTINUE_EXECUTION` (`-1`) stops dispatch and resumes execution. `EXCEPTION_CONTINUE_SEARCH` (`0`) continues to the next handler. If no VEH handles the exception, dispatch proceeds to frame-based SEH.

## Structures

The internal, unexported structure lives in `ntdll!LdrpVectorHandlerList` (inside `.mrdata`) and contains separate locks and list heads for VEH and VCH:

```cpp
struct ldrp_vector_handler_list_t {
    SRWLOCK* m_veh_lock;
    LIST_ENTRY m_veh_list;
    SRWLOCK* m_vch_lock;
    LIST_ENTRY m_vch_list;
};
```

This is a standalone record definition:

```cpp
struct vector_handler_entry_t {
    LIST_ENTRY m_entry;
    uint64_t* m_refcount;    /// Pointer to an allocated count.
    uint32_t m_flags;        /// Set to 1 on remove.
    uint32_t m_pad;
    void* m_encoded;         /// Encrypted handler.
};
```

Each handler's address is encrypted using a process cookie. Below is the encryption and decryption method:

```cpp
auto encrypted = _rotr64(ptr ^ cookie, cookie & 0x3f);

auto decrypted = _rotr64(ptr, (64 - (cookie & 0x3f)) & 0x3f) ^ cookie;
```

You need to call `NtQueryInformationProcess` with the `ProcessCookie` option to retrieve a cookie.

It's better, though, not to waste your time like that and just use `EncodePointer`/`DecodePointer` if you're sure they aren't hooked.

## Dispatch internals

The walk loop in `RtlpCallVectoredHandlers`:

```text
lea     rax, [r15+10h]
mov     rax, [rax]               ; rax = m_refcount
lock xadd [rax], rcx             ; +1, int 29h if the old count was <= 0
mov     rcx, [rdi]
call    RtlReleaseSRWLockExclusive
mov     rcx, [r15+20h]
call    RtlDecodePointer
lea     rcx, [rsp+40h]
call    guard_dispatch_icall     ; the handler
mov     rcx, [rdi]
call    RtlAcquireSRWLockExclusive
mov     r15, [r15]               ; next entry
mov     rax, [rsp+38h]
mov     rcx, -1
mov     rax, [rax]
lock xadd [rax], rcx             ; -1
```

- The dispatcher increments the entry's reference count before calling the handler.
- It releases the list lock before invoking the handler and acquires it again afterwards. This allows entries to be unlinked while their handlers are running.
- The reference count keeps an entry alive until dispatch is finished.
- Removal marks the entry by changing its flags, then decrements the reference count. Once the count reaches zero, the entry is freed through `LdrpMrdataHeap`.
- Both reference-count operations contain fastfail checks. An invalid count can trigger `int 29h` with code `0xE`.
- The handler invocation goes through `guard_dispatch_icall`. On CFG-enabled builds, a handler residing in raw RWX memory can fail at the indirect call.
- Removal identifies entries by comparing the supplied handle against the list node address, not the handler pointer stored in the entry.

## Conditions

- `PEB->CrossProcessFlags` (`+0x50`) must have bit 2 (`ProcessUsingVEH`) set, otherwise the dispatcher skips the walk entirely.
- `.mrdata` sits at `PAGE_READONLY`. `LdrProtectMrdata(0)` unprotects the section, `LdrProtectMrdata(1)` protects it again.

## Resolving LdrProtectMrdata

The function has no export entry. However, `RtlInitializeNtUserPfn` is exported and contains the calls that bracket its own table writes:

```text
33 C9                   xor     ecx, ecx
E8 xx xx xx xx          call    LdrProtectMrdata
...
B9 01 00 00 00          mov     ecx, 1
C6 05 xx xx xx xx 01    mov     cs:byte_..., 1
E8 xx xx xx xx          call    LdrProtectMrdata
```

Byte patterns can be used to locate the function. The important part is checking that both relative calls resolve to the same address rather than relying on a single match.

```cpp
using ldr_protect_mrdata_t = void( NTAPI* )( uint8_t );

static ldr_protect_mrdata_t g_LdrProtectMrdata = {};

ldr_protect_mrdata_t resolve_ldr_protect_mrdata( ) {
    if ( g_LdrProtectMrdata )
        return g_LdrProtectMrdata;

    auto* fn = reinterpret_cast< uint8_t* >( ::GetProcAddress( ::GetModuleHandle( L"ntdll.dll" ), "RtlInitializeNtUserPfn" ) );
    if ( !fn )
        return nullptr;

    uintptr_t unprotect_target = {};
    uintptr_t protect_target = {};

    for ( uint16_t i = 0; i < 256; ++i ) {
        auto* p = fn + i;

        if ( !unprotect_target && p[ 0 ] == 0x33 && p[ 1 ] == 0xC9 ) {
            for ( uint8_t j = 2; j < 8; ++j ) {
                if ( p[ j ] != 0xE8 )
                    continue;

                auto rel = *reinterpret_cast< int32_t* >( p + j + 1 );
                unprotect_target = reinterpret_cast< uintptr_t >( p + j + 5 + rel );
                break;
            }
        }

        if ( !protect_target && p[ 0 ] == 0xB9 && p[ 1 ] == 0x01 && p[ 2 ] == 0x00 && p[ 3 ] == 0x00 && p[ 4 ] == 0x00 ) {
            for ( uint8_t j = 5; j < 16; ++j ) {
                if ( p[ j ] != 0xE8 )
                    continue;

                auto rel = *reinterpret_cast< int32_t* >( p + j + 1 );
                protect_target = reinterpret_cast< uintptr_t >( p + j + 5 + rel );
                break;
            }
        }
    }

    if ( !unprotect_target || unprotect_target != protect_target )
        return nullptr;

    g_LdrProtectMrdata = reinterpret_cast< ldr_protect_mrdata_t >( unprotect_target );
    return g_LdrProtectMrdata;
}
```

## Finding the list head

`RtlRemoveVectoredExceptionHandler` is a short thunk that jumps to the internal removal routine.

From there, the call to `RtlAcquireSRWLockExclusive` provides a useful reference point for locating the RIP-relative `lea` that loads `LdrpVectorHandlerList`.

```cpp
uintptr_t get_list_head( ) {
    auto* function = reinterpret_cast< uint8_t* >( &::RtlRemoveVectoredExceptionHandler );

    /*
        33 D2                   xor     edx, edx
        E9 xx xx xx xx          jmp     RtlpRemoveVectoredHandler
    */
    auto rel = *reinterpret_cast< int32_t* >( function + 3 );
    function = function + 7 + rel;

    /*
        4C 8D 25 xx xx xx xx    lea     r12, LdrpVectorHandlerList
        ...
        E8 xx xx xx xx          call    RtlAcquireSRWLockExclusive
    */
    for ( uint8_t i = 0; i < 128; ++i ) {
        auto* p = function + i;

        if ( p[ 0 ] != 0xE8 )
            continue;

        auto call_rel = *reinterpret_cast< int32_t* >( p + 1 );
        auto call_target = reinterpret_cast< uintptr_t >( p + 5 + call_rel );

        if ( call_target != reinterpret_cast< uintptr_t >( &::RtlAcquireSRWLockExclusive ) )
            continue;

        for ( int j = 1; j < 40; ++j ) {
            auto* q = p - j;

            if ( ( q[ 0 ] == 0x4C || q[ 0 ] == 0x48 ) && q[ 1 ] == 0x8D ) {
                uint8_t modrm = q[ 2 ];

                // mod=00, r/m=101 -> [rip+disp32]
                if ( ( modrm & 0xC7 ) == 0x05 ) {
                    auto lea_rel = *reinterpret_cast< int32_t* >( q + 3 );
                    return reinterpret_cast< uintptr_t >( q + 7 + lea_rel );
                }
            }
        }
        break;
    }
    return 0;
}
```

## Locking

```cpp
ldrp_vector_handler_list_t* lock_veh_list( ) {
    if ( !resolve_ldr_protect_mrdata( ) )
        return nullptr;

    auto head = get_list_head( );
    if ( !head )
        return nullptr;

    auto* list = reinterpret_cast< ldrp_vector_handler_list_t* >( head );

    g_LdrProtectMrdata( 0 );
    ::RtlAcquireSRWLockExclusive( list->m_veh_lock );

    return list;
}

void unlock_veh_list( ldrp_vector_handler_list_t* list ) {
    ::RtlReleaseSRWLockExclusive( list->m_veh_lock );
    g_LdrProtectMrdata( 1 );
}
```

## Enumeration

The VEH list is a doubly linked list, and each entry stores an encoded handler pointer.

```cpp
for ( auto* current = head->Flink; current != head; current = current->Flink ) {
    auto* entry = CONTAINING_RECORD( current, vector_handler_entry_t, m_entry );
    auto handler = reinterpret_cast< uintptr_t >( ::DecodePointer( entry->m_encoded ) );

    std::println( "[VEH {}] handler={:#x}", count, handler );

    ++count;
}
```

Output example:

```text
[VEH 0] handler=0x7ff683ce3100
```

## Registration without the API

The internal registration routine, `RtlpAddVectoredHandler`, is responsible for allocating the entry and its reference counter, initializing the fields, linking the entry into the list and setting `ProcessUsingVEH`.

We can simply reimplement it:

```cpp
uintptr_t manual_add_veh( PVECTORED_EXCEPTION_HANDLER handler, bool first ) {
    auto* list = lock_veh_list( );
    if ( !list )
        return 0;

    auto* refcount = reinterpret_cast< uint64_t* >( ::RtlAllocateHeap( ::GetProcessHeap( ), HEAP_ZERO_MEMORY, sizeof( uint64_t ) ) );
    auto* entry = reinterpret_cast< vector_handler_entry_t* >( ::RtlAllocateHeap( ::GetProcessHeap( ), HEAP_ZERO_MEMORY, sizeof( vector_handler_entry_t ) ) );
    if ( !refcount || !entry ) {
        if ( refcount )
            ::RtlFreeHeap( ::GetProcessHeap( ), 0, refcount );
        if ( entry )
            ::RtlFreeHeap( ::GetProcessHeap( ), 0, entry );
        unlock_veh_list( list );
        return 0;
    }

    *refcount = 1;
    entry->m_refcount = refcount;
    entry->m_flags = 0;
    entry->m_encoded = ::EncodePointer( handler );

    if ( first ) {
        entry->m_entry.Flink = list->m_veh_list.Flink;
        entry->m_entry.Blink = &list->m_veh_list;
        list->m_veh_list.Flink->Blink = &entry->m_entry;
        list->m_veh_list.Flink = &entry->m_entry;
    } else {
        entry->m_entry.Flink = &list->m_veh_list;
        entry->m_entry.Blink = list->m_veh_list.Blink;
        list->m_veh_list.Blink->Flink = &entry->m_entry;
        list->m_veh_list.Blink = &entry->m_entry;
    }

    unlock_veh_list( list );

    _interlockedbittestandset( reinterpret_cast< volatile LONG* >( &NtCurrentPeb( )->CrossProcessFlags ), 2 );

    return reinterpret_cast< uintptr_t >( entry );
}
```

A forged entry dispatches like a native one, but `RemoveVectoredExceptionHandler` frees through `LdrpMrdataHeap`, so unlink forged entries by hand.

## Hooking a foreign handler

Hooking the handler function itself is different from changing the list entry. In this case, the registration remains in place and dispatch reaches the modified function through the existing handler pointer.

```cpp
uintptr_t o_veh_handler = {};

uint32_t NTAPI hk_veh_handler( EXCEPTION_POINTERS* info ) {
    return o_veh_handler ? reinterpret_cast< decltype( hk_veh_handler )* >( o_veh_handler )( info ) : EXCEPTION_CONTINUE_SEARCH;
}

bool hook_foreign_veh( void* handler ) {
    if ( ::MH_Initialize( ) != MH_OK )
        return false;

    if ( ::MH_CreateHook( handler, &hk_veh_handler, reinterpret_cast< void** >( &o_veh_handler ) ) != MH_OK || ::MH_EnableHook( handler ) != MH_OK )
        return false;

    return true;
}
```

The list and the registration stay untouched, but CRC check can ruin everything. Вies as soon as the victim unregisters.

## Pointer swap

Changing the stored handler pointer does not change the linked-list structure or the entry's reference counter.

```cpp
uintptr_t o_veh_victim = {};

for ( auto* current = head->Flink; current != head; current = current->Flink ) {
    auto* entry = CONTAINING_RECORD( current, vector_handler_entry_t, m_entry );

    if ( reinterpret_cast< uintptr_t >( ::DecodePointer( entry->m_encoded ) ) != victim )
        continue;

    o_veh_victim = victim;
    entry->m_encoded = ::EncodePointer( replacement );
    swapped = true;
    break;
}
```

The quietest option. Dies as soon as the victim unregisters.

## Wipe

This is a neutralization method involving removal from the list.

```cpp
while ( current != head ) {
    auto* entry = CONTAINING_RECORD( current, vector_handler_entry_t, m_entry );
    auto* next = current->Flink;

    auto handler = reinterpret_cast< uintptr_t >( ::DecodePointer( entry->m_encoded ) );

    bool foreign = image_size == 0 || handler < image_base || handler >= image_base + image_size;

    if ( foreign && handler ) {
        entry->m_entry.Flink->Blink = entry->m_entry.Blink;
        entry->m_entry.Blink->Flink = entry->m_entry.Flink;
        ++killed;
    }

    current = next;
}
```

Unlink only.

## Lobotomy

The handler stays in place, does nothing, and returns immediately.

```text
31 C0    xor eax, eax    ; EXCEPTION_CONTINUE_SEARCH (0)
C3       ret
```

Or return any status that's convenient for you.

CRC check can ruin everything.

## Conclusion

In the latest Windows version, the structure and availability of the API have changed, but that doesn't stop you from exploiting it.

Understanding VEH helps you both modify an application's behavior and defend against such attacks; it's up to you to decide which approach to take.
