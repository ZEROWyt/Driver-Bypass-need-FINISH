#pragma once

#ifndef RVA_TO_VA
#define RVA_TO_VA(p) ((PVOID)((PCHAR)(p) + *(PLONG)(p) + sizeof(LONG)))
#endif 

#define LENGTH(a) (sizeof(a) / sizeof(a[0]))
#define RELATIVE_ADDR(addr, size) ((PVOID)((PBYTE)addr + *(PINT)((PBYTE)addr + (size - (INT)sizeof(INT))) + size))

#define ABSOLUTE(wait) (wait)

#define RELATIVE(wait) (-(wait))

#define NANOSECONDS(nanos) \
(((signed __int64)(nanos)) / 100L)

#define MICROSECONDS(micros) \
(((signed __int64)(micros)) * NANOSECONDS(1000L))

#define MILLISECONDS(milli) \
(((signed __int64)(milli)) * MICROSECONDS(1000L))

#define SECONDS(seconds) \
(((signed __int64)(seconds)) * MILLISECONDS(1000L))

#define CALLOUT_ENABLE_INTERRUPT_FLAG (0x200)

#define KE_SUCCESS(Status) (((ULONG64)(Status)) >= 0)

typedef enum _MI_VAD_TYPE
{
    VadNone,
    VadDevicePhysicalMemory,
    VadImageMap,
    VadAwe,
    VadWriteWatch,
    VadLargePages,
    VadRotatePhysical,
    VadLargePageSection
} MI_VAD_TYPE, * PMI_VAD_TYPE;

typedef struct _MEMORY_DATA
{
	ULONG pId;
	ULONG Size;
	ULONGLONG Address;
	ULONGLONG Data;
	ULONG64 status;
}MEMORY_DATA, *PMEMORY_DATA;


#pragma warning(disable : 4214 4201)
#pragma pack(push, 1)

typedef struct _MMPTE_HARDWARE64
{
    ULONG64 Valid : 1;
    ULONG64 Dirty1 : 1;
    ULONG64 Owner : 1;
    ULONG64 WriteThrough : 1;
    ULONG64 CacheDisable : 1;
    ULONG64 Accessed : 1;
    ULONG64 Dirty : 1;
    ULONG64 LargePage : 1;
    ULONG64 Global : 1;
    ULONG64 CopyOnWrite : 1;
    ULONG64 Prototype : 1;
    ULONG64 Write : 1;
    ULONG64 PageFrameNumber : 36;
    ULONG64 Reserved1 : 4;
    ULONG64 SoftwareWsIndex : 11;
    ULONG64 NoExecute : 1;
} MMPTE_HARDWARE64, * PMMPTE_HARDWARE64;

typedef struct _MMPTE_SOFTWARE_PAE {
    ULONGLONG Valid : 1;
    ULONGLONG PageFileLow : 4;
    ULONGLONG Protection : 5;
    ULONGLONG Prototype : 1;
    ULONGLONG Transition : 1;
    ULONGLONG Unused : 20;
    ULONGLONG PageFileHigh : 32;
} MMPTE_SOFTWARE_PAE;

typedef struct _MMPTE
{
    union {
        ULONG64 Long;
        MMPTE_HARDWARE64 Hard;
        MMPTE_SOFTWARE_PAE Soft;
    } u;
} MMPTE, * PMMPTE;

typedef struct _MM_AVL_NODE // Size=24
{
    struct _MM_AVL_NODE* LeftChild; // Size=8 Offset=0
    struct _MM_AVL_NODE* RightChild; // Size=8 Offset=8

    union ___unnamed1666 // Size=8
    {
        struct
        {
            __int64 Balance : 2; // Size=8 Offset=0 BitOffset=0 BitCount=2
        };
        struct _MM_AVL_NODE* Parent; // Size=8 Offset=0
    } u1;
} MM_AVL_NODE, * PMM_AVL_NODE, * PMMADDRESS_NODE;

typedef struct _RTL_AVL_TREE // Size=8
{
    PMM_AVL_NODE BalancedRoot;
    void* NodeHint;
    unsigned __int64 NumberGenericTableElements;
} RTL_AVL_TREE, * PRTL_AVL_TREE, MM_AVL_TABLE, * PMM_AVL_TABLE;

union _EX_PUSH_LOCK // Size=8
{
    struct
    {
        unsigned __int64 Locked : 1; // Size=8 Offset=0 BitOffset=0 BitCount=1
        unsigned __int64 Waiting : 1; // Size=8 Offset=0 BitOffset=1 BitCount=1
        unsigned __int64 Waking : 1; // Size=8 Offset=0 BitOffset=2 BitCount=1
        unsigned __int64 MultipleShared : 1; // Size=8 Offset=0 BitOffset=3 BitCount=1
        unsigned __int64 Shared : 60; // Size=8 Offset=0 BitOffset=4 BitCount=60
    };
    unsigned __int64 Value; // Size=8 Offset=0
    void* Ptr; // Size=8 Offset=0
};

union _MMVAD_FLAGS // Size=4
{
    struct
    {
        unsigned long VadType : 3; // Size=4 Offset=0 BitOffset=0 BitCount=3
        unsigned long Protection : 5; // Size=4 Offset=0 BitOffset=3 BitCount=5
        unsigned long PreferredNode : 6; // Size=4 Offset=0 BitOffset=8 BitCount=6
        unsigned long NoChange : 1; // Size=4 Offset=0 BitOffset=14 BitCount=1
        unsigned long PrivateMemory : 1; // Size=4 Offset=0 BitOffset=15 BitCount=1
        unsigned long Teb : 1; // Size=4 Offset=0 BitOffset=16 BitCount=1
        unsigned long PrivateFixup : 1; // Size=4 Offset=0 BitOffset=17 BitCount=1
        unsigned long ManySubsections : 1; // Size=4 Offset=0 BitOffset=18 BitCount=1
        unsigned long Spare : 12; // Size=4 Offset=0 BitOffset=19 BitCount=12
        unsigned long DeleteInProgress : 1; // Size=4 Offset=0 BitOffset=31 BitCount=1
    }u81_10;

    struct
    {
        unsigned long Lock : 1;
        unsigned long LockContended : 1;
        unsigned long DeleteInProgress : 1;
        unsigned long NoChange : 1;
        unsigned long VadType : 3;
        unsigned long Protection : 5;
        unsigned long PreferredNode : 6;
        unsigned long PageSize : 2;
        unsigned long PrivateMemory : 1;
    }uNew10;
};

struct _MMVAD_FLAGS1 // Size=4
{
    unsigned long CommitCharge : 31; // Size=4 Offset=0 BitOffset=0 BitCount=31
    unsigned long MemCommit : 1; // Size=4 Offset=0 BitOffset=31 BitCount=1
};

struct _MMVAD_FLAGS2 // Size=4
{
    unsigned long FileOffset : 24; // Size=4 Offset=0 BitOffset=0 BitCount=24
    unsigned long Large : 1; // Size=4 Offset=0 BitOffset=24 BitCount=1
    unsigned long TrimBehind : 1; // Size=4 Offset=0 BitOffset=25 BitCount=1
    unsigned long Inherit : 1; // Size=4 Offset=0 BitOffset=26 BitCount=1
    unsigned long CopyOnWrite : 1; // Size=4 Offset=0 BitOffset=27 BitCount=1
    unsigned long NoValidationNeeded : 1; // Size=4 Offset=0 BitOffset=28 BitCount=1
    unsigned long Spare : 3; // Size=4 Offset=0 BitOffset=29 BitCount=3
};

struct _MI_VAD_SEQUENTIAL_INFO // Size=8
{
    unsigned __int64 Length : 12; // Size=8 Offset=0 BitOffset=0 BitCount=12
    unsigned __int64 Vpn : 52; // Size=8 Offset=0 BitOffset=12 BitCount=52
};

union ___unnamed1951 // Size=4
{
    unsigned long LongFlags; // Size=4 Offset=0
    union _MMVAD_FLAGS VadFlags; // Size=4 Offset=0
};

union ___unnamed1952 // Size=4
{
    unsigned long LongFlags1; // Size=4 Offset=0
    struct _MMVAD_FLAGS1 VadFlags1; // Size=4 Offset=0
};

typedef struct _MMVAD_SHORT // Size=64
{
    union
    {
        struct _RTL_BALANCED_NODE VadNode; // Size=24 Offset=0
        struct _MMVAD_SHORT* NextVad; // Size=8 Offset=0
    };
    unsigned long StartingVpn; // Size=4 Offset=24
    unsigned long EndingVpn; // Size=4 Offset=28
    unsigned char StartingVpnHigh; // Size=1 Offset=32
    unsigned char EndingVpnHigh; // Size=1 Offset=33
    unsigned char CommitChargeHigh; // Size=1 Offset=34
    unsigned char SpareNT64VadUChar; // Size=1 Offset=35
    long ReferenceCount; // Size=4 Offset=36
    union _EX_PUSH_LOCK PushLock; // Size=8 Offset=40
    union ___unnamed1951 u; // Size=4 Offset=48
    union ___unnamed1952 u1; // Size=4 Offset=52
    struct _MI_VAD_EVENT_BLOCK* EventList; // Size=8 Offset=56
} MMVAD_SHORT, * PMMVAD_SHORT;

#pragma pack(pop)
#pragma warning(default : 4214 4201)

#define GET_VAD_ROOT(Table) Table->BalancedRoot

PPEB PsGetProcessPeb(PEPROCESS);
PVOID PsGetProcessSectionBaseAddress(PEPROCESS);
NTSYSAPI
PIMAGE_NT_HEADERS
NTAPI
RtlImageNtHeader(PVOID Base);

typedef struct _REQUEST
{
	UINT32 Type;
	PVOID Instruction;
} REQUEST, * PREQUEST;

typedef struct _MAPUSER_MEMORY
{
	ULONG64 MapMemory;
	ULONG64 FunctionHook;
	ULONG64 size;
	ULONG pid;
	ULONG status;
}MAPUSER_MEMORY, * PMAPUSER_MEMORY;


typedef struct _KAFFINITY_EX
{
    UINT16    Count;
    UINT16    Size;
    UINT32    Reserved;
    UINT64    Bitmap[20];
} KAFFINITY_EX;
typedef KAFFINITY_EX* PKAFFINITY_EX;
typedef KAFFINITY_EX const* PCKAFFINITY_EX;

BOOLEAN KeInterlockedSetProcessorAffinityEx(PKAFFINITY_EX, ULONG);

EXTERN_C NTSTATUS NtQuerySystemInformationEx(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

typedef struct _SYSTEM_BIGPOOL_ENTRY
{
    union
    {
        PVOID VirtualAddress;
        ULONG_PTR NonPaged : 1;
    }u;
    ULONG_PTR SizeInBytes;
    union
    {
        UCHAR Tag[4];
        ULONG TagUlong;
    }u1;
} SYSTEM_BIGPOOL_ENTRY, * PSYSTEM_BIGPOOL_ENTRY;

typedef struct _SYSTEM_BIGPOOL_INFORMATION
{
    ULONG Count;
    SYSTEM_BIGPOOL_ENTRY AllocatedInfo[ANYSIZE_ARRAY];
} SYSTEM_BIGPOOL_INFORMATION, * PSYSTEM_BIGPOOL_INFORMATION;

#pragma warning(disable : 4201)
typedef struct _MOUSE_INPUT_DATA
{
    USHORT UnitId;
    USHORT Flags;
    union
    {
        ULONG Buttons;
        struct
        {
            USHORT ButtonFlags;
            USHORT ButtonData;
        };
    };
    ULONG  RawButtons;
    LONG   LastX;
    LONG   LastY;
    ULONG  ExtraInformation;
} MOUSE_INPUT_DATA, * PMOUSE_INPUT_DATA;
#pragma warning(default : 4201)

typedef VOID(*MouseClassServiceCallbackFn)(PDEVICE_OBJECT DeviceObject, PMOUSE_INPUT_DATA InputDataStart, PMOUSE_INPUT_DATA InputDataEnd, PULONG InputDataConsumed);
NTSTATUS ObReferenceObjectByName(PUNICODE_STRING, ULONG, PACCESS_STATE, ACCESS_MASK, POBJECT_TYPE, KPROCESSOR_MODE, PVOID, PVOID*);
NTKERNELAPI PVOID PsGetCurrentThreadStackBase();

NTSYSAPI
_Success_(return != 0)
USHORT
NTAPI
RtlCaptureStackBackTrace(
    _In_ ULONG FramesToSkip,
    _In_ ULONG FramesToCapture,
    _Out_writes_to_(FramesToCapture, return) PVOID* BackTrace,
    _Out_opt_ PULONG BackTraceHash
);

NTSYSAPI
VOID
NTAPI
RtlCaptureContext(
    _Out_ PCONTEXT ContextRecord
);

typedef struct _MOUSE_OBJECT
{
    PDEVICE_OBJECT MouseDevice;
    MouseClassServiceCallbackFn ServiceCallback;
} MOUSE_OBJECT, * PMOUSE_OBJECT;

typedef struct _MOUSE_DATA
{
    LONG x;
    LONG y;
    USHORT Flags;
}MOUSE_DATA, * PMOUSE_DATA;

#define WPP_FLAG_ALL (0xFFFFFFFFFFFFFFFF)

typedef VOID(*WPP_FILTER)(PCONTEXT, PVOID, PVOID, PVOID);

typedef struct _WPP 
{
    PVOID ReturnAddress;
    WPP_FILTER Filter;
    PDEVICE_OBJECT* WppGlobal;
    PDEVICE_OBJECT WppGlobalOriginal;
    PVOID* WppTraceMessage;
    PVOID WppTraceMessageOriginal;
} WPP, * PWPP;


typedef struct _GET_USERMODULE_IN_PROCESS
{
    ULONG pid;
    ULONG64 BaseAddress;
    ULONG64 ProcessPeb;
    ULONG64 ProcessCr3;
} GET_USERMODULE_IN_PROCESS;


typedef struct _KM_READ_REQUEST
{
    ULONG64 Cr3;
    UINT_PTR SourceAddress;
    ULONGLONG Size;
    PVOID Output;
} KM_READ_REQUEST;

typedef struct _KM_WRITE_REQUEST
{
    ULONG64 Cr3;
    UINT_PTR SourceAddress;
    ULONGLONG Size;
    UINT_PTR TargetAddress;
} KM_WRITE_REQUEST;

typedef struct _KM_CODE_REQUEST
{
    ULONG64 ComunKey;
    ULONG SubKey;
} KM_CODE_REQUEST;

typedef struct _GLOBAL_DATA
{
    ULONG64 RetInstruction;
    ULONG64 RopGadgetAddress;
    ULONG64 StartThreadAddress;
    ULONG StartAddressOffset;
    ULONG Win32StartAddressOffset;

    ULONG64 PteBase;
    ULONG64 MiSystemPartition;
    ULONG64 MiGetPage;
    ULONG64 MiRemovePhysicalMemory;
    ULONG64 MiSystemPteInfo;
    ULONG64 MiReservePtes;

    PVOID SharedSection;
    HANDLE SectionHandle;
    HANDLE SharedEventHandleData;
    HANDLE SharedEventHandleTrigger;
    HANDLE SharedEventHandleMem;
    HANDLE SharedEventHandleWaiit;

    PKEVENT SharedEventData;
    PKEVENT SharedEventTrigger;
    PKEVENT SharedEventMem;
    PKEVENT SharedEventWaiit;

    ULONG64 MdlMap;
    ULONG64 MdlData;
    ULONG64 KeAcquireSpinLockAtDpcLevel;
    ULONG64 KeReleaseSpinLockFromDpcLevel;
    ULONG64 IofCompleteRequest;
    ULONG64 IoReleaseRemoveLockEx;
    PSE_EXPORTS SeExports;
    POBJECT_TYPE* IoDriverObjectType;
	decltype(&MmIsAddressValid) MmIsAddressValid;
    decltype(&ExAllocatePoolWithTag) ExAllocatePoolWithTag;
    decltype(&ExFreePoolWithTag) ExFreePoolWithTag;
	decltype(&PsLookupProcessByProcessId) PsLookupProcessByProcessId;
	decltype(&ObfDereferenceObject) ObfDereferenceObject;
    decltype(&memcpy) memcpy;
    decltype(&memset) memset;
    decltype(&strcmp) strcmp;
    decltype(&MmCopyMemory) MmCopyMemory;
    decltype(&MmMapIoSpaceEx) MmMapIoSpaceEx;
    decltype(&MmUnmapIoSpace) MmUnmapIoSpace;
    decltype(&PsGetProcessPeb) PsGetProcessPeb;
    decltype(&PsGetProcessSectionBaseAddress) PsGetProcessSectionBaseAddress;
    decltype(&ObReferenceObjectByName) ObReferenceObjectByName;

    decltype(&ObReferenceObjectByHandle) ObReferenceObjectByHandle;
    decltype(&ObGetObjectSecurity) ObGetObjectSecurity;
    decltype(&ObReleaseObjectSecurity) ObReleaseObjectSecurity;

    decltype(&RtlInitUnicodeString) RtlInitUnicodeString;
    decltype(&KfRaiseIrql) KfRaiseIrql;
    decltype(&KeLowerIrql) KeLowerIrql;
    decltype(&RtlCreateSecurityDescriptor) RtlCreateSecurityDescriptor;
    decltype(&RtlLengthSid) RtlLengthSid;
    decltype(&RtlCreateAcl) RtlCreateAcl;
    decltype(&RtlAddAccessAllowedAce) RtlAddAccessAllowedAce;
    decltype(&RtlSetDaclSecurityDescriptor) RtlSetDaclSecurityDescriptor;
    decltype(&ZwOpenSection) ZwOpenSection;
    decltype(&ZwCreateSection) ZwCreateSection;
    decltype(&ZwMapViewOfSection) ZwMapViewOfSection;
    decltype(&ZwUnmapViewOfSection) ZwUnmapViewOfSection;
    decltype(&ZwClose) ZwClose; 
    decltype(&IoCreateNotificationEvent) IoCreateNotificationEvent; 
    decltype(&PsCreateSystemThread) PsCreateSystemThread;
    decltype(&KeSetEvent) KeSetEvent;
    decltype(&KeResetEvent) KeResetEvent;
    decltype(&KeDelayExecutionThread) KeDelayExecutionThread;
	decltype(&DbgPrintEx) DbgPrintEx;
    ULONG KavShadow;
    ULONG RandomPool;
} GLOBAL_DATA, *PGLOBAL_DATA;

EXTERN_C PGLOBAL_DATA GlobalData;

EXTERN_C PVOID CalloutInterrupt(PVOID, PVOID, size_t, size_t, PVOID, PVOID, PVOID, PVOID, ...);
