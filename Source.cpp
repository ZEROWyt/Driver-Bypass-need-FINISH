#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <Ntstrsafe.h>
#include <intrin.h>
#include "Header.h"
#include <fltKernel.h>


#pragma data_seg(push, stack1, ".data")
EXTERN_C PGLOBAL_DATA GlobalData = nullptr;
EXTERN_C ULONG64 RetInstruction = 0;
EXTERN_C PVOID RopGadgetAddress = NULL;
EXTERN_C ULONG64 InterruptedThread = 0;
EXTERN_C PVOID PreservedStack = NULL;
EXTERN_C PVOID TeamRead = NULL;
#pragma data_seg(pop,  stack1)

template<typename Ret, typename A1 = PVOID, typename A2 = PVOID, typename A3 = PVOID, typename A4 = PVOID, typename... Stack>
Ret CallSpoofed(PVOID Func, A1 a1 = A1{}, A2 a2 = A2{}, A3 a3 = A3{}, A4 a4 = A4{}, Stack... args)
{
	//if (InterruptedThread == __readgsqword(0x188) && RopGadgetAddress != 0)
	//{
	//	return (Ret)(CalloutInterrupt(Func, PreservedStack, sizeof...(Stack), CALLOUT_ENABLE_INTERRUPT_FLAG, (PVOID)a1, (PVOID)a2, (PVOID)a3, (PVOID)a4, args...));
	//}
	return ((Ret(__fastcall*)(...))Func)(a1, a2, a3, a4, args...);
}

#define PRINT_DBG(format, ...) CallSpoofed<VOID>(GlobalData->DbgPrintEx, DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)

BOOLEAN ReadPhysicalAddress(PVOID Va, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesRead)
{
	MM_COPY_ADDRESS Pa = {};
	Pa.PhysicalAddress.QuadPart = (ULONG64)(Va);
	ULONG64 Status = CallSpoofed<ULONG64>(GlobalData->MmCopyMemory, lpBuffer, &Pa, Size, (ULONG)MM_COPY_MEMORY_PHYSICAL, (PVOID)BytesRead);
	PRINT_DBG("Status: 0x%X\n", Status);
	if (Status != STATUS_SUCCESS)
		return FALSE;

	return TRUE;
}

BOOLEAN ReadPhysicalAddressEx(PVOID TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesRead)
{
	if (!TargetAddress)
		return FALSE;

	PHYSICAL_ADDRESS Va = {};
	Va.QuadPart = (ULONG64)(TargetAddress);
	PVOID pmapped_mem = CallSpoofed<PVOID>(GlobalData->MmMapIoSpaceEx, (PVOID)(PHYSICAL_ADDRESS(Va), Size, (ULONG)PAGE_READWRITE));
	if (!pmapped_mem)
	{
		PRINT_DBG("pmapped_mem: 0x%p\n", pmapped_mem);
		return FALSE;
	}
	CallSpoofed<PVOID>(GlobalData->memcpy, lpBuffer, pmapped_mem, Size);
	*BytesRead = Size;
	CallSpoofed<VOID>(GlobalData->MmUnmapIoSpace, pmapped_mem, Size);
	return TRUE;
}

BOOLEAN WritePhysicalAddress(PVOID TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesWritten)
{
	if (!TargetAddress)
		return FALSE;

	PHYSICAL_ADDRESS Va = {};
	Va.QuadPart = (ULONG64)(TargetAddress);
	PVOID pmapped_mem = CallSpoofed<PVOID>(GlobalData->MmMapIoSpaceEx, (PVOID)(PHYSICAL_ADDRESS(Va), Size, (ULONG)PAGE_READWRITE));
	if (!pmapped_mem)
		return FALSE;

	CallSpoofed<PVOID>(GlobalData->memcpy, pmapped_mem, lpBuffer, Size);
	*BytesWritten = Size;
	CallSpoofed<VOID>(GlobalData->MmUnmapIoSpace, pmapped_mem, Size);
	return TRUE;
}

ULONG64 GetLinearAddress(ULONG64 Cr3, ULONG64 Va)
{
	Cr3 &= ~0xf;
	ULONG64 pageOffset = Va & ~(~0ul << PAGE_SHIFT);
	ULONG64 pte = ((Va >> 12) & (0x1ffll));
	ULONG64 pt = ((Va >> 21) & (0x1ffll));
	ULONG64 pd = ((Va >> 30) & (0x1ffll));
	ULONG64 pdp = ((Va >> 39) & (0x1ffll));

	SIZE_T readsize = 0;
	ULONG64 pdpe = 0;
	ReadPhysicalAddress((PVOID)(Cr3 + 8 * pdp), &pdpe, sizeof(pdpe), &readsize);
	if (~pdpe & 1)
		return 0;

	ULONG64 pde = 0;
	ReadPhysicalAddress((PVOID)((pdpe & (~0xfull << 8) & 0xfffffffffull) + 8 * pd), &pde, sizeof(pde), &readsize);
	if (~pde & 1)
		return 0;

	if (pde & 0x80)
		return (pde & (~0ull << 42 >> 12)) + (Va & ~(~0ull << 30));

	ULONG64 pteAddr = 0;
	ReadPhysicalAddress((PVOID)((pde & (~0xfull << 8) & 0xfffffffffull) + 8 * pt), &pteAddr, sizeof(pteAddr), &readsize);
	if (~pteAddr & 1)
		return 0;

	if (pteAddr & 0x80)
		return (pteAddr & (~0xfull << 8) & 0xfffffffffull) + (Va & ~(~0ull << 21));

	Va = 0;
	ReadPhysicalAddress((PVOID)((pteAddr & (~0xfull << 8) & 0xfffffffffull) + 8 * pte), &Va, sizeof(Va), &readsize);
	Va &= (~0xfull << 8) & 0xfffffffffull;
	if (!Va)
		return 0;

	return Va + pageOffset;
}

BOOLEAN ReadProcessMemory(ULONG64 Cr3, ULONG64 Address, PVOID Data, ULONGLONG Size)
{
	BOOLEAN Returns = FALSE;

	SIZE_T CurOffset = 0;
	SIZE_T TotalSize = Size;
	while (TotalSize)
	{
		ULONG64 CurPhysAddr = GetLinearAddress(Cr3, (ULONG64)Address + CurOffset);
		if (!CurPhysAddr)
		{
			PRINT_DBG("CurPhysAddr: 0x%p\n", CurPhysAddr);
			return FALSE;
		}
		SIZE_T BytesRead = 0;
		ULONG64 ReadSize = min(PAGE_SIZE - (CurPhysAddr & 0xFFF), TotalSize);
		Returns = ReadPhysicalAddressEx((PVOID)(CurPhysAddr), (PVOID)((ULONG64)Data + CurOffset), ReadSize, &BytesRead);
		TotalSize -= BytesRead;
		CurOffset += BytesRead;
		if (Returns != TRUE)
			break;

		if (BytesRead == 0)
			break;
	}
	return Returns;
}

BOOLEAN WriteProcessMemory(ULONG64 Cr3, ULONG64 Address, PVOID Data, ULONGLONG Size)
{
	BOOLEAN Returns = FALSE;
	SIZE_T CurOffset = 0;
	SIZE_T TotalSize = Size;
	while (TotalSize)
	{
		ULONG64 CurPhysAddr = GetLinearAddress(Cr3, (ULONG64)Address + CurOffset);
		if (!CurPhysAddr)
			return FALSE;

		SIZE_T BytesWritten = 0;
		ULONG64 WriteSize = min(PAGE_SIZE - (CurPhysAddr & 0xFFF), TotalSize);
		Returns = WritePhysicalAddress((PVOID)CurPhysAddr, (PVOID)((ULONG64)Data + CurOffset), WriteSize, &BytesWritten);
		TotalSize -= BytesWritten;
		CurOffset += BytesWritten;
		if (Returns != TRUE)
			break;
	}
	return Returns;
}

VOID UpdateSharedMemory()
{
	if (GlobalData->SharedSection)
	{
		CallSpoofed<VOID>(GlobalData->ZwUnmapViewOfSection, NtCurrentProcess(), GlobalData->SharedSection);
		GlobalData->SharedSection = nullptr;
	}

	SIZE_T ulViewSize = 0x4000;
	ULONG64 ntStatus = CallSpoofed<ULONG64>(GlobalData->ZwMapViewOfSection, (HANDLE)GlobalData->SectionHandle, (HANDLE)NtCurrentProcess(), (PVOID*)&GlobalData->SharedSection, (ULONG64)(0), ulViewSize, (PLARGE_INTEGER)NULL, &ulViewSize, ViewShare, (ULONG)0, ULONG(PAGE_READWRITE | PAGE_NOCACHE));
	if (ntStatus != STATUS_SUCCESS)
	{
		CallSpoofed<VOID>(GlobalData->ZwClose, GlobalData->SectionHandle);
		return;
	}
}

NTSTATUS CreateAsyncEvent()
{
	UNICODE_STRING EventNameData{};
	CallSpoofed<VOID>(GlobalData->RtlInitUnicodeString, &EventNameData, L"\\BaseNamedObjects\\EventData");
	GlobalData->SharedEventData = CallSpoofed<PKEVENT>(GlobalData->IoCreateNotificationEvent, &EventNameData, &GlobalData->SharedEventHandleData);
	if (GlobalData->SharedEventData == nullptr)
		return STATUS_UNSUCCESSFUL;
	
	UNICODE_STRING EventNameTrigger{};
	CallSpoofed<VOID>(GlobalData->RtlInitUnicodeString, &EventNameTrigger, L"\\BaseNamedObjects\\EventTiger");
	GlobalData->SharedEventTrigger = CallSpoofed<PKEVENT>(GlobalData->IoCreateNotificationEvent, &EventNameTrigger, &GlobalData->SharedEventHandleTrigger);
	if (GlobalData->SharedEventTrigger == nullptr)
		return STATUS_UNSUCCESSFUL;

	UNICODE_STRING EventNameMem{};
	CallSpoofed<VOID>(GlobalData->RtlInitUnicodeString, &EventNameMem, L"\\BaseNamedObjects\\EventMem");
	GlobalData->SharedEventMem = CallSpoofed<PKEVENT>(GlobalData->IoCreateNotificationEvent, &EventNameMem, &GlobalData->SharedEventHandleMem);
	if (GlobalData->SharedEventMem == nullptr)
		return STATUS_UNSUCCESSFUL;

	PRINT_DBG("AsyncEvent Success!\n");
	return STATUS_SUCCESS;
}

int mstrcmp(const char* s1, const char* s2)
{
	while (*s1 == *s2++)
	{
		if (*s1++ == 0)
			return (0);
	}
	return (*(unsigned char*)s1 - *(unsigned char*)--s2);
}

VOID SleepKe(ULONG ms)
{
	LARGE_INTEGER Timeout{};
	Timeout.QuadPart = RELATIVE(MILLISECONDS(ms));
	CallSpoofed<VOID>(GlobalData->KeDelayExecutionThread, KernelMode, FALSE, &Timeout);
}

VOID WaitGame(PVOID StartContext, PVOID StackPreserve)
{
	UNREFERENCED_PARAMETER(StartContext);
	//UNREFERENCED_PARAMETER(StackPreserve);

	ULONG64 CurrentThread = __readgsqword(0x188);

	//KeGetCurrentPrcb();

	InterruptedThread = CurrentThread;
	PreservedStack = StackPreserve;

	*(ULONG64*)((ULONG64)CurrentThread + GlobalData->StartAddressOffset) = GlobalData->StartThreadAddress;
	*(ULONG64*)((ULONG64)CurrentThread + GlobalData->Win32StartAddressOffset) = GlobalData->StartThreadAddress;

	OBJECT_ATTRIBUTES ObjAttr{};
	UNICODE_STRING sectionName{};
	CallSpoofed<VOID>(GlobalData->RtlInitUnicodeString, &sectionName, L"\\BaseNamedObjects\\WdMemEx");
	InitializeObjectAttributes(&ObjAttr, &sectionName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

ReplayThread:
	GlobalData->SectionHandle = 0;
	PRINT_DBG("Start :)\n");

	while (true)
	{
		ULONG64 Status = CallSpoofed<ULONG64>(GlobalData->ZwOpenSection, (PVOID*)&GlobalData->SectionHandle, SECTION_ALL_ACCESS, &ObjAttr);
		if(Status != STATUS_SUCCESS)
			continue;

		if (GlobalData->SectionHandle != 0 && Status == STATUS_SUCCESS)
			break;
		
		SleepKe(10000);
	}

	if (!NT_SUCCESS(CreateAsyncEvent()))
		return;

	SleepKe(100);

	while (TRUE)
	{
		//Mutex
		if (!GlobalData->SectionHandle)
			continue;

		UpdateSharedMemory();

		if (!GlobalData->SharedSection)
			continue;

		if((PCHAR)GlobalData->SharedSection == NULL)
			continue;

		while (!(PCHAR)GlobalData->SharedSection == NULL && CallSpoofed<ULONG64>(GlobalData->strcmp, (PCHAR)GlobalData->SharedSection, "TheEnd") == 0)
		{
			if (GlobalData->SharedSection)
			{
				CallSpoofed<VOID>(GlobalData->ZwUnmapViewOfSection, NtCurrentProcess(), GlobalData->SharedSection);
				GlobalData->SharedSection = nullptr;
				CallSpoofed<VOID>(GlobalData->ZwClose, GlobalData->SectionHandle);
				PRINT_DBG("TheEnd(:\n");
			}
			goto ReplayThread;
		}
		while (!(PCHAR)GlobalData->SharedSection == NULL && CallSpoofed<ULONG64>(GlobalData->strcmp, (PCHAR)GlobalData->SharedSection, "InfPro") == 0)
		{
			CallSpoofed<VOID>(GlobalData->KeSetEvent, GlobalData->SharedEventData, KPRIORITY(0), BOOLEAN(FALSE));
			//SleepKe(1);
			UpdateSharedMemory();
			GET_USERMODULE_IN_PROCESS UserModeData{};
			CallSpoofed<VOID>(GlobalData->memcpy, (PVOID)&UserModeData, (PVOID)GlobalData->SharedSection, (SIZE_T)sizeof(GET_USERMODULE_IN_PROCESS));

			PEPROCESS TargetProcess = nullptr;
			ULONG64 Status = CallSpoofed<ULONG64>(GlobalData->PsLookupProcessByProcessId, (HANDLE)UserModeData.pid, (PEPROCESS)&TargetProcess);
			if (Status == STATUS_SUCCESS)
			{
				UserModeData.BaseAddress = (ULONG64)CallSpoofed<ULONG64>(GlobalData->PsGetProcessSectionBaseAddress, TargetProcess);
				UserModeData.ProcessPeb = (ULONG64)CallSpoofed<ULONG64>(GlobalData->PsGetProcessPeb, TargetProcess);
				ULONG64 ProcessDirbase = 0;
				CallSpoofed<VOID>(GlobalData->memcpy, &ProcessDirbase, PVOID((PUCHAR)TargetProcess + 0x28), sizeof(ULONG64));
				if (ProcessDirbase == 0)
					CallSpoofed<VOID>(GlobalData->memcpy, &ProcessDirbase, PVOID((PUCHAR)TargetProcess + GlobalData->KavShadow), sizeof(ULONG64));

				UserModeData.ProcessCr3 = ProcessDirbase;
				CallSpoofed<VOID>(GlobalData->ObfDereferenceObject, TargetProcess);
			}

			UpdateSharedMemory();
			CallSpoofed<VOID>(GlobalData->memcpy, GlobalData->SharedSection, &UserModeData, sizeof(GET_USERMODULE_IN_PROCESS));
			CallSpoofed<VOID>(GlobalData->KeSetEvent, GlobalData->SharedEventMem, KPRIORITY(0), BOOLEAN(FALSE));
			CallSpoofed<VOID>(GlobalData->KeResetEvent, GlobalData->SharedEventData);
			CallSpoofed<VOID>(GlobalData->KeResetEvent, GlobalData->SharedEventMem);
			break;
		}
		while (!(PCHAR)GlobalData->SharedSection == NULL && CallSpoofed<ULONG64>(GlobalData->strcmp, (PCHAR)GlobalData->SharedSection, "Read") == 0)
		{
			CallSpoofed<VOID>(GlobalData->KeSetEvent, GlobalData->SharedEventData, KPRIORITY(0), BOOLEAN(FALSE));
			UpdateSharedMemory();

			KM_READ_REQUEST ReadInput{};
			CallSpoofed<VOID>(GlobalData->memcpy, &ReadInput, (PVOID)GlobalData->SharedSection, sizeof(KM_READ_REQUEST));

			PRINT_DBG("Cr3: %p\n", ReadInput.Cr3);
			PRINT_DBG("SourceAddress: %p\n", ReadInput.SourceAddress);
			PRINT_DBG("Size: %p\n", ReadInput.Size);

			if (!ReadProcessMemory(ReadInput.Cr3, ReadInput.SourceAddress, TeamRead, ReadInput.Size))
			{
				CallSpoofed<VOID>(GlobalData->KeSetEvent, GlobalData->SharedEventMem, KPRIORITY(0), BOOLEAN(FALSE));
				CallSpoofed<VOID>(GlobalData->KeResetEvent, GlobalData->SharedEventData);
				CallSpoofed<VOID>(GlobalData->KeResetEvent, GlobalData->SharedEventMem);
				CallSpoofed<VOID>(GlobalData->KeSetEvent, GlobalData->SharedEventTrigger, KPRIORITY(0), BOOLEAN(FALSE));
				PRINT_DBG("Fail\n");
				break;
			}
			PRINT_DBG("ReadOutput: %p\n", TeamRead);
			ReadInput.Output = TeamRead;

			UpdateSharedMemory();

			CallSpoofed<VOID>(GlobalData->memcpy, GlobalData->SharedSection, &ReadInput, sizeof(KM_READ_REQUEST));

			CallSpoofed<VOID>(GlobalData->KeSetEvent, GlobalData->SharedEventMem, KPRIORITY(0), BOOLEAN(FALSE));
			CallSpoofed<VOID>(GlobalData->KeResetEvent, GlobalData->SharedEventData);
			CallSpoofed<VOID>(GlobalData->KeResetEvent, GlobalData->SharedEventMem);
			CallSpoofed<VOID>(GlobalData->KeSetEvent, GlobalData->SharedEventTrigger, KPRIORITY(0), BOOLEAN(FALSE));
			break;
		}
		while (!(PCHAR)GlobalData->SharedSection == NULL && CallSpoofed<ULONG64>(GlobalData->strcmp, (PCHAR)GlobalData->SharedSection, "Write") == 0)
		{
			CallSpoofed<VOID>(GlobalData->KeSetEvent, GlobalData->SharedEventData, 0, FALSE);
			//SleepKe(1);
			UpdateSharedMemory();

			KM_WRITE_REQUEST WriteInput{};
			CallSpoofed<VOID>(GlobalData->memcpy, (PVOID)&WriteInput, (PVOID)GlobalData->SharedSection, (SIZE_T)sizeof(KM_WRITE_REQUEST));
			if (!WriteProcessMemory(WriteInput.Cr3, WriteInput.SourceAddress, (PVOID)WriteInput.TargetAddress, WriteInput.Size))
			{
				CallSpoofed<VOID>(GlobalData->KeResetEvent, GlobalData->SharedEventData);
				continue;
			}
			CallSpoofed<VOID>(GlobalData->KeResetEvent, GlobalData->SharedEventData);
			CallSpoofed<VOID>(GlobalData->KeSetEvent, GlobalData->SharedEventTrigger, 0, FALSE);
			break;
		}

		//Mutex
		SleepKe(1);
	}
}

PVOID MmAllocateIndependentPages(ULONG PageCount)
{
	MMPTE* PTE = CallSpoofed<MMPTE*>((PVOID)GlobalData->MiReservePtes, (PVOID)GlobalData->MiSystemPteInfo, PageCount);
	if (!PTE) 
		return nullptr;

#define PTE_SHIFT 3
#define VA_SHIFT (63 - 47)
#define MiGetVirtualAddressMappedByPte(PTE) ((PVOID)((LONG_PTR)(((LONG_PTR)(PTE) - GlobalData->PteBase) << (PAGE_SHIFT + VA_SHIFT - PTE_SHIFT)) >> VA_SHIFT))
	auto VA = MiGetVirtualAddressMappedByPte(PTE);

	for (SIZE_T i = 0; i < PageCount; i++)
	{
	NewTry:
		auto PFN = CallSpoofed<ULONG64>((PVOID)GlobalData->MiGetPage, (PVOID)GlobalData->MiSystemPartition, 0ull, 8ull);
		if (PFN == -1) 
			goto NewTry;

		ULONG64 PfnSize = 0x1000; PfnSize = PfnSize >> 12;
		CallSpoofed<VOID>((PVOID)GlobalData->MiRemovePhysicalMemory, PFN, PfnSize);
		PTE->u.Hard.Valid = 1;
		PTE->u.Hard.Owner = 0;
		PTE->u.Hard.Write = 1;
		PTE->u.Hard.NoExecute = 0;
		PTE->u.Hard.PageFrameNumber = PFN;
		++PTE;
	}
	return VA;
}

void InitializeThread()
{
	UCHAR ThreadStartShellcode[26] = { 0xFA, 0x48, 0x89, 0xE2, 0x48, 0xBC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0 };
	UCHAR* ShellcodeBase = (UCHAR*)GlobalData->ExAllocatePoolWithTag(NonPagedPool, sizeof(ThreadStartShellcode), GlobalData->RandomPool);
	if (!ShellcodeBase)
		return;

	GlobalData->memcpy(ShellcodeBase, &ThreadStartShellcode[0], sizeof(ThreadStartShellcode));

	SIZE_T StackSize = 0x1000 * 16;
	auto RealStack = (ULONG64)MmAllocateIndependentPages(16);
	if (!RealStack)
	{
		PRINT_DBG("Error1\n");
		return;
	}
	
	GlobalData->memset((PVOID)RealStack, 0, StackSize);
	*(ULONG64*)(&ShellcodeBase[6])    = (ULONG64)(RealStack + StackSize - 0x28);
	*(ULONG64*)(&ShellcodeBase[0x10]) = (ULONG64)WaitGame;

	HANDLE ThreadHandle; OBJECT_ATTRIBUTES ObjectAttributes; CLIENT_ID ClientID{ };
	InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	GlobalData->PsCreateSystemThread(&ThreadHandle, THREAD_ALL_ACCESS, & ObjectAttributes, 0, & ClientID, (PKSTART_ROUTINE)ShellcodeBase, 0);
	GlobalData->ZwClose(ThreadHandle);
	GlobalData->ExFreePoolWithTag(ShellcodeBase, GlobalData->RandomPool);
}

typedef struct _CR3_INFO
{
	decltype(&PsLookupProcessByProcessId) PsLookupProcessByProcessId;
	decltype(&ObfDereferenceObject) ObfDereferenceObject;
	decltype(&KeStackAttachProcess) KeStackAttachProcess;
	decltype(&KeUnstackDetachProcess) KeUnstackDetachProcess;
} CR3_INFO, *PCR3_INFO;


ULONG64 GetCr3Eac(ULONG ProcessId, PCR3_INFO Info)
{

	PEPROCESS TargetProcess = nullptr;
	KAPC_STATE State{};
	NTSTATUS Status = Info->PsLookupProcessByProcessId((HANDLE)ProcessId, &TargetProcess);
	if (NT_SUCCESS(Status))
	{
		ULONG64 Cr3 = 0;
		Info->KeStackAttachProcess(TargetProcess, &State);
		Cr3 = __readcr3();
		Info->KeUnstackDetachProcess(&State);
		Info->ObfDereferenceObject(TargetProcess);
		return Cr3;
	}
	return 0;
}

bool DriverStart(ULONG64 ExternData)
{
	GlobalData = (PGLOBAL_DATA)ExternData;
	if(!GlobalData)
		return false;

	RetInstruction = GlobalData->RetInstruction;
	RopGadgetAddress = (PVOID)GlobalData->RopGadgetAddress;

	TeamRead = (PVOID)GlobalData->ExAllocatePoolWithTag(PagedPool, 0x2000, GlobalData->RandomPool);
	if(!TeamRead)
		return false;

	//if(!NT_SUCCESS(CreatShaderSection()))
	//	return false;

	//HANDLE ThreadHandle = NULL;

	//FltCreateCommunicationPort(GlobalData->FilterHandle, &GlobalData->ServerPort, &GlobalData->CommunicationPortAttr, NULL, ConnectPort, DisconnectPort, NULL, 1);
	//GlobalData->PsCreateSystemThread(&ThreadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, (PKSTART_ROUTINE)WaitGame, NULL);
	InitializeThread();
	return true;
}
