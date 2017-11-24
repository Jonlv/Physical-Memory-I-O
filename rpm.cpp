#include <Windows.h>
#include <winternl.h>
#include <exception>
#include <string>
#include <memory>
#include "superfetch.h"
#include <functional>
#include "rpm.h"
#include <dia2.h>
#include "symbols.h"
#include <DbgHelp.h>
#include <iostream>

using namespace std;

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "dbghelp.lib")

#define PHYSICAL_ADDRESS	LARGE_INTEGER

typedef struct _POOL_HEADER
{
	union
	{
		struct
		{
#if defined(_AMD64_)
			ULONG	PreviousSize : 8;
			ULONG	PoolIndex : 8;
			ULONG	BlockSize : 8;
			ULONG	PoolType : 8;
#else
			USHORT	PreviousSize : 9;
			USHORT	PoolIndex : 7;
			USHORT	BlockSize : 9;
			USHORT	PoolType : 7;
#endif
		};
		ULONG	Ulong1;
	};
#if defined(_WIN64)
	ULONG	PoolTag;
#endif
	union
	{
#if defined(_WIN64)
		void	*ProcessBilled;
#else
		ULONG	PoolTag;
#endif
		struct
		{
			USHORT	AllocatorBackTraceIndex;
			USHORT	PoolTagHash;
		};
	};
} POOL_HEADER, *PPOOL_HEADER;

typedef struct _OBJECT_HEADER
{
	LONG	PointerCount;
	union
	{
		LONG	HandleCount;
		PVOID	NextToFree;
	};
	uint64_t	Lock;
	UCHAR		TypeIndex;
	union
	{
		UCHAR	TraceFlags;
		struct
		{
			UCHAR	DbgRefTrace : 1;
			UCHAR	DbgTracePermanent : 1;
			UCHAR	Reserved : 6;
		};
	};
	UCHAR	InfoMask;
	union
	{
		UCHAR	Flags;
		struct
		{
			UCHAR	NewObject : 1;
			UCHAR	KernelObject : 1;
			UCHAR	KernelOnlyAccess : 1;
			UCHAR	ExclusiveObject : 1;
			UCHAR	PermanentObject : 1;
			UCHAR	DefaultSecurityQuota : 1;
			UCHAR	SingleHandleEntry : 1;
			UCHAR	DeletedInline : 1;
		};
	};
	union
	{
		PVOID	ObjectCreateInfo;
		PVOID	QuotaBlockCharged;
	};
	PVOID	SecurityDescriptor;
	PVOID	Body;
} OBJECT_HEADER, *POBJECT_HEADER;

int isAscii(int c)
{
	return((c >= 'A' && c <= 'z') || (c >= '0' && c <= '9') || c == ' '/*0x20*/ || c == '@' || c == '_' || c == '?');
}

bool isPrintable(uint32_t uint32)
{
	if ((isAscii((uint32 >> 24) & 0xFF)) && (isAscii((uint32 >> 16) & 0xFF)) && (isAscii((uint32 >> 8) & 0xFF)) &&
		(isAscii((uint32) & 0xFF)))
		return true;
	else
		return false;
}

typedef enum _SECTION_INHERIT { ViewShare = 1, ViewUnmap = 2 } SECTION_INHERIT, *PSECTION_INHERIT;

extern "C" NTSTATUS NTAPI	ZwOpenSection(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
extern "C" NTSTATUS NTAPI	ZwMapViewOfSection(_In_ HANDLE SectionHandle, _In_ HANDLE ProcessHandle,
	_Inout_ PVOID BaseAddress, _In_ ULONG_PTR ZeroBits, _In_ SIZE_T CommitSize,
	_Inout_opt_ PLARGE_INTEGER SectionOffset, _Inout_ PSIZE_T ViewSize,
	_In_ SECTION_INHERIT InheritDisposition, _In_ ULONG AllocationType,
	_In_ ULONG Win32Protect);
extern "C" NTSTATUS NTAPI	ZwUnmapViewOfSection(_In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress);

BOOLEAN MapPhysicalMemory(HANDLE hMemory, PDWORD64 pDwAddress, PSIZE_T pSize, PDWORD64 pDwVirtualAddress)
{
	NTSTATUS ntStatus;

	LARGE_INTEGER viewBase;
	*pDwVirtualAddress = 0;
	viewBase.QuadPart = *pDwAddress;
	ntStatus = ZwMapViewOfSection(hMemory, GetCurrentProcess(), (void**)pDwVirtualAddress, 0L, *pSize, &viewBase, pSize, ViewShare, 0, PAGE_READWRITE);
	if (!NT_SUCCESS(ntStatus))
		return false;
	*pDwAddress = viewBase.QuadPart;
	return true;
}

BOOLEAN UnmapPhysicalMemory(PDWORD64 Address)
{
	if (!ZwUnmapViewOfSection(GetCurrentProcess(), (void*)Address))
		return true;
	else
		return false;
}


HANDLE OpenPhysicalMemory()
{
	UNICODE_STRING		physmemString;
	OBJECT_ATTRIBUTES	attributes;
	WCHAR				physmemName[] = L"\\device\\physicalmemory";
	NTSTATUS			status;
	HANDLE				physmem;

	RtlInitUnicodeString(&physmemString, physmemName);

	InitializeObjectAttributes(&attributes, &physmemString, OBJ_CASE_INSENSITIVE, NULL, NULL);

	status = ZwOpenSection(&physmem, SECTION_ALL_ACCESS, &attributes);

	if (!NT_SUCCESS(status))
	{
		return NULL;
	}

	return physmem;
}

PhysicalMemoryWrapper::PhysicalMemoryWrapper()
{
	/*
	EPNameOffset = 0x450;
	EPPidOffset = 0x02E0;
	EPDirBaseOffset = 0x0028;
	EPBaseOffset = 0x03C0;
	EPLinkOffset = 0x02E8;
	*/
	//SymSetOptions(SYMOPT_CASE_INSENSITIVE | SYMOPT_DEBUG | SYMOPT_DEFERRED_LOADS | SYMOPT_SECURE);
	SymSetOptions(SYMOPT_DEBUG | SYMOPT_CASE_INSENSITIVE);
	char local_path[MAX_PATH], system_path[MAX_PATH];
	GetCurrentDirectoryA(MAX_PATH, local_path);
	std::string sym = "srv*" + std::string(local_path) + "*http://msdl.microsoft.com/download/symbols";
	GetSystemDirectoryA(system_path, MAX_PATH);
	std::string sysfile = system_path + std::string("\\ntoskrnl.exe"), localfile = local_path + std::string("\\ntoskrnl.exe");
	CopyFileA(sysfile.c_str(), localfile.c_str(), FALSE);

	if (!SymInitialize(GetCurrentProcess(), sym.c_str(), FALSE))
		throw std::exception("SymInitialize() failed.");
	SYMSRV_INDEX_INFO info = { };
	info.sizeofstruct = sizeof(SYMSRV_INDEX_INFO);
	if (!SymSrvGetFileIndexInfo("ntoskrnl.exe", &info, 0))
		throw std::exception("SymSrvGetFileIndexInfo() failed.");

	char pdbpath[MAX_PATH];
	if (!SymFindFileInPath(GetCurrentProcess(), nullptr, info.pdbfile, &info.guid, info.age, 0, SSRVOPT_GUIDPTR, pdbpath, nullptr, NULL))
		throw std::exception("SymFindFileInPath() failed.");
	SymCleanup(GetCurrentProcess());
	std::string path(pdbpath);

	PDB pdb(std::wstring(path.begin(), path.end()), L""); //we could also have it search for the symbols.
	auto EPROCESS = pdb.dump_UDT(L"_EPROCESS");
	//wcout << EPROCESS << endl;
	//cout << "--------------" << endl;
	//cout << "--------------" << endl;
	//cout << "--------------" << endl;
	auto KPROCESS = pdb.dump_UDT(L"_KPROCESS");
	//wcout << KPROCESS << endl;
	//ExitProcess(0);
	EPNameOffset = get_offset(EPROCESS, L"ImageFileName");
	EPPidOffset = get_offset(EPROCESS, L"UniqueProcessId");
	EPDirBaseOffset = get_offset(KPROCESS, L"DirectoryTableBase");
	EPBaseOffset = get_offset(EPROCESS, L"SectionBaseAddress");
	EPLinkOffset = get_offset(EPROCESS, L"ActiveProcessLinks");
	EPObjectTable = get_offset(EPROCESS, L"ObjectTable");

	if (EPNameOffset == 0 || EPPidOffset == 0 || EPDirBaseOffset == 0 || EPBaseOffset == 0 || EPLinkOffset == 0 || EPObjectTable == 0)
		throw std::exception("PDB::Offset finder was unable to find one or more offsets from the dumped UDT structure.");

	SFSetup();
	SFGetMemoryInfo(mMemInfo, mInfoCount);

	cached_kernel_dir_base = NULL; //cr3? http://rayseyfarth.com/asm/pdf/ch04-memory-mapping.pdf
	hPhysicalMemory = OpenPhysicalMemory();
	if (hPhysicalMemory == NULL)
		throw std::exception("Unable to open.");

	//mMemInfo[i].Start = 0x1000;
	//mMemInfo[i].End = 0x1000;
	//mMemInfo[i].Size = 0x1000;
	mMemInfo[mInfoCount - 1].End -= 0x1000;
	mMemInfo[mInfoCount - 1].Size -= 0x1000;
	uint8_t* startScan = 0;
	if (!MapPhysicalMemory(hPhysicalMemory, (PDWORD64)&startScan, &mMemInfo[mInfoCount - 1].End, (PDWORD64)&ramImage)) {
		::CloseHandle(hPhysicalMemory);
		throw std::exception("Failed to map.");
	}
}

PhysicalMemoryWrapper::~PhysicalMemoryWrapper()
{
	UnmapPhysicalMemory((PDWORD64)ramImage);
	::CloseHandle(hPhysicalMemory);
}

bool PhysicalMemoryWrapper::isInRam(uint64_t address, uint32_t len) {
	for (int j = 0; j < mInfoCount; j++)
		if ((mMemInfo[j].Start <= address) && ((address + len) <= mMemInfo[j].End))
			return true;
	return false;
}

bool PhysicalMemoryWrapper::ScanPoolTag(char* tag_char, std::function<bool(uint64_t)> scan_callback)
{
	uint32_t tag = (
		tag_char[0] |
		tag_char[1] << 8 |
		tag_char[2] << 16 |
		tag_char[3] << 24
		);


	for (auto i = 0ULL; i < mMemInfo[mInfoCount - 1].End; i += 0x1000) {
		if (!isInRam(i, 0x1000))
			continue;
		uint8_t* lpCursor = ramImage + i;
		uint32_t previousSize = 0;
		while (true) {
			auto pPoolHeader = (PPOOL_HEADER)lpCursor;
			auto blockSize = (pPoolHeader->BlockSize << 4);
			auto previousBlockSize = (pPoolHeader->PreviousSize << 4);

			if (previousBlockSize != previousSize ||
				blockSize == 0 ||
				blockSize >= 0xFFF ||
				!isPrintable(pPoolHeader->PoolTag & 0x7FFFFFFF))
				break;

			previousSize = blockSize;

			if (tag == (pPoolHeader->PoolTag & 0x7FFFFFFF))
				if (scan_callback((uint64_t)(lpCursor - ramImage)))
					return true;
			lpCursor += blockSize;
			if ((lpCursor - (ramImage + i)) >= 0x1000)
				break;
		}
	}

	return false;
}

bool PhysicalMemoryWrapper::Read(uint64_t address, uint8_t* buffer, int size)
{
	for (int i = 0; i < mInfoCount; i++)
	{
		if (mMemInfo[i].Start <= address && address + size <= mMemInfo[i].End)
		{
			memcpy(buffer, (void*)(ramImage + address), size);
			return true;
		}
	}
	memset(buffer, 0, size);
	return false;
}

bool PhysicalMemoryWrapper::Write(uint64_t address, uint8_t* buffer, int size)
{
	for (int i = 0; i < mInfoCount; i++)
	{
		if (mMemInfo[i].Start <= address && address + size <= mMemInfo[i].End)
		{
			memcpy((void*)(ramImage + address), buffer, size);
			return true;
		}
	}
	return false;
}

uint64_t PhysicalMemoryWrapper::TranslateLinearAddress(uint64_t directoryTableBase, uint64_t virtualAddress)
{
	uint16_t PML4 = (uint16_t)((virtualAddress >> 39) & 0x1FF);         //<! PML4 Entry Index
	uint16_t DirectoryPtr = (uint16_t)((virtualAddress >> 30) & 0x1FF); //<! Page-Directory-Pointer Table Index
	uint16_t Directory = (uint16_t)((virtualAddress >> 21) & 0x1FF);    //<! Page Directory Table Index
	uint16_t Table = (uint16_t)((virtualAddress >> 12) & 0x1FF);        //<! Page Table Index

	// Read the PML4 Entry. DirectoryTableBase has the base address of the table.
	// It can be read from the CR3 register or from the kernel process object.
	uint64_t PML4E = 0;// ReadPhysicalAddress<ulong>(directoryTableBase + (ulong)PML4 * sizeof(ulong));
	if (!Read(directoryTableBase + (uint64_t)PML4 * sizeof(uint64_t), (uint8_t*)&PML4E, sizeof(PML4E)))
		return 0;

	if (PML4E == 0)
		return 0;

	// The PML4E that we read is the base address of the next table on the chain,
	// the Page-Directory-Pointer Table.
	uint64_t PDPTE = 0;// ReadPhysicalAddress<ulong>((PML4E & 0xFFFF1FFFFFF000) + (ulong)DirectoryPtr * sizeof(ulong));
	if (!Read((PML4E & 0xFFFF1FFFFFF000) + (uint64_t)DirectoryPtr * sizeof(uint64_t), (uint8_t*)&PDPTE, sizeof(PDPTE)))
		return 0;

	if (PDPTE == 0)
		return 0;

	//Check the PS bit
	if ((PDPTE & (1 << 7)) != 0)
	{
		// If the PDPTE¨s PS flag is 1, the PDPTE maps a 1-GByte page. The
		// final physical address is computed as follows:
		// ！ Bits 51:30 are from the PDPTE.
		// ！ Bits 29:0 are from the original va address.
		return (PDPTE & 0xFFFFFC0000000) + (virtualAddress & 0x3FFFFFFF);
	}

	// PS bit was 0. That means that the PDPTE references the next table
	// on the chain, the Page Directory Table. Read it.
	uint64_t PDE = 0;// ReadPhysicalAddress<ulong>((PDPTE & 0xFFFFFFFFFF000) + (ulong)Directory * sizeof(ulong));
	if (!Read((PDPTE & 0xFFFFFFFFFF000) + (uint64_t)Directory * sizeof(uint64_t), (uint8_t*)&PDE, sizeof(PDE)))
		return 0;

	if (PDE == 0)
		return 0;

	if ((PDE & (1 << 7)) != 0)
	{
		// If the PDE¨s PS flag is 1, the PDE maps a 2-MByte page. The
		// final physical address is computed as follows:
		// ！ Bits 51:21 are from the PDE.
		// ！ Bits 20:0 are from the original va address.
		return (PDE & 0xFFFFFFFE00000) + (virtualAddress & 0x1FFFFF);
	}

	// PS bit was 0. That means that the PDE references a Page Table.
	uint64_t PTE = 0;// ReadPhysicalAddress<ulong>((PDE & 0xFFFFFFFFFF000) + (ulong)Table * sizeof(ulong));
	if (!Read((PDE & 0xFFFFFFFFFF000) + (uint64_t)Table * sizeof(uint64_t), (uint8_t*)&PTE, sizeof(PTE)))
		return 0;

	if (PTE == 0)
		return 0;

	// The PTE maps a 4-KByte page. The
	// final physical address is computed as follows:
	// ！ Bits 51:12 are from the PTE.
	// ！ Bits 11:0 are from the original va address.
	return (PTE & 0xFFFFFFFFFF000) + (virtualAddress & 0xFFF);
}

bool PhysicalMemoryWrapper::ReadVirtual(uint64_t dirbase, uint64_t address, uint8_t* buffer, int size)
{
	auto paddress = TranslateLinearAddress(dirbase, address);
	if (paddress == NULL)
		return false;
	return Read(paddress, buffer, size);
}

bool PhysicalMemoryWrapper::WriteVirtual(uint64_t dirbase, uint64_t address, uint8_t* buffer, int size)
{
	auto paddress = TranslateLinearAddress(dirbase, address);
	if (paddress == NULL)
		return false;
	return Write(paddress, buffer, size);
}

PVOID PhysicalMemoryWrapper::GetMappedAddress(uint64_t dirbase, uint64_t vaddress, uint32_t size)
{
	auto paddress = TranslateLinearAddress(dirbase, vaddress);
	if (paddress == NULL)
		return false;
	for (int i = 0; i < mInfoCount; i++)
	{
		if (mMemInfo[i].Start <= paddress && paddress + size <= mMemInfo[i].End)
			return ramImage + paddress;
	}
	return nullptr;
}

uint64_t PhysicalMemoryWrapper::GetEProcess(int pid)
{
	_LIST_ENTRY ActiveProcessLinks;
	if (ReadVirtual(GetKernelDirBase(), SFGetEProcess(4) + EPLinkOffset, (uint8_t*)&ActiveProcessLinks, sizeof(ActiveProcessLinks)))
		while (true)
		{
			uint64_t next_pid = 0;
			uint64_t next_link = (uint64_t)(ActiveProcessLinks.Flink);
			uint64_t next = next_link - EPLinkOffset;
			if (!ReadVirtual(GetKernelDirBase(), next + EPPidOffset, (uint8_t*)&next_pid, sizeof(next_pid)))
				break;
			if (!ReadVirtual(GetKernelDirBase(), next + EPLinkOffset, (uint8_t*)&ActiveProcessLinks, sizeof(ActiveProcessLinks)))
				break;
			if (next_pid == pid)
				return next;
			if (next_pid == 4)
				break;
		}
	return 0;
}

uint64_t PhysicalMemoryWrapper::HideEProcess(int pid)
{
	_LIST_ENTRY ActiveProcessLinks;
	if (!ReadVirtual(GetKernelDirBase(), SFGetEProcess(4) + EPLinkOffset, (uint8_t*)&ActiveProcessLinks, sizeof(ActiveProcessLinks)))
		return NULL;
	while (true)
	{
		uint64_t next_pid = 0;
		uint64_t next_link = (uint64_t)(ActiveProcessLinks.Flink);
		uint64_t next = next_link - EPLinkOffset;
		if (!ReadVirtual(GetKernelDirBase(), next + EPPidOffset, (uint8_t*)&next_pid, sizeof(next_pid)))
			break;
		if (!ReadVirtual(GetKernelDirBase(), next + EPLinkOffset, (uint8_t*)&ActiveProcessLinks, sizeof(ActiveProcessLinks)))
			break;
		if (next_pid == pid) {
			_LIST_ENTRY prev_entry, next_entry, current;
			if (!ReadVirtual(GetKernelDirBase(), next_link, (uint8_t*)&current, sizeof(_LIST_ENTRY)))
				break;
			if (!ReadVirtual(GetKernelDirBase(), (uint64_t)current.Blink, (uint8_t*)&prev_entry, sizeof(_LIST_ENTRY)))
				break;
			if (!ReadVirtual(GetKernelDirBase(), (uint64_t)current.Flink, (uint8_t*)&next_entry, sizeof(_LIST_ENTRY)))
				break;
			prev_entry.Flink = current.Flink;
			next_entry.Blink = current.Blink;
			//we don't check these, because if it fails, we're seriously in trouble(and i'm too lazy to save the previous state of the list to restore in case of a critical failure to write).
			//anyways, the point is, it shouldn't happen.
			WriteVirtual(GetKernelDirBase(), (uint64_t)current.Blink, (uint8_t*)&prev_entry, sizeof(_LIST_ENTRY));
			WriteVirtual(GetKernelDirBase(), (uint64_t)current.Flink, (uint8_t*)&next_entry, sizeof(_LIST_ENTRY));
			current.Blink = (_LIST_ENTRY*)next_link;
			current.Flink = (_LIST_ENTRY*)next_link;
			WriteVirtual(GetKernelDirBase(), (uint64_t)next_link, (uint8_t*)&current, sizeof(current));
			
			//next_pid = 4340; //1337;
			//WriteVirtual(GetKernelDirBase(), next_link + EPPidOffset, (uint8_t*)&next_pid, sizeof(next_pid));
			return next;
		}
		if (next_pid == 4)
			break;
	}
	return NULL;
}

bool PhysicalMemoryWrapper::UnHideEProcess(uint64_t hidden_process)
{
	if (!hidden_process)
		return false;
	_LIST_ENTRY Pid4, Pid4Next, hidden;
	auto Pid4_link = SFGetEProcess(4) + EPLinkOffset;
	if (!ReadVirtual(GetKernelDirBase(), Pid4_link, (uint8_t*)&Pid4, sizeof(Pid4)))
		return false;
	auto Pid4_Original_Next = (uint64_t)Pid4.Flink;
	hidden_process += EPLinkOffset;
	if (!ReadVirtual(GetKernelDirBase(), hidden_process, (uint8_t*)&hidden, sizeof(hidden)))
		return false;
	if (!ReadVirtual(GetKernelDirBase(), (uint64_t)Pid4_Original_Next, (uint8_t*)&Pid4Next, sizeof(Pid4Next)))
		return false;
	hidden.Flink = Pid4.Flink;
	hidden.Blink = (LIST_ENTRY*)Pid4_link;
	Pid4Next.Blink = (LIST_ENTRY*)hidden_process;
	Pid4.Flink = (LIST_ENTRY*)hidden_process;

	WriteVirtual(GetKernelDirBase(), (uint64_t)hidden_process, (uint8_t*)&hidden, sizeof(hidden));
	WriteVirtual(GetKernelDirBase(), (uint64_t)Pid4_link, (uint8_t*)&Pid4, sizeof(Pid4));
	WriteVirtual(GetKernelDirBase(), (uint64_t)Pid4_Original_Next, (uint8_t*)&Pid4Next, sizeof(Pid4Next));
	return true;
}

uint64_t PhysicalMemoryWrapper::get_process_dir_base(int pid)
{
	uint64_t cr3 = 0;
	if (ReadVirtual(GetKernelDirBase(), GetEProcess(pid) + EPDirBaseOffset, (uint8_t*)&cr3, sizeof(cr3)))
		return cr3;
	return 0;
}

uint64_t PhysicalMemoryWrapper::get_process_base(int pid)
{
	uint64_t base = 0;
	ReadVirtual(GetKernelDirBase(), GetEProcess(pid) + EPBaseOffset, (uint8_t*)&base, sizeof(base));
	return base;
}

uint64_t PhysicalMemoryWrapper::GetKernelDirBase()
{
	if (cached_kernel_dir_base != 0)
		return cached_kernel_dir_base;

	auto result = ScanPoolTag("Proc", [&](uint64_t address) -> bool
	{
		uint64_t peprocess;
		char buffer[0xFFFF];
		if (!Read(address, (uint8_t*)buffer, sizeof(buffer)))
			return false;
		for (char* ptr = buffer; (uint64_t)ptr - (uint64_t)buffer <= sizeof(buffer); ptr++)
			if (!strcmp(ptr, "System"))
				peprocess = address + (uint64_t)ptr - (uint64_t)buffer - EPNameOffset;

		uint64_t pid = 0;
		if (!Read(peprocess + EPPidOffset, (uint8_t*)&pid, sizeof(pid)))
			return false;

		if (pid == 4)
		{
			if (!Read(peprocess + EPDirBaseOffset, (uint8_t*)&cached_kernel_dir_base, sizeof(cached_kernel_dir_base)))
				return false;
			if (peprocess == TranslateLinearAddress(cached_kernel_dir_base, SFGetEProcess(4))) {
				//printf("Found System CR3\n");
				return true;
			}
		}
		return false;
	});

	if (result)
		return cached_kernel_dir_base;
	else
		cached_kernel_dir_base = NULL;
	return 0;
}

MemoryIO::MemoryIO(PhysicalMemoryWrapper & physmem_api, DWORD dwPID):physmem_api(physmem_api)
{
	cached_eprocess = physmem_api.GetEProcess(dwPID);
	cached_process_dir_base = physmem_api.get_process_dir_base(dwPID);
	if (cached_process_dir_base == NULL)
		throw std::exception("Unable to get process dir base.");
	cached_process_base_address = physmem_api.get_process_base(dwPID);
	if (cached_process_base_address == NULL)
		throw std::exception("Unable to get process base address.");

}

bool MemoryIO::read(uint64_t address, PVOID data, ULONG size)
{
	if (address == 0)
		return false;
	return physmem_api.ReadVirtual(cached_process_dir_base, address, (uint8_t*)data, size);
}

bool MemoryIO::write(uint64_t address, LPCVOID data, ULONG size)
{
	if (address == 0)
		return false;
	return physmem_api.WriteVirtual(cached_process_dir_base, address, (uint8_t*)data, size);
}

bool MemoryIO::IsInRam(uint64_t address, uint32_t size)
{
	if (address == 0)
		return false;
	auto paddress = physmem_api.TranslateLinearAddress(cached_process_dir_base, address);
	return physmem_api.isInRam(paddress, size);
}

PVOID MemoryIO::map(uint64_t va, uint32_t size)
{
	if (va == 0)
		return nullptr;
	return physmem_api.GetMappedAddress(cached_process_dir_base, va, size);
}

bool MemoryIO::grant_handle_access(HANDLE handle, ACCESS_MASK access_rights)
{
	auto handle_table_addr = this->read<PHANDLE_TABLE>(uint64_t(cached_eprocess + physmem_api.EPObjectTable));
	auto handle_table = read<HANDLE_TABLE>((uint64_t)handle_table_addr);
	auto entry_addr = PHANDLE_TABLE_ENTRY{ nullptr };
	entry_addr = ExpLookupHandleTableEntry(&handle_table, (ULONGLONG)handle);
	if (!entry_addr)
		return false;
	auto entry = read<HANDLE_TABLE_ENTRY>((uint64_t)entry_addr);
	entry.GrantedAccess = access_rights;
	return write<HANDLE_TABLE_ENTRY>((uint64_t)entry_addr, entry);
}

PHANDLE_TABLE_ENTRY MemoryIO::ExpLookupHandleTableEntry(PHANDLE_TABLE HandleTable, ULONGLONG Handle)
{
	ULONGLONG v2; // rdx@1
	LONGLONG v3; // r8@2
	ULONGLONG result; // rax@4
	ULONGLONG v5;

	ULONGLONG a1 = (ULONGLONG)HandleTable;

	v2 = Handle & 0xFFFFFFFFFFFFFFFCui64;
	if (v2 >= *(DWORD*)a1) {
		result = 0i64;
	}
	else {
		v3 = *(ULONGLONG*)(a1 + 8);
		if (*(ULONGLONG*)(a1 + 8) & 3) {
			if ((*(DWORD*)(a1 + 8) & 3) == 1) {
				v5 = this->read<ULONGLONG>(v3 + 8 * (v2 >> 10) - 1);
				result = v5 + 4 * (v2 & 0x3FF);
			}
			else {
				v5 = this->read<ULONGLONG>(this->read<ULONGLONG>(v3 + 8 * (v2 >> 19) - 2) + 8 * ((v2 >> 10) & 0x1FF));
				result = v5 + 4 * (v2 & 0x3FF);
			}
		}
		else {
			result = v3 + 4 * v2;
		}
	}
	return (PHANDLE_TABLE_ENTRY)result;
}