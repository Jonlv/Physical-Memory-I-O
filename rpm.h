#pragma once
#include <stdint.h>

struct PfnList;
class Driver_Exploit {
public:
	Driver_Exploit();
	~Driver_Exploit();
private:
	SFMemoryInfo myRanges[32] = { 0 };
	PfnList* pfnTable = nullptr;
	int nOfRange = 0;
	void patch(bool bPatch);
	uint64_t physmem_object_header;
	HANDLE hDriver;
};

class MemoryIO;
class PhysicalMemoryWrapper {
public:
	PhysicalMemoryWrapper(bool bUseHardcoded = false);
	~PhysicalMemoryWrapper();

	bool isInRam(uint64_t address, uint32_t len);
	bool ScanPoolTag(char* tag_char, std::function<bool(uint64_t)> scan_callback);
	bool Read(uint64_t address, uint8_t* buffer, int size);
	bool Write(uint64_t address, uint8_t* buffer, int size);
	bool ReadVirtual(uint64_t dirbase, uint64_t address, uint8_t* buffer, int size);
	bool WriteVirtual(uint64_t dirbase, uint64_t address, uint8_t* buffer, int size);
	PVOID GetMappedAddress(uint64_t dirbase, uint64_t vaddress, uint32_t size);
	uint64_t TranslateLinearAddress(uint64_t directoryTableBase, uint64_t virtualAddress);
	uint64_t get_process_dir_base(int pid);
	uint64_t get_process_base(int pid);
	uint64_t GetEProcess(int pid);
	uint64_t HideEProcess(int pid);
	bool UnHideEProcess(uint64_t hidden_process);
	uint64_t GetKernelDirBase();
	bool change_pid(int pid, uint64_t eprocess);

	template <typename T>
	T SPread(uint64_t address);
	template <typename T>
	bool SPwrite(uint64_t address, const T& value);
private:
	friend class MemoryIO;
	uint64_t EPNameOffset = 0;
	uint64_t EPPidOffset = 0;
	uint64_t EPDirBaseOffset = 0;
	uint64_t EPBaseOffset = 0;
	uint64_t EPLinkOffset = 0;
	uint64_t EPObjectTable = 0;
	
	uint8_t *ramImage = 0;

	SFMemoryInfo mMemInfo[32];
	int mInfoCount = 0;

	HANDLE hPhysicalMemory;
	uint64_t cached_kernel_dir_base;
};

template<typename T>
inline T PhysicalMemoryWrapper::SPread(uint64_t address)
{
	T t;
	if (readVirtual(GetKernelDirBase(), address, &t, sizeof(t)))
		return t;
	return T();
}

template<typename T>
inline bool PhysicalMemoryWrapper::SPwrite(uint64_t address, const T & value)
{
	return writeVirtual(GetKernelDirBase(), address, &value, sizeof(value));
}


typedef struct _HANDLE_TABLE* PHANDLE_TABLE;

typedef struct _HANDLE_TABLE_ENTRY
{
	//This struct is incomplete, but we dont really care about the other fields
	ULONGLONG Value;
	ULONGLONG GrantedAccess : 25;
} HANDLE_TABLE_ENTRY, *PHANDLE_TABLE_ENTRY;

typedef struct _HANDLE_TABLE
{
	CHAR fill[100];
} HANDLE_TABLE, *PHANDLE_TABLE;

class MemoryIO {
public:
	MemoryIO(PhysicalMemoryWrapper& physmem_api, DWORD dwPID);
	bool read(uint64_t address, PVOID data, ULONG size);
	bool write(uint64_t address, LPCVOID data, ULONG size);
	template <typename T>
	T read(uint64_t address);
	template <typename T>
	bool write(uint64_t address, const T& value);
	bool IsInRam(uint64_t address, uint32_t size);
	PVOID map(uint64_t va, uint32_t size); //get mapped pointer(for fast memory access).
	uint64_t get_process_base() const { return cached_process_base_address; };
	bool grant_handle_access(HANDLE handle, ACCESS_MASK access_rights);
	bool change_pid(int inewpid);
private:
	PHANDLE_TABLE_ENTRY ExpLookupHandleTableEntry(PHANDLE_TABLE HandleTable, ULONGLONG Handle);
	uint64_t cached_process_dir_base = 0, cached_process_base_address = 0, cached_eprocess = 0;
	PhysicalMemoryWrapper& physmem_api;
};

template<typename T>
inline T MemoryIO::read(uint64_t address)
{
	T t;
	if (read(address, &t, sizeof(t)))
		return t;
	return T();
}

template<typename T>
inline bool MemoryIO::write(uint64_t address, const T & value)
{
	return write(address, &value, sizeof(value));
}
