#include "dia2.h"
#include <Windows.h>
#include <string>
#include "callback.h"
#include <map>
#include <functional>
#include "symbols.h"

#include <sstream>
#include <iomanip>
#include <list>

////////////////////////////////////////////////////////////
// Create an IDiaData source and open a PDB file
//
bool LoadDataFromPdb(
	const wchar_t    *szFilename,
	IDiaDataSource  **ppSource,
	IDiaSession     **ppSession,
	IDiaSymbol      **ppGlobal, const std::wstring SymbolSearchPath)
{
	wchar_t wszExt[MAX_PATH];
	DWORD dwMachType = 0;

	HRESULT hr = CoInitialize(NULL);

	// Obtain access to the provider

	hr = CoCreateInstance(__uuidof(DiaSource),
		NULL,
		CLSCTX_INPROC_SERVER,
		__uuidof(IDiaDataSource),
		(void **)ppSource);

	if (FAILED(hr)) {
		wprintf(L"CoCreateInstance failed - HRESULT = %08X\n", hr);

		return false;
	}

	_wsplitpath_s(szFilename, NULL, 0, NULL, 0, NULL, 0, wszExt, MAX_PATH);

	if (!_wcsicmp(wszExt, L".pdb")) {
		// Open and prepare a program database (.pdb) file as a debug data source

		hr = (*ppSource)->loadDataFromPdb(szFilename);

		if (FAILED(hr)) {
			wprintf(L"loadDataFromPdb failed - HRESULT = %08X\n", hr);

			return false;
		}
	}

	else {
		CCallback callback; // Receives callbacks from the DIA symbol locating procedure,
							// thus enabling a user interface to report on the progress of
							// the location attempt. The client application may optionally
							// provide a reference to its own implementation of this
							// virtual base class to the IDiaDataSource::loadDataForExe method.
		callback.AddRef();

		// Open and prepare the debug data associated with the executable

		hr = (*ppSource)->loadDataForExe(szFilename, SymbolSearchPath.c_str(), &callback);

		if (FAILED(hr)) {
			wprintf(L"loadDataForExe failed - HRESULT = %08X\n", hr);

			return false;
		}
	}

	// Open a session for querying symbols

	hr = (*ppSource)->openSession(ppSession);

	if (FAILED(hr)) {
		wprintf(L"openSession failed - HRESULT = %08X\n", hr);

		return false;
	}

	// Retrieve a reference to the global scope

	hr = (*ppSession)->get_globalScope(ppGlobal);

	if (hr != S_OK) {
		wprintf(L"get_globalScope failed\n");

		return false;
	}

	// Set Machine type for getting correct register names
	/*
	if ((*ppGlobal)->get_machineType(&dwMachType) == S_OK) {
	switch (dwMachType) {
	case IMAGE_FILE_MACHINE_I386: g_dwMachineType = CV_CFL_80386; break;
	case IMAGE_FILE_MACHINE_IA64: g_dwMachineType = CV_CFL_IA64; break;
	case IMAGE_FILE_MACHINE_AMD64: g_dwMachineType = CV_CFL_AMD64; break;
	}
	}
	*/
	return true;
}

std::wstring SymbolName(IDiaSymbol *pSymbol)
{
	BSTR bstrName;
	BSTR bstrUndName;

	if (pSymbol->get_name(&bstrName) != S_OK)
		return L"(none)";
	std::wstring tmp;
	if (pSymbol->get_undecoratedName(&bstrUndName) == S_OK) {
		if (wcscmp(bstrName, bstrUndName) == 0)
			tmp = std::wstring((wchar_t*)bstrName);
		else
			tmp = std::wstring((wchar_t*)bstrUndName) + L"(" + tmp = std::wstring((wchar_t*)bstrName) + L")";
		SysFreeString(bstrUndName);
	}
	else
		tmp = std::wstring((wchar_t*)bstrName);
	SysFreeString(bstrName);
	return tmp;
}

const wchar_t * const rgLocationTypeString[] =
{
	L"NULL",
	L"static",
	L"TLS",
	L"RegRel",
	L"ThisRel",
	L"Enregistered",
	L"BitField",
	L"Slot",
	L"IL Relative",
	L"In MetaData",
	L"Constant"
};

inline int myDebugBreak(int) {
	DebugBreak();
	return 0;
}

#define MAXELEMS(x)     (sizeof(x)/sizeof(x[0]))
#define SafeDRef(a, i)  ((i < MAXELEMS(a)) ? a[i] : a[myDebugBreak(i)])


////////////////////////////////////////////////////////////
// returns a string corresponding to a location type
//
std::wstring GetOffset(IDiaSymbol *pSymbol)
{
	DWORD dwLocType;
	DWORD dwRVA, dwSect, dwOff, dwReg, dwBitPos, dwSlot;
	LONG lOffset;
	ULONGLONG ulLen;
	VARIANT vt = { VT_EMPTY };

	if (pSymbol->get_locationType(&dwLocType) != S_OK) {
		// It must be a symbol in optimized code
		return L"symbol in optmized code";
	}
	wchar_t buf[1024] = { 0 };

	switch (dwLocType) {
	case LocIsStatic:
		if ((pSymbol->get_relativeVirtualAddress(&dwRVA) == S_OK) &&
			(pSymbol->get_addressSection(&dwSect) == S_OK) &&
			(pSymbol->get_addressOffset(&dwOff) == S_OK)) {
			swprintf_s(buf, L"%s, [%08X][%04X:%08X]", SafeDRef(rgLocationTypeString, dwLocType), dwRVA, dwSect, dwOff);
		}
		break;

	case LocIsTLS:
	case LocInMetaData:
	case LocIsIlRel:
		if ((pSymbol->get_relativeVirtualAddress(&dwRVA) == S_OK) &&
			(pSymbol->get_addressSection(&dwSect) == S_OK) &&
			(pSymbol->get_addressOffset(&dwOff) == S_OK)) {
			swprintf_s(buf, L"%s, [%08X][%04X:%08X]", SafeDRef(rgLocationTypeString, dwLocType), dwRVA, dwSect, dwOff);
		}
		break;

	case LocIsRegRel:
		if ((pSymbol->get_registerId(&dwReg) == S_OK) &&
			(pSymbol->get_offset(&lOffset) == S_OK)) {
			throw std::exception("not implemented"); //swprintf_s(buf, L"%s Relative, [%08X]", SzNameC7Reg((USHORT)dwReg), lOffset);
		}
		break;

	case LocIsThisRel:
		if (pSymbol->get_offset(&lOffset) == S_OK) {
			swprintf_s(buf, L"this+0x%X", lOffset);
		}
		break;

	case LocIsBitField:
		if ((pSymbol->get_offset(&lOffset) == S_OK) &&
			(pSymbol->get_bitPosition(&dwBitPos) == S_OK) &&
			(pSymbol->get_length(&ulLen) == S_OK)) {
			swprintf_s(buf, L"this(bf)+0x%X:0x%X len(0x%X)", lOffset, dwBitPos, (ULONG)ulLen);
		}
		break;

	case LocIsEnregistered:
		if (pSymbol->get_registerId(&dwReg) == S_OK) {
			throw std::exception("not implemented");//swprintf_s(buf, L"enregistered %s", SzNameC7Reg((USHORT)dwReg));
		}
		break;

	case LocIsSlot:
		if (pSymbol->get_slot(&dwSlot) == S_OK) {
			swprintf_s(buf, L"%s, [%08X]", SafeDRef(rgLocationTypeString, dwLocType), dwSlot);
		}
		break;

	case LocIsConstant:
		wprintf(L"constant");
		throw std::exception("not implemented"); //only for enums
		if (pSymbol->get_value(&vt) == S_OK) {
			//return ExtractVariant(vt);
			VariantClear((VARIANTARG *)&vt);
		}
		break;

	case LocIsNull:
		break;

	default:
		swprintf_s(buf, L"Error - invalid location type: 0x%X", dwLocType);
		break;
	}
	return buf;
}

PDB::PDB(const std::wstring & filename, const std::wstring& SymbolSearchPath)
{
	this->filename = filename;
	FILE *pFile;
	if (_wfopen_s(&pFile, filename.c_str(), L"r") || !pFile)
		throw std::exception("File does not exist.");
	fclose(pFile);

	// CoCreate() and initialize COM objects

	if (!LoadDataFromPdb(filename.c_str(), &g_pDiaDataSource, &g_pDiaSession, &g_pGlobalSymbol, SymbolSearchPath))
		throw std::exception("LoadDataFromPdb() failed.");

}

const wchar_t * const rgDataKind[] =
{
	L"Unknown",
	L"Local",
	L"Static Local",
	L"Param",
	L"Object Ptr",
	L"File Static",
	L"Global",
	L"Member",
	L"Static Member",
	L"Constant",
};

std::wstring GetDataType(IDiaSymbol* pSymbol)
{
	DWORD dwDataKind;
	if (pSymbol->get_dataKind(&dwDataKind) != S_OK)
		throw std::exception("ERROR - GetType() get_dataKind");
	wchar_t data_kind[100];
	swprintf_s(data_kind, L", %s", SafeDRef(rgDataKind, dwDataKind));
	//PrintSymbolType(pSymbol);
	return data_kind;
}

const wchar_t * const rgUdtKind[] =
{
	L"struct",
	L"class",
	L"union",
	L"interface",
};

std::wstring GetUdtKind(IDiaSymbol *pSymbol)
{
	DWORD dwKind = 0;
	if (pSymbol->get_udtKind(&dwKind) == S_OK)
		return rgUdtKind[dwKind];
	return L"";
}

std::wstring GetDataKind(IDiaSymbol *pSymbol)
{
	DWORD dwDataKind;
	if (pSymbol->get_dataKind(&dwDataKind) == S_OK)
		return rgDataKind[dwDataKind];
	return L"";
}


#define MAX_TYPE_IN_DETAIL 5

void iterate_symbol_children(IDiaSymbol* pSymbol, std::function<void(const std::wstring&)> cb, DWORD dwIndent = 0)
{
	if (dwIndent > MAX_TYPE_IN_DETAIL)
		return;

	DWORD dwSymTag;
	if (pSymbol->get_symTag(&dwSymTag) != S_OK)
		return;

	switch (dwSymTag) {
	case SymTagData:
	{
		cb(GetOffset(pSymbol) + L" ," + GetDataKind(pSymbol) + L" " + SymbolName(pSymbol) + L"\n");
		IDiaSymbol* pType;
		DWORD dwSymTagType;
		if (pSymbol->get_type(&pType) == S_OK) {
			if (pType->get_symTag(&dwSymTagType) == S_OK) {
				if (dwSymTagType == SymTagUDT) {
					iterate_symbol_children(pType, cb, dwIndent + 2);
				}
			}
			pType->Release();
		}
	}
	break;
	case SymTagUDT:
	{
		if (dwIndent != 0) {
			cb(GetUdtKind(pSymbol) + L" " + SymbolName(pSymbol) + L"\n");
		}
		IDiaEnumSymbols *pEnumChildren;
		if (SUCCEEDED(pSymbol->findChildren(SymTagNull, NULL, nsNone, &pEnumChildren))) {
			IDiaSymbol *pChild;
			ULONG celt = 0;
			while (SUCCEEDED(pEnumChildren->Next(1, &pChild, &celt)) && (celt == 1)) {
				iterate_symbol_children(pChild, cb, dwIndent + 2);
				pChild->Release();
			}
			pEnumChildren->Release();
			cb(L"\n");
		}
	}
	break;
	}

}

std::wstring PDB::dump_UDT(const std::wstring & name)
{
	auto pGlobal = g_pGlobalSymbol;
	std::wstring tmp;
	IDiaEnumSymbols *pEnumSymbols;
	if (FAILED(pGlobal->findChildren(SymTagUDT, NULL, nsNone, &pEnumSymbols))) {
		//wprintf(L"ERROR - DumpAllUDTs() returned no symbols\n");
		return tmp;
	}

	IDiaSymbol *pSymbol;
	ULONG celt = 0;

	while (SUCCEEDED(pEnumSymbols->Next(1, &pSymbol, &celt)) && (celt == 1)) {
		DWORD dwSymTag;
		if (pSymbol->get_symTag(&dwSymTag) != S_OK) {
			pSymbol->Release();
			//wprintf(L"ERROR - PrintTypeInDetail() get_symTag\n");
			break;
		}
		if (dwSymTag == SymTagUDT && SymbolName(pSymbol) == name) {
			tmp += GetUdtKind(pSymbol) + L" " + name + L"{ \n";
			iterate_symbol_children(pSymbol, [&](const std::wstring& value) {
				tmp += value;
			});
			tmp += L"};\n";
			break;
		}
		pSymbol->Release();
	}
	pEnumSymbols->Release();
	return tmp;
}


PDB::~PDB()
{
	if (g_pGlobalSymbol) {
		g_pGlobalSymbol->Release();
		g_pGlobalSymbol = NULL;
	}

	if (g_pDiaSession) {
		g_pDiaSession->Release();
		g_pDiaSession = NULL;
	}

	CoUninitialize();
}


ULONG get_offset(const std::wstring& structure, const std::wstring& member)
{
	std::list<std::wstring> parts;
	std::wstring temp;
	std::wstringstream wss(structure);
	while (std::getline(wss, temp, L'\n'))
		parts.push_back(temp);
	for (auto& part : parts) {
		size_t pos;
		if ((pos = part.find(member)) != std::wstring::npos) {
			if (part.length() - pos != member.length())
				continue;

			if ((pos = part.find(L"this+0x")) != std::wstring::npos) {
				pos += wcslen(L"this+0x");
				auto pos2 = part.find(L',', pos);
				std::wstring hexvalue = part.substr(pos, pos2 - pos);
				ULONG r;
				std::wstringstream(hexvalue) >> std::hex >> r;
				return r;
			}
			else if (part.find(L"this(bf)"))
				throw std::exception("get_offset - Unsupported.");

		}
	}
	return 0;
}