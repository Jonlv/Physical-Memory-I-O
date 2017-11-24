#pragma once

class PDB {
public:
	PDB(const std::wstring& filename, const std::wstring& symbol_search_path);
	~PDB();

	std::wstring dump_UDT(const std::wstring& struct_name); //extracts all user defined types (UDTs) from the struct name.
private:
	IDiaDataSource *g_pDiaDataSource;
	IDiaSession *g_pDiaSession;
	IDiaSymbol *g_pGlobalSymbol;
	std::wstring filename;
};

ULONG get_offset(const std::wstring& structure, const std::wstring& member);