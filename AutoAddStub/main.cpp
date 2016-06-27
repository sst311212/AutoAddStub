#include <stdio.h>
#include <Windows.h>

int main(int argc, char **argv)
{
	if (argc != 2) {
		printf("AutoAddStub v1.0, coded by sst311212\n\n");
		printf("usage: %s <input.exe>\n", argv[0]);
		return 0;
	}

	FILE *pFile;
	fopen_s(&pFile, argv[1], "rb+");

	IMAGE_DOS_HEADER hDos;
	fread(&hDos, 1, sizeof(hDos), pFile);
	fseek(pFile, hDos.e_lfanew, SEEK_SET);

	IMAGE_NT_HEADERS hNt;
	fread(&hNt, 1, sizeof(hNt), pFile);
	
	int NumOfSec = hNt.FileHeader.NumberOfSections;
	auto hSecs = new IMAGE_SECTION_HEADER [NumOfSec + 1];
	memset(hSecs, 0, sizeof(IMAGE_SECTION_HEADER) * (NumOfSec + 1));
	fread(hSecs, sizeof(IMAGE_SECTION_HEADER), NumOfSec, pFile);

	memcpy(hSecs[NumOfSec].Name, ".2DJ\x0\x0\x0\x0", 8);
	// 設定新區段表的資料
	hSecs[NumOfSec].Misc.VirtualSize = 0x400;
	hSecs[NumOfSec].VirtualAddress = hSecs[NumOfSec - 1].VirtualAddress + (hNt.OptionalHeader.SectionAlignment * ((hSecs[NumOfSec - 1].Misc.VirtualSize / hNt.OptionalHeader.SectionAlignment) + 1));
	hSecs[NumOfSec].SizeOfRawData = hSecs[NumOfSec].Misc.VirtualSize;
	hSecs[NumOfSec].PointerToRawData = hSecs[NumOfSec - 1].PointerToRawData + hSecs[NumOfSec - 1].SizeOfRawData;
	hSecs[NumOfSec].Characteristics = 0xE0000020;

	fseek(pFile, 0, SEEK_CUR);
	fwrite(&hSecs[NumOfSec], 1, sizeof(IMAGE_SECTION_HEADER), pFile);
	auto ZeroArray = new BYTE [hSecs[NumOfSec].SizeOfRawData];
	memset(ZeroArray, 0, hSecs[NumOfSec].SizeOfRawData);
	fseek(pFile, hSecs[NumOfSec].PointerToRawData, SEEK_SET);
	fwrite(ZeroArray, 1, hSecs[NumOfSec].SizeOfRawData, pFile);

	for (int i = 0; i < hNt.FileHeader.NumberOfSections; i++) {
		if (!memcmp(hSecs[i].Name, ".rdata", 8)) {
			UINT dwPosit = hNt.OptionalHeader.DataDirectory[1].VirtualAddress - hSecs[i].VirtualAddress + hSecs[i].PointerToRawData;
			fseek(pFile, dwPosit, SEEK_SET);
			int NumOfDll = hNt.OptionalHeader.DataDirectory[1].Size / 0x14;
			auto ImportDir = new IMAGE_IMPORT_DESCRIPTOR [NumOfDll];
			memset(ImportDir, 0, hNt.OptionalHeader.DataDirectory[1].Size);
			fread(ImportDir, 1, hNt.OptionalHeader.DataDirectory[1].Size, pFile);
			fseek(pFile, hSecs[NumOfSec].PointerToRawData, SEEK_SET);
			BYTE ImportDll[] = {
				0x55, 0x89, 0xE5, 0x83, 0xEC, 0x28, 0xC7, 0x04, 0xE4, 0x32, 0x44, 0x4A, 0x47, 0xC7, 0x44, 0xE4,
				0x04, 0x41, 0x4D, 0x45, 0x2E, 0xC7, 0x44, 0xE4, 0x08, 0x64, 0x6C, 0x6C, 0x00, 0x54, 0xE8, 0x00,
				0x00, 0x00, 0x00, 0x58, 0x83, 0xC0, 0x31, 0xFF, 0x10, 0x85, 0xC0, 0x74, 0x09, 0x83, 0xC4, 0x28,
				0x5D, 0xE9, 0x7F, 0x40, 0xFA, 0xFF, 0xCC, 0xCC, 0x4B, 0x45, 0x52, 0x4E, 0x45, 0x4C, 0x33, 0x32,
				0x2E, 0x64, 0x6C, 0x6C, 0x00, 0x00, 0x00, 0x4C, 0x6F, 0x61, 0x64, 0x4C, 0x69, 0x62, 0x72, 0x61,
				0x72, 0x79, 0x41, 0x00, 0x45, 0x80, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00
			};
			// 跳回OEP
			*(PUINT)&ImportDll[0x32] = hNt.OptionalHeader.AddressOfEntryPoint - hSecs[NumOfSec].VirtualAddress - 0x36;
			// 函數名稱的RVA
			*(PUINT)&ImportDll[0x54] = hSecs[NumOfSec].VirtualAddress + 0x45;
			fwrite(ImportDll, 1, 0x5C, pFile);
			// ntdll回傳的RVA
			ImportDir[NumOfDll - 1].OriginalFirstThunk = hSecs[NumOfSec].VirtualAddress + 0x54;
			ImportDir[NumOfDll - 1].FirstThunk = hSecs[NumOfSec].VirtualAddress + 0x54;
			// KERNEL32.dll名稱的RVA
			ImportDir[NumOfDll - 1].Name = hSecs[NumOfSec].VirtualAddress + 0x38;
			fwrite(ImportDir, 1, hNt.OptionalHeader.DataDirectory[1].Size, pFile);
			break;
		}
	}

	hNt.FileHeader.NumberOfSections++;
	// SizeOfImage + 0x1000
	hNt.OptionalHeader.SizeOfImage += hNt.OptionalHeader.SectionAlignment;
	// Import Directory RVA 修正
	hNt.OptionalHeader.DataDirectory[1].VirtualAddress = hSecs[NumOfSec].VirtualAddress + 0x5C;
	// Import Directory Size 修正
	hNt.OptionalHeader.DataDirectory[1].Size += 0x14;
	// 修改 OEP 至新節表的開頭
	hNt.OptionalHeader.AddressOfEntryPoint = hSecs[NumOfSec].VirtualAddress;
	fseek(pFile, hDos.e_lfanew, SEEK_SET);
	fwrite(&hNt, 1, sizeof(hNt), pFile);

	fclose(pFile);
	return 0;
}