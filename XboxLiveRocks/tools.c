#include "stdafx.h"
#include "tools.h"
extern KEY_VAULT keyVault;
#define hvKvPtrDev      0x00000002000162e0
#define hvKvPtrRetail   0x0000000200016240

#pragma warning(push)
#pragma warning(disable:4826) // Get rid of the sign-extended warning

const BYTE RetailKey19[0x10]		= { 0xE1, 0xBC, 0x15, 0x9C, 0x73, 0xB1, 0xEA, 0xE9, 0xAB, 0x31, 0x70, 0xF3, 0xAD, 0x47, 0xEB, 0xF3 };
HRESULT SetKeyVault(BYTE* KeyVault) {
	memcpy(&keyVault, KeyVault, 0x4000);
	
	memcpy((PVOID)0x8E03A000, &keyVault.ConsoleCertificate, 0x1A8);
	if(1 == 0) {
		memcpy((BYTE*)((*(DWORD*)0x81D59F68) + 0x313C), &keyVault.ConsoleCertificate, 0x1A8); // CXNetLogonTask * g_pXNetLogonTask handle // v16203
	}
	
    memcpy((PVOID)0x8E038020, &keyVault.ConsoleCertificate.ConsoleId.abData, 5);

	BYTE newHash[XECRYPT_SHA_DIGEST_SIZE];
	XeCryptSha((BYTE*)0x8E038014, 0x3EC, NULL, NULL, NULL, NULL, newHash, XECRYPT_SHA_DIGEST_SIZE);
    memcpy((PVOID)0x8E038000, newHash, XECRYPT_SHA_DIGEST_SIZE);

	QWORD kvAddress = (1 == 0) ? Hv::HvPeekQWORD(hvKvPtrDev) : Hv::HvPeekQWORD(hvKvPtrRetail);

	Hv::HvPeekBytes(kvAddress + 0xD0, &keyVault.ConsoleObfuscationKey, 0x40);
	memcpy(keyVault.RoamableObfuscationKey, RetailKey19, 0x10);
	Hv::HvPokeBytes(kvAddress, &keyVault, 0x4000);

	//DbgPrint("[KV] Kv Set");

	// All done
	return ERROR_SUCCESS;
}
HRESULT SetKeyVault(CHAR* FilePath) {
	Tools::MemoryBuffer mbKv;
	if(!Tools::CReadFile(FilePath, mbKv)) {
		return E_FAIL;
	}

	return SetKeyVault(mbKv.GetData());
}

namespace Tools {
	BOOL XeKeysPkcs1Verify(const BYTE* pbHash, const BYTE* pbSig, XECRYPT_RSA* pRsa) {
		BYTE scratch[256];
		DWORD val = pRsa->cqw << 3;
		if (val <= 0x200) {
			XeCryptBnQw_SwapDwQwLeBe((QWORD*)pbSig, (QWORD*)scratch, val >> 3);
			if (XeCryptBnQwNeRsaPubCrypt((QWORD*)scratch, (QWORD*)scratch, pRsa) == 0) return FALSE;
			XeCryptBnQw_SwapDwQwLeBe((QWORD*)scratch, (QWORD*)scratch, val >> 3);
			return XeCryptBnDwLePkcs1Verify((const PBYTE)pbHash, scratch, val);
		}
		else return FALSE;
	}
	DWORD applyPatchData(PVOID buffer){
		DWORD PatchCount = NULL;
		PDWORD PatchData = (PDWORD)buffer;
		while(*PatchData != 0xFFFFFFFF)
		{
			memcpy((PVOID)PatchData[0], &PatchData[2], PatchData[1] * sizeof(DWORD));
			PatchData += (PatchData[1] + 2);
			PatchCount++;
		}

		return PatchCount;
	}
	void ThreadMe(LPTHREAD_START_ROUTINE lpStartAddress) {
		HANDLE handle;
		DWORD lpThreadId;
		ExCreateThread(&handle, 0, &lpThreadId, (void*)XapiThreadStartup, lpStartAddress, NULL, 0x2 | CREATE_SUSPENDED);
		XSetThreadProcessor(handle, 4);
		SetThreadPriority(handle, THREAD_PRIORITY_ABOVE_NORMAL);
		ResumeThread(handle);
	}	
	void __declspec(naked) GLPR(void) {
		__asm {
			std     r14, -0x98(sp)
				std     r15, -0x90(sp)
				std     r16, -0x88(sp)
				std     r17, -0x80(sp)
				std     r18, -0x78(sp)
				std     r19, -0x70(sp)
				std     r20, -0x68(sp)
				std     r21, -0x60(sp)
				std     r22, -0x58(sp)
				std     r23, -0x50(sp)
				std     r24, -0x48(sp)
				std     r25, -0x40(sp)
				std     r26, -0x38(sp)
				std     r27, -0x30(sp)
				std     r28, -0x28(sp)
				std     r29, -0x20(sp)
				std     r30, -0x18(sp)
				std     r31, -0x10(sp)
				stw     r12, -0x8(sp)
				blr
		}
	}
	DWORD RelinkGPLR(DWORD SFSOffset, DWORD* SaveStubAddress, DWORD* OriginalAddress) {
		DWORD Instruction = 0, Replacing;
		DWORD* Saver = (DWORD*)GLPR;
		if (SFSOffset & 0x2000000)
			SFSOffset = SFSOffset | 0xFC000000;

		Replacing = OriginalAddress[SFSOffset / 4];
		for (int i = 0; i < 20; i++) {
			if (Replacing == Saver[i]) {
				DWORD NewOffset = (DWORD)&Saver[i] - (DWORD)SaveStubAddress;
				Instruction = 0x48000001 | (NewOffset & 0x3FFFFFC);
			}
		}
		return Instruction;
	}
	DWORD ApplyPatches(void* buffer)
	{
		DWORD PatchCount = NULL;
		DWORD* PatchData = (DWORD*)buffer;
		while (*PatchData != 0xFFFFFFFF) 
		{
			memcpy((void*)PatchData[0], &PatchData[2], PatchData[1] * sizeof(DWORD));
			PatchData += (PatchData[1] + 2);
			PatchCount++;
		}
		return PatchCount;
	}
	void HookFunctionStart(DWORD* Address, DWORD* SaveStub, DWORD Destination)
	{
		if ((SaveStub != NULL) && (Address != NULL)) {
			DWORD AddressRelocation = (DWORD)(&Address[4]);
			if (AddressRelocation & 0x8000)
				SaveStub[0x00] = 0x3D600000 + (((AddressRelocation >> 0x10) & 0xFFFF) + 0x01);
			else
				SaveStub[0x00] = 0x3D600000 + ((AddressRelocation >> 0x10) & 0xFFFF);
			SaveStub[0x01] = 0x396B0000 + (AddressRelocation & 0xFFFF);
			SaveStub[0x02] = 0x7D6903A6;
			for (int i = 0; i < 0x04; i++) {
				if ((Address[i] & 0x48000003) == 0x48000001) SaveStub[i + 0x03] = RelinkGPLR((Address[i] & ~0x48000003), &SaveStub[i + 0x03], &Address[i]);
				else SaveStub[i + 0x03] = Address[i];
			}
			SaveStub[0x07] = 0x4E800420;
			__dcbst(0x00, SaveStub);
			__sync();
			__isync();
			PatchInJump(Address, Destination, false);
		}
	}
	void PatchInJump(DWORD* Address, DWORD Destination, bool Linked) {
		Address[0] = 0x3D600000 + ((Destination >> 16) & 0xFFFF);
		if (Destination & 0x8000) Address[0] += 1;
		Address[1] = 0x396B0000 + (Destination & 0xFFFF);
		Address[2] = 0x7D6903A6;
		Address[3] = Linked ? 0x4E800421 : 0x4E800420;
	}
	void PatchInBranch(DWORD* Address, DWORD Destination, bool Linked) {
		Address[0] = (0x48000000 + ((Destination - (DWORD)Address) & 0x3FFFFFF));
		if (Linked) Address[0] += 1;
	}
	FARPROC ResolveFunction(char* ModuleName, DWORD Ordinal) {
		HMODULE mHandle = GetModuleHandle(ModuleName);
		return (mHandle == NULL) ? NULL : GetProcAddress(mHandle, (LPCSTR)Ordinal);
	}
	DWORD PatchModuleImport(char* Module, char* ImportedModuleName, DWORD Ordinal, DWORD PatchAddress) {
		LDR_DATA_TABLE_ENTRY* moduleHandle = (LDR_DATA_TABLE_ENTRY*)GetModuleHandle(Module);
		return (moduleHandle == NULL) ? S_FALSE : PatchModuleImport(moduleHandle, ImportedModuleName, Ordinal, PatchAddress);
	}
	DWORD PatchModuleImport(PLDR_DATA_TABLE_ENTRY Module, char* ImportedModuleName, DWORD Ordinal, DWORD PatchAddress) {
		DWORD address = (DWORD)ResolveFunction(ImportedModuleName, Ordinal);
		if (address == NULL) return S_FALSE;

		void* headerBase = Module->XexHeaderBase;
		PXEX_IMPORT_DESCRIPTOR importDesc = (PXEX_IMPORT_DESCRIPTOR)RtlImageXexHeaderField(headerBase, 0x000103FF);
		if (importDesc == NULL) return S_FALSE;

		DWORD result = 2;
		PCHAR stringTable = (PCHAR)(importDesc + 1);
		XEX_IMPORT_TABLE_ORG* importTable = (XEX_IMPORT_TABLE_ORG*)(stringTable + importDesc->NameTableSize);
		for (DWORD x = 0; x < importDesc->ModuleCount; x++) {
			DWORD* importAdd = (DWORD*)(importTable + 1);
			for (DWORD y = 0; y < importTable->ImportTable.ImportCount; y++) {
				DWORD value = *((DWORD*)importAdd[y]);
				if (value == address) {
					memcpy((DWORD*)(importAdd[y]), &PatchAddress, 4);
					DWORD newCode[4];
					PatchInJump(newCode, PatchAddress, false);
					memcpy((DWORD*)(importAdd[y + 1]), newCode, 16);
					result = S_OK;
				}
			}

			importTable = (XEX_IMPORT_TABLE_ORG*)(((BYTE*)importTable) + importTable->TableSize);
		}
		return result;
	}
	DWORD CreateSymbolicLink(char* szDrive, char* szDeviceName, bool System) {
		CHAR szDestinationDrive[MAX_PATH];
		sprintf_s(szDestinationDrive, MAX_PATH, System ? "\\System??\\%s" : "\\??\\%s", szDrive);

		ANSI_STRING linkname, devicename;
		RtlInitAnsiString(&linkname, szDestinationDrive);
		RtlInitAnsiString(&devicename, szDeviceName);
		if (FileExists(szDrive)) return S_OK;
		NTSTATUS status = ObCreateSymbolicLink(&linkname, &devicename);
		return (status >= 0) ? S_OK : S_FALSE;
	}
	bool CReadFile(const char* FileName, MemoryBuffer &pBuffer) {
		HANDLE hFile; DWORD dwFileSize, dwNumberOfBytesRead;
		hFile = CreateFile(FileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
			return false;

		dwFileSize = GetFileSize(hFile, NULL);
		BYTE* lpBuffer = (BYTE*)malloc(dwFileSize);
		if (lpBuffer == NULL) {
			CloseHandle(hFile);
			return false;
		}

		if (ReadFile(hFile, lpBuffer, dwFileSize, &dwNumberOfBytesRead, NULL) == FALSE) {
			free(lpBuffer);
			CloseHandle(hFile);
			return false;
		} else if (dwNumberOfBytesRead != dwFileSize) {
			free(lpBuffer);
			CloseHandle(hFile);
			return false;
		}

		CloseHandle(hFile);
		pBuffer.Add(lpBuffer, dwFileSize);
		free(lpBuffer);
		return true;
	}
	bool CWriteFile(const char* FilePath, const void* Data, DWORD Size) {
		HANDLE fHandle = CreateFile(FilePath, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (fHandle == INVALID_HANDLE_VALUE)
			return false;

		DWORD writeSize = Size;
		if (WriteFile(fHandle, Data, writeSize, &writeSize, NULL) != TRUE)
			return false;

		CloseHandle(fHandle);
		return true;
	}
	bool FileExists(LPCSTR lpFileName) {
		if (GetFileAttributes(lpFileName) == -1) {
			if (GetLastError() == ERROR_FILE_NOT_FOUND || GetLastError() == ERROR_PATH_NOT_FOUND)
				return false;
		}
		return true;
	}
	void XNotifyUI(char* Type, PWCHAR pwszStringParam) 
	{
		XNOTIFYQUEUEUI_TYPE eType;
		if (strcmp(Type, "happy") == 0)       eType = XNOTIFYUI_TYPE_PREFERRED_REVIEW;
		else if (strcmp(Type, "sad") == 0)    eType = XNOTIFYUI_TYPE_AVOID_REVIEW;
		else if (strcmp(Type, "hammer") == 0) eType = XNOTIFYUI_TYPE_COMPLAINT;
		else if (strcmp(Type, "xbox") == 0)   eType = XNOTIFYUI_TYPE_CONSOLEMESSAGE;
		else if (strcmp(Type, "mail") == 0)   eType = XNOTIFYUI_TYPE_MAILBOX;
		else /*Unsupported Type*/			  eType = XNOTIFYUI_TYPE_PREFERRED_REVIEW;

		XNotifyQueueUI(eType, XUSER_INDEX_ANY, XNOTIFYUI_PRIORITY_HIGH, pwszStringParam, NULL);
	}
}