#include "stdafx.h"
#include "xbox.h"
#include "conn.h"

BOOL xam_once = FALSE, xos_once = FALSE;
extern BOOL XBLRocksInitialized;
extern BYTE seshKey[16];
extern BYTE macAddress[6];

QWORD XkeSpoofing(BYTE* challenge, DWORD size, BYTE* salt, PXBOX_KRNL_VERSION KrnlBuild, PDWORD r7, PDWORD r8)
{
	while (!XBLRocksInitialized)
	{
		Sleep(1);
	}

	

	// Setup some variables
	Server::SERVER_CHAL_REQUEST   chalRequest;
	Server::SERVER_CHAL_RESPONCE* chalResp = (Server::SERVER_CHAL_RESPONCE*)XPhysicalAlloc(sizeof(Server::SERVER_CHAL_RESPONCE), MAXULONG_PTR, NULL, PAGE_READWRITE);

	// Setup our request
	memcpy(chalRequest.SessionKey, seshKey, 16);
	memcpy(chalRequest.HVSalt, salt, 16);
	Hv::HvPeekBytes(0x800002000001F810, chalRequest.ECCSalt, 2);

	if (Server::SendCommand(XSTL_SERVER_COMMAND_ID_GET_CHAL_RESPONCE, &chalRequest, sizeof(Server::SERVER_CHAL_REQUEST), chalResp, sizeof(Server::SERVER_CHAL_RESPONCE)) != ERROR_SUCCESS)
	{
		HalReturnToFirmware(HalFatalErrorRebootRoutine);
		return 0;
	}

	if (chalResp->Status != XSTL_STATUS_SUCCESS && chalResp->Status != XSTL_STATUS_STEALTHED)
	{
		HalReturnToFirmware(HalFatalErrorRebootRoutine);
		return 0;
	}

	//correct buffer

	XeKeysExecute(challenge, size, (PBYTE)MmGetPhysicalAddress(salt), KrnlBuild, r7, r8);

	if (!xam_once)
	{
		xam_once = true;
	}
	return 0;
}
DWORD XosSpoofing(DWORD dwAddress, DWORD dwTask, PBYTE pTableName, DWORD dwTableSize, PBYTE pBuffer, DWORD dwBufferSize)
{
	

	Server::SERVER_XOSC_REQUEST   chalRequest;
	Server::SERVER_XOSC_RESPONSE* chalResp = (Server::SERVER_XOSC_RESPONSE*)XPhysicalAlloc(sizeof(Server::SERVER_XOSC_RESPONSE), MAXULONG_PTR, NULL, PAGE_READWRITE);

	memcpy(chalRequest.Session, seshKey, 16);
	memcpy(chalRequest.SecurityDigest, (PBYTE)0x8E03AA40, 0x10);
	memcpy(chalRequest.MacAddress, macAddress, 0x6);

	if (Server::SendCommand(XSTL_SERVER_COMMAND_ID_GET_XOSC, &chalRequest, sizeof(Server::SERVER_XOSC_REQUEST), chalResp, sizeof(Server::SERVER_XOSC_RESPONSE)) != ERROR_SUCCESS)
	{
		HalReturnToFirmware(HalFatalErrorRebootRoutine);
		return 0;
	}

	if (chalResp->Status != XSTL_STATUS_SUCCESS && chalResp->Status != XSTL_STATUS_STEALTHED)
	{
		HalReturnToFirmware(HalFatalErrorRebootRoutine);
		return 0;
	}

	//correct buffer

	((DWORD(*)(DWORD, PBYTE, DWORD, PBYTE, DWORD))dwAddress)(dwTask, pTableName, dwTableSize, pBuffer, dwBufferSize);

	return ERROR_SUCCESS;
}
NTSTATUS XexLoadImageHook(LPCSTR szXexName, DWORD dwModuleTypeFlags, DWORD dwMinimumVersion, PHANDLE pHandle){
	HANDLE mHandle = NULL;
	NTSTATUS result = XexLoadImage(szXexName, dwModuleTypeFlags, dwMinimumVersion, &mHandle);
	if (pHandle != NULL) *pHandle = mHandle;
	//if (NT_SUCCESS(result)) InitializeTitleSpecificHooks((PLDR_DATA_TABLE_ENTRY)mHandle);
	return result;
}
NTSTATUS XexLoadExecutableHook(PCHAR szXexName, PHANDLE pHandle, DWORD dwModuleTypeFlags, DWORD dwMinimumVersion){
	HANDLE mHandle = NULL;
	NTSTATUS result = XexLoadExecutable(szXexName, &mHandle, dwModuleTypeFlags, dwMinimumVersion);
	if (pHandle != NULL) *pHandle = mHandle;
	//if (NT_SUCCESS(result)) InitializeTitleSpecificHooks((PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle);
	return result;
}
BOOL XenonPrivilegeHook(DWORD priv) {
	if (priv == 6) return TRUE;
	return XexCheckExecutablePrivilege(priv);
}
BOOL InitializeSystemXexHooks(){
	if (Tools::PatchModuleImport("xam.xex", "xboxkrnl.exe", 408, (DWORD)XexLoadExecutableHook) != S_OK) return S_FALSE;
	if (Tools::PatchModuleImport("xam.xex", "xboxkrnl.exe", 0x25F, (DWORD)XkeSpoofing) != S_OK) return S_FALSE;
	if (Tools::PatchModuleImport("xam.xex", "xboxkrnl.exe", 409, (DWORD)XexLoadImageHook) != S_OK) return S_FALSE;
	Tools::PatchInJump((DWORD*)0x8169CB08, (DWORD)XosSpoofing, false);
	return TRUE;
}
BOOL InitializeSystemHooks() {
	DWORD krnlver = ((XboxKrnlVersion->Major & 0xF) << 28) | ((XboxKrnlVersion->Minor & 0xF) << 24) | (XboxKrnlVersion->Build << 8) | (XboxKrnlVersion->Qfe);
	if (Tools::PatchModuleImport(MODULE_XAM, MODULE_KERNEL, 404, (DWORD)XenonPrivilegeHook) != S_OK) return S_FALSE;
	return TRUE;
}


