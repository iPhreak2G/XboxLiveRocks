// XboxLiveRocks.c : Defines the entry point for the application.
//
#include "stdafx.h"
#include "hv.h"
#include "title.h"
#include "conn.h"
#include "xbox.h"
#include "serv.h"

BYTE macAddress[6];
BYTE KVHash[20];
BOOL Initialized = FALSE;
BOOL dashLoaded = FALSE;
BOOL XBLRocksInitialized = FALSE;
extern KEY_VAULT keyVault;
DWORD dwUpdateSequence;
VOID Wait(){
	while(!dashLoaded) Sleep(1);
	Tools::XNotifyUI("happy", L"XboxLiveRocks | Connected!");
}
HRESULT SetMacAddress() {	
	macAddress[0] = 0x00;
	macAddress[1] = 0x1D;
	macAddress[2] = 0xD8;
	macAddress[3] = keyVault.ConsoleCertificate.ConsoleId.asBits.MacIndex3;
	macAddress[4] = keyVault.ConsoleCertificate.ConsoleId.asBits.MacIndex4;
	macAddress[5] = keyVault.ConsoleCertificate.ConsoleId.asBits.MacIndex5;
	BYTE curMacAddress[6]; 
	WORD settingSize = 6;
	ExGetXConfigSetting(XCONFIG_SECURED_CATEGORY, XCONFIG_SECURED_MAC_ADDRESS, curMacAddress, 6, &settingSize);
	if(memcmp(curMacAddress, macAddress, 6) == 0) {
		DWORD temp = 0;
		XeCryptSha(macAddress, 6, NULL, NULL, NULL, NULL, (BYTE*)&temp, 4);
		dwUpdateSequence |= (temp & ~0xFF);
		return ERROR_SUCCESS;
	}
	if(NT_SUCCESS(ExSetXConfigSetting(XCONFIG_SECURED_CATEGORY, XCONFIG_SECURED_MAC_ADDRESS, macAddress, 6))) {
		Sleep(3000);
		HalReturnToFirmware(HalFatalErrorRebootRoutine);
	}
	return E_FAIL;
}
namespace XBLRocks {
	HRESULT Initialize()
	{
		Server::StartupServerCommincator();	
		if (Tools::CreateSymbolicLink("hdd:\\", "\\Device\\Harddisk0\\Partition1", TRUE) != ERROR_SUCCESS) 
		{
			return E_FAIL;
		}
		if(!GetModuleHandle("XboxLiveRocks.xex") || Tools::FileExists("LongLiveXbOnline.bin") || Tools::FileExists("Crack.bin")) {
			return E_FAIL;
		}
		if(Hv::InitializeHvPeekPoke() != ERROR_SUCCESS) {
			return E_FAIL;
		}
		if(InitializeSystemHooks() != TRUE) {
			return E_FAIL;
		}
		if(!InitializeSystemXexHooks()) {
			return E_FAIL;
		}
		if(SetKeyVault("hdd:\\kv.bin") != ERROR_SUCCESS){
			return E_FAIL;
		}
		if (SetMacAddress() != ERROR_SUCCESS) {
			return E_FAIL;
		}
		if (Serv::Communicate() == ERROR_SUCCESS){
			Tools::ThreadMe((LPTHREAD_START_ROUTINE)Wait);
		}
		Serv::MonitorThread();
		XBLRocksInitialized = true;
		return ERROR_SUCCESS;
	}
}

BOOL WINAPI DllMain(HANDLE hInstDLL, DWORD fdwReason, LPVOID lpReserved) {
	switch (fdwReason) {
		case DLL_PROCESS_ATTACH:
			Tools::ThreadMe((LPTHREAD_START_ROUTINE)XBLRocks::Initialize);
			break;
		case DLL_PROCESS_DETACH:
			break;
		case DLL_THREAD_ATTACH:
			break;
		case DLL_THREAD_DETACH:
			break;
	} return TRUE;
}