#include "stdafx.h"
#include "serv.h"
#include "hv.h"

BYTE seshKey[16];
extern BYTE KVHash[20];
KEY_VAULT keyVault;
byte KeyVaultBytes[0x4000];
BYTE cpuKeyBytes[0x10];
byte ExecutableHash[16];
Server::SERVER_GET_CUSTOM_RESPONCE cData;
extern BOOL dashLoaded; 
short serverErrors = -1;
namespace Serv {
	void presenceThread() {
	
		Server::SERVER_UPDATE_PRESENCE_REQUEST  req;
		Server::SERVER_UPDATE_PRESENCE_RESPONCE resp;
		while (TRUE) {
			while (!dashLoaded) Sleep(1);
			memcpy(req.SessionKey, seshKey, 0x10);
			memcpy(req.ExecutableHash, ExecutableHash, 0x10);
			req.TitleId = XamGetCurrentTitleId();
			XUSER_SIGNIN_INFO userInfo; 
			memcpy(&userInfo, 0, sizeof(XUSER_SIGNIN_INFO));
			if (XUserGetSigninInfo(0, XUSER_GET_SIGNIN_INFO_ONLINE_XUID_ONLY, &userInfo) == ERROR_SUCCESS) {
				memcpy(req.Gamertag, userInfo.szUserName, 16);
				req.Xuid = (char)userInfo.xuid;
			}
			memcpy(req.kvhash, KVHash, 20);
			req.banned = 1; //static for now, alweys band yeye
			if (Server::SendCommand(XSTL_SERVER_COMMAND_ID_UPDATE_PRESENCE, &req, sizeof(Server::SERVER_UPDATE_PRESENCE_REQUEST), &resp, sizeof(Server::SERVER_UPDATE_PRESENCE_RESPONCE), true) != ERROR_SUCCESS) {
				switch (serverErrors++) {
				case 0:
					Tools::XNotifyUI("sad", L"XBLRocks | Connection Error! Reconnecting...");
					break;
				case 1:
					Tools::XNotifyUI("sad", L"XBLRocks | Failed! Reconnecting...");
					break;
				case 2:
					break;
				case 3:
					Tools::XNotifyUI("sad", L"XBLRocks | Disconnected!");
					Sleep(5000);
					HalReturnToFirmware(HalFatalErrorRebootRoutine);
					break;
				}
			}
			else {
				switch (resp.Status) {
				case XSTL_STATUS_SUCCESS:
					Server::EndCommand();
					break;
				case XSTL_STATUS_BANNED:
					Server::EndCommand();
					Tools::XNotifyUI("sad", L"XboxLiveRocks | Banned!");
					break;
				case XSTL_STATUS_UPDATE:
						Sleep(500);
						Tools::XNotifyUI("happy", L"XboxLiveRocks | Update Available!");
						break; //manual update required, cbf
				case XSTL_STATUS_EXPIRED:
					Server::EndCommand();
					Tools::XNotifyUI("sad", L"XboxLiveRocks | Time Expired!");
					Sleep(15000);
					HalReturnToFirmware(HalResetSMCRoutine);
					break;
				case XSTL_STATUS_ERROR:
					Server::EndCommand();
					Tools::XNotifyUI("sad", L"XBLRocks | Server Error [0xDEAD4040]!");
					break;
				default:
					Server::EndCommand();
					Tools::XNotifyUI("sad", L"XBLRocks | Server Error [0xDEAD4010]!");
					Sleep(4000);
					HalReturnToFirmware(HalResetSMCRoutine);
				}
			}
			Sleep(59500); //updates every minute, more efficient with over 1500 xblr customers & broke owner.
		}
	}

	HRESULT Authenticate() {
	Server::SERVER_GET_SALT_REQUEST* request = (Server::SERVER_GET_SALT_REQUEST*)XPhysicalAlloc(sizeof(Server::SERVER_GET_SALT_REQUEST), MAXULONG_PTR, NULL, PAGE_READWRITE);
	Server::SERVER_GET_SALT_RESPONCE responce;

	request->Version = XSTL_SERVER_VER;
	request->ConsoleType = 0; //no devkit support, mus nawt leek devkite suport
	
	memcpy(request->CpuKey, cpuKeyBytes, 16);
	memcpy(KeyVaultBytes, &keyVault, 0x4000);
	memcpy(request->KeyVault, KeyVaultBytes, 0x4000);


	if(Server::SendCommand(XSTL_SERVER_COMMAND_ID_GET_SALT, request, sizeof(Server::SERVER_GET_SALT_REQUEST), &responce, sizeof(Server::SERVER_GET_SALT_RESPONCE), TRUE) != ERROR_SUCCESS) {
		return E_FAIL;
	}
	XPhysicalFree(request);

	HRESULT retVal = E_FAIL;
	switch(responce.Status) {
		case XSTL_STATUS_SUCCESS:
			retVal = Server::ReceiveData(seshKey, 16);
			Server::EndCommand();
			return retVal;
		case XSTL_STATUS_FREEMODE:
			retVal = Server::ReceiveData(seshKey, 16);
			Server::EndCommand();
			return retVal;
		case XSTL_STATUS_EXPIRED:
			Server::EndCommand();
		    return ERROR_SUCCESS;
		case XSTL_STATUS_ERROR:
			Server::EndCommand();
			return E_FAIL;
		default: 
			Server::EndCommand();
			return E_FAIL;
	}
	return E_FAIL;
}

	HRESULT AuthStage2() {
	Server::SERVER_GET_STATUS_REQUEST statusRequest;
	Server::SERVER_GET_STATUS_RESPONCE statusResponce;
	Tools::MemoryBuffer mbXBLRocks;
	if(CReadFile("hdd:\\XboxLiveRocks.xex", mbXBLRocks) != TRUE) {
		
		return E_FAIL;
	}
	XeCryptHmacSha(seshKey, 16, mbXBLRocks.GetData(), mbXBLRocks.GetDataLength(), NULL, 0, NULL, 0, statusRequest.ExecutableHash, 16);
	memcpy(ExecutableHash, statusRequest.ExecutableHash, 0x10);
	memcpy(statusRequest.CpuKey, cpuKeyBytes, 16);
	if(Server::SendCommand(XSTL_SERVER_COMMAND_ID_GET_STATUS, &statusRequest, sizeof(Server::SERVER_GET_STATUS_REQUEST), &statusResponce, sizeof(Server::SERVER_GET_STATUS_RESPONCE), true) != ERROR_SUCCESS) {
		
		return E_FAIL;
	}
	switch(statusResponce.Status) {
		case XSTL_STATUS_SUCCESS:
			Server::EndCommand();
			return ERROR_SUCCESS;
		case XSTL_STATUS_EXPIRED:
			Server::EndCommand();
		    return E_FAIL;
		case XSTL_STATUS_UPDATE:
			return E_FAIL;
		case XSTL_STATUS_ERROR:
			Server::EndCommand();
			return E_FAIL;
		default: 
			Server::EndCommand();
			return E_FAIL;
	}

	return E_FAIL;
}	
	HRESULT getStats(){
	
		Server::SERVER_GET_CUSTOM_REQUEST req;
		memcpy(req.SessionKey, seshKey, 16);
		if(SendCommand(XSTL_SERVER_COMMAND_ID_GET_CUSTOM, &req, sizeof(Server::SERVER_GET_CUSTOM_REQUEST), &cData, sizeof(Server::SERVER_GET_CUSTOM_RESPONCE)) != ERROR_SUCCESS){
			return E_FAIL;
		}
	
		Tools::applyPatchData(cData.xamPatchData);
		return ERROR_SUCCESS;
	}


	VOID MonitorThread(){
		HANDLE hThread; 
		DWORD threadId;
		ExCreateThread(&hThread, 0, &threadId, (VOID*)XapiThreadStartup, (LPTHREAD_START_ROUTINE)presenceThread, NULL, 0x2 | CREATE_SUSPENDED);
		XSetThreadProcessor(hThread, 4);
		SetThreadPriority(hThread, THREAD_PRIORITY_ABOVE_NORMAL);
		ResumeThread(hThread);
	}

	HRESULT Communicate(){
		if (Serv::Authenticate() != ERROR_SUCCESS) {
			return E_FAIL;
		} 
		if (Serv::AuthStage2 != ERROR_SUCCESS) {
			return E_FAIL;
		}
		if(Serv::getStats != ERROR_SUCCESS){
			return E_FAIL;
		return ERROR_SUCCESS; 
	}
}
}