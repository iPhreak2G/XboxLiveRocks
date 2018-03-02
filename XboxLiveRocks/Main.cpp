#include "stdafx.h"
namespace Main {

	void MountPaths()
	{
		if ((XboxHardwareInfo->Flags & 0x20) == 0x20)
			if (Tools::CreateSymbolicLink("Cheats:\\", "\\Device\\Harddisk0\\Partition1", true) != ERROR_SUCCESS)
				return;
		else
			if (Tools::CreateSymbolicLink("Cheats:\\", "\\Device\\Mass0", true) != ERROR_SUCCESS)
				return;
	}

	void LoadHooks()
	{
		if (Tools::PatchModuleImport(MODULE_XAM, MODULE_KERNEL, 408, (DWORD)System::XexLoadExecutableHook) != S_OK) return;
		if (Tools::PatchModuleImport(MODULE_XAM, MODULE_KERNEL, 409, (DWORD)System::XexLoadImageHook) != S_OK) return;
	}

	void Initialize()
	{
		MountPaths();
		LoadHooks();
	}
}

BOOL APIENTRY DllMain(HANDLE hModule, DWORD dwReason, LPVOID lpReserved)
{
	if ( dwReason == DLL_PROCESS_ATTACH ) 
	{
 		if (XamLoaderGetDvdTrayState() == DVD_TRAY_STATE_OPEN) printf("/");
		else Main::Initialize();
	}
	return TRUE;
}
