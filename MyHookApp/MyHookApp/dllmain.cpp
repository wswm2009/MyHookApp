#include "MyHookApp.h"


HINSTANCE hinst;
HWND hwndDLG;
HWND hMainWnd;
HANDLE handle1;
DWORD WINAPI PorcDllAttch(PVOID pArg);



BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call,LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		hinst=(HINSTANCE)hModule;
		//InstallHook();
		handle1=::CreateThread(NULL,0,PorcDllAttch,NULL,0,NULL);
		CloseHandle(handle1); 
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
        //UninstallHook();
		break;
	}
	return TRUE;
}
DWORD WINAPI PorcDllAttch(PVOID pArg)
{
	InstallHook();
	return 1;
}