// HookApiTst.cpp : Defines the exported functions for the DLL application.
//




#include "MyHookApp.h"
#include "MyHookFile/HookFunc.h"
#include "DetoursFile/detours.h"
#include "DataOperate/DataOperate.h"
#include "resource.h"
#pragma comment(lib, "DetoursFile/Detours.lib")

//加入Lua支持
extern "C" {    
#include "lua/lauxlib.h"
#include "lua/lua.h"
#include "lua/lualib.h"
} 

#pragma comment(lib,"lua/lua4.0.1.lib") 
//全局变量的声明

extern HINSTANCE hinst;
extern HWND hwndDLG;
extern HWND hMainWnd;
//全局变量的定义


HMODULE ghmod=NULL;
DWORD *gdwJmpRetAddr=NULL;

FILE *pfile = NULL;
BOOL IsHooked = FALSE;
DWORD gFlag=0;
unsigned char gValue=0;

DWORD gSrcBuffAddr=0;
DWORD gDecBuffAddr=0;
DWORD gHeight=0;
DWORD gWidth=0;
DWORD gA5=0;
DWORD gA6=0;


DWORD gSrcAddr=0;
DWORD gDstAddr=0;
DWORD gArg1_Addr=0;
DWORD gArg2_Addr=0;
DWORD gArg3_Addr=0;
DWORD gArg4_Addr=0;
DWORD gArg5_Addr=0;
DWORD gArg6_Addr=0;

//HOOK的RVA地址
DWORD gHookAddr1,gHookRetAddr1;
DWORD gHookAddr9,gHookRetAddr9;
DWORD gHookAddr2,gHookRetAddr2;
DWORD gHookAddr3,gHookRetAddr3;
DWORD gHookAddr4,gHookRetAddr4;








__declspec(naked) void Fake_Dispatch1(void)
{
	__asm
	{

	    	pushad
			pushfd
			push[eax - 0x2c]
		    call Fix_Dispatch1
			pop esi
			popfd
			popad
			jmp [gHookRetAddr1]
	}
}


BOOL HookInit()
{
	
	IsHooked=TRUE;
	HMODULE hmod=GetModuleHandleA(NULL);
	if(!hmod)
	{
		return FALSE;//失败
	}
	gHookAddr1 = ((0x00C41983 - 0x400000) + (DWORD)hmod);
	//这里是通过特征码搜索获取Hook的地址
	//gHookAddr2 = (DWORD)MH_SearchPattern(hmod,BrightAndConstrastSig, sizeof(BrightAndConstrastSig));//正常情况下,g_pOrigin返回就是特征所指向的函数地址了^^
   
    return TRUE;
}
BOOL InstallHook()
{   
    BOOL bResult=FALSE; 
	if (IsHooked)
	{
		return FALSE;
	}
    if (!HookInit())
    {
		return FALSE;
    }



	//第一种方式的HOOK  目前只知道在HOOK API的时候才用这个Detours.lib
	// 	DetourTransactionBegin();  
	// 	DetourUpdateThread(GetCurrentThread());  
	// 	gdwMessageBox=(pfnMessageBoxA)DetourFindFunction("user32.dll", "MessageBoxA");
	// 	DetourAttach((PVOID *)&gdwMessageBox, NEW_MessageBoxA);
	// 	DetourTransactionCommit(); 


	/*第二种方式  只需HOOK的地址，  和自己的函数地址，和一个Void** 变量 它自动获取到返回地址*/
	 
	bResult= InlineHook((void *)gHookAddr1,(void *)&Fake_Dispatch1,(void **)&gHookRetAddr1);
	/*第三种方式 IATHOOK*/
	// 	HMODULE hModule = GetModuleHandleA("user32.dll");
	// 	gdwMessageBox = (pfnMessageBoxA)GetProcAddress(hModule,"MessageBoxA");
	// 	if(IATHook("user32.dll",(PVOID)gdwMessageBox,NEW_MessageBoxA)==false)
	// 	{
	// 		//MessageBoxA(0,"Hook 目标进程XX函数失败！","错误",MB_OK);
	// 		;
	// 	}

	return bResult;
}

BOOL UninstallHook()
{
	BOOL bResult=FALSE;
	if (IsHooked)
	{
		 bResult=UnInlineHook((void *)gHookAddr1,(void *)&Fake_Dispatch1);
	}
	return bResult;
}

