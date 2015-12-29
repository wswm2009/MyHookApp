#include "HookFunc.h"
#include "LDasm.h"


BOOL
WriteReadOnlyMemory(
    LPBYTE    lpDest,
    LPBYTE    lpSource,
    ULONG    Length
    )
{
    BOOL bRet;
    DWORD dwOldProtect;
    bRet = FALSE;

    if (!VirtualProtect(lpDest, Length, PAGE_EXECUTE_READWRITE, &dwOldProtect))
    {
        return bRet;
    }

    memcpy(lpDest, lpSource, Length);

    bRet = VirtualProtect(lpDest, Length, dwOldProtect, &dwOldProtect);

    return    bRet;
}

BOOL 
GetPatchSize(
    IN    void *Proc,            /* 需要Hook的函数地址 */
    IN    DWORD dwNeedSize,    /* Hook函数头部占用的字节大小 */
    OUT LPDWORD lpPatchSize    /* 返回根据函数头分析需要修补的大小 */
    )
{
    DWORD Length;
    PUCHAR pOpcode;
    DWORD PatchSize = 0;
	ldasm_data data = { 0 };

    if (!Proc || !lpPatchSize)
    {
        return FALSE;
    }

    do
    {
		Length = ldasm(Proc, &data, is_x64);
	
		pOpcode = (unsigned char*)Proc + data.opcd_offset;
        if ((Length == 1) && (*pOpcode == 0xC3))
            break;
        if ((Length == 3) && (*pOpcode == 0xC2))
            break;
        Proc = (PVOID)((DWORD)Proc + Length);

        PatchSize += Length;
        if (PatchSize >= dwNeedSize)
        {
            break;
        }

    }while(Length);


    *lpPatchSize = PatchSize;

    return TRUE;
}

BOOL InlineHook(
    IN    void *OrgProc,        /* 需要Hook的函数地址 */
    IN    void *NewProc,        /* 代替被Hook函数的地址 */
    OUT    void **RealProc        /* 返回原始函数的入口地址 */
    )
{
    DWORD dwPatchSize;    // 得到需要patch的字节大小
    //DWORD dwOldProtect;
    LPVOID lpHookFunc;    // 分配的Hook函数的内存
    DWORD dwBytesNeed;    // 分配的Hook函数的大小
    LPBYTE lpPatchBuffer; // jmp 指令的临时缓冲区

    if (!OrgProc || !NewProc || !RealProc)
    {
        return FALSE;
    }
    // 得到需要patch的字节大小
    if (!GetPatchSize(OrgProc, JMP_SIZE, &dwPatchSize))
    {
        return FALSE;
    }

    /*
    0x00000800                    0x00000800        sizeof(DWORD)    // dwPatchSize
    JMP    / FAR 0xAABBCCDD        E9 DDCCBBAA        JMP_SIZE
    ...                            ...                dwPatchSize        // Backup instruction
    JMP    / FAR 0xAABBCCDD        E9 DDCCBBAA        JMP_SIZE
    */

    dwBytesNeed = sizeof(DWORD) + JMP_SIZE + dwPatchSize + JMP_SIZE;

    lpHookFunc = __malloc(dwBytesNeed);

    //备份dwPatchSize到lpHookFunc
    *(DWORD *)lpHookFunc = dwPatchSize;

    //跳过开头的4个字节
    lpHookFunc = (LPVOID)((DWORD)lpHookFunc + sizeof(DWORD));

    //开始backup函数开头的字
    memcpy((BYTE *)lpHookFunc + JMP_SIZE, OrgProc, dwPatchSize);

    lpPatchBuffer = (LPBYTE)__malloc(dwPatchSize);

    //NOP填充
    memset(lpPatchBuffer, 0x90, dwPatchSize);

    //jmp到Hook
    *(BYTE *)lpHookFunc = 0xE9;
    *(DWORD*)((DWORD)lpHookFunc + 1) = (DWORD)NewProc - (DWORD)lpHookFunc - JMP_SIZE;

    //跳回原始
    *(BYTE *)((DWORD)lpHookFunc + 5 + dwPatchSize) = 0xE9;
    *(DWORD*)((DWORD)lpHookFunc + 5 + dwPatchSize + 1) = ((DWORD)OrgProc + dwPatchSize) - ((DWORD)lpHookFunc + JMP_SIZE + dwPatchSize) - JMP_SIZE;


    //jmp 
    *(BYTE *)lpPatchBuffer = 0xE9;
    //注意计算长度的时候得用OrgProc
    *(DWORD*)(lpPatchBuffer + 1) = (DWORD)lpHookFunc - (DWORD)OrgProc - JMP_SIZE;

    WriteReadOnlyMemory((LPBYTE)OrgProc, lpPatchBuffer, dwPatchSize);

    __free(lpPatchBuffer);

    *RealProc = (void *)((DWORD)lpHookFunc + JMP_SIZE);

    return TRUE;
}

BOOL UnInlineHook(
    void *OrgProc,  /* 需要恢复Hook的函数地址 */
    void *RealProc  /* 原始函数的入口地址 */
    )
{
	BOOL bResult =FALSE;
    DWORD dwPatchSize;
    //DWORD dwOldProtect;
    LPBYTE lpBuffer;

    //找到分配的空间
    lpBuffer = (LPBYTE)((DWORD)RealProc - (sizeof(DWORD) + JMP_SIZE));
    //得到dwPatchSize
    dwPatchSize = *(DWORD *)lpBuffer;

    bResult=WriteReadOnlyMemory((LPBYTE)OrgProc, (LPBYTE)RealProc, dwPatchSize);

    //释放分配的跳转函数的空间
    __free(lpBuffer);

    return bResult;
}


bool IATHook(char *LibraryName,PVOID Hook,PVOID NewFunctionAddress)
{
	PIMAGE_DOS_HEADER pDosHead =NULL;
	PIMAGE_NT_HEADERS pNtHead = NULL;
	DWORD ImportLibNum = 0;  // 导入表的库个数
	PIMAGE_IMPORT_DESCRIPTOR lib = NULL;
	if (LibraryName==NULL ||Hook==NULL||NewFunctionAddress==NULL)
	{
		return false;
	}
	pDosHead = (PIMAGE_DOS_HEADER)GetModuleHandleA(NULL);
	if (pDosHead==NULL)
	{
		return false;
	}
	pNtHead = (PIMAGE_NT_HEADERS)((DWORD)pDosHead + (DWORD)pDosHead->e_lfanew);
	pNtHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	// 计算导入库的个数
	ImportLibNum = pNtHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
	ImportLibNum--;
	if (ImportLibNum<1)
	{
		return false;
	}
	// 定位到 导入表
	lib = (PIMAGE_IMPORT_DESCRIPTOR)((int)pDosHead+(int)(pNtHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress));
	while (lib)
	{
		char *name = NULL;
		name  = (char * )((char*)pDosHead +(DWORD)lib->Name);
		if (lstrcmpiA(LibraryName,name)==0)
		{
			IMAGE_THUNK_DATA* ThunkData = (IMAGE_THUNK_DATA*)((BYTE*)pDosHead+lib->FirstThunk);
			while (ThunkData)
			{
				if (IsBadWritePtr(&ThunkData->u1.Function,sizeof(DWORD))!=0)
				{
					ThunkData++;
				}
				if (ThunkData->u1.Function == (DWORD)Hook)
				{
					VirtualProtect(&ThunkData->u1.Function,4,PAGE_READWRITE,NULL);
					WriteProcessMemory(GetCurrentProcess(),&(ThunkData->u1.Function),&NewFunctionAddress,sizeof(DWORD),NULL);
					return true;
				}
				ThunkData++;
			}
			break;
		}
		lib++;
	}
	return false;
}



/************************************************************************/
/* 通过特征码的搜索获取要Hook的RVA    Add By Wm 2015年4月28日13:37:24  
   参数说明:
           hModule : 要在哪个模块搜索
		   pPattern: 特征码?? 替换成 2B
		   dwPatternLen: 特征码长度*/
/************************************************************************/
void *GetRvaBySearchPattern(HMODULE hModule, unsigned char *pPattern, DWORD dwPatternLen) 
{ 

	MEMORY_BASIC_INFORMATION mem;
	if (!VirtualQuery(hModule, &mem, sizeof(MEMORY_BASIC_INFORMATION))) 
		return NULL;


	DWORD dwStartAddr = (DWORD)mem.AllocationBase; 
	DWORD dwSearchLen = ((IMAGE_NT_HEADERS *)((DWORD)hModule + ((IMAGE_DOS_HEADER *)hModule)->e_lfanew))->OptionalHeader.SizeOfImage;
	DWORD dwEndAddr = dwStartAddr + dwSearchLen - dwPatternLen-1;


	while (dwStartAddr < dwEndAddr) //这里从文件的开始位置扫描,如果没有找到指定特征码的位置的话,就会跳出循环并结束扫描工作;否则会返回所查到的址
	{ 
		bool found = true;

		for (DWORD i = 0; i < dwPatternLen-1; i++) 
		{ 
			unsigned char code = *(unsigned char *)(dwStartAddr + i);
			//0x2A为跳转码的转换,比如当某一部分为 E8 AB CD 2E 76     call sub_xxxxxxxx时,
			//那么此时除了E8之外,其它的应该更换为2A
			if (pPattern[i] != 0x2B && pPattern[i] != code) 
			{ 
				found = false; 
				break; 
			} 
		}

		if (found) 
			return (void *)dwStartAddr;

		dwStartAddr++; 
	}

	return 0; 
}



