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
    IN    void *Proc,            /* ��ҪHook�ĺ�����ַ */
    IN    DWORD dwNeedSize,    /* Hook����ͷ��ռ�õ��ֽڴ�С */
    OUT LPDWORD lpPatchSize    /* ���ظ��ݺ���ͷ������Ҫ�޲��Ĵ�С */
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
    IN    void *OrgProc,        /* ��ҪHook�ĺ�����ַ */
    IN    void *NewProc,        /* ���汻Hook�����ĵ�ַ */
    OUT    void **RealProc        /* ����ԭʼ��������ڵ�ַ */
    )
{
    DWORD dwPatchSize;    // �õ���Ҫpatch���ֽڴ�С
    //DWORD dwOldProtect;
    LPVOID lpHookFunc;    // �����Hook�������ڴ�
    DWORD dwBytesNeed;    // �����Hook�����Ĵ�С
    LPBYTE lpPatchBuffer; // jmp ָ�����ʱ������

    if (!OrgProc || !NewProc || !RealProc)
    {
        return FALSE;
    }
    // �õ���Ҫpatch���ֽڴ�С
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

    //����dwPatchSize��lpHookFunc
    *(DWORD *)lpHookFunc = dwPatchSize;

    //������ͷ��4���ֽ�
    lpHookFunc = (LPVOID)((DWORD)lpHookFunc + sizeof(DWORD));

    //��ʼbackup������ͷ����
    memcpy((BYTE *)lpHookFunc + JMP_SIZE, OrgProc, dwPatchSize);

    lpPatchBuffer = (LPBYTE)__malloc(dwPatchSize);

    //NOP���
    memset(lpPatchBuffer, 0x90, dwPatchSize);

    //jmp��Hook
    *(BYTE *)lpHookFunc = 0xE9;
    *(DWORD*)((DWORD)lpHookFunc + 1) = (DWORD)NewProc - (DWORD)lpHookFunc - JMP_SIZE;

    //����ԭʼ
    *(BYTE *)((DWORD)lpHookFunc + 5 + dwPatchSize) = 0xE9;
    *(DWORD*)((DWORD)lpHookFunc + 5 + dwPatchSize + 1) = ((DWORD)OrgProc + dwPatchSize) - ((DWORD)lpHookFunc + JMP_SIZE + dwPatchSize) - JMP_SIZE;


    //jmp 
    *(BYTE *)lpPatchBuffer = 0xE9;
    //ע����㳤�ȵ�ʱ�����OrgProc
    *(DWORD*)(lpPatchBuffer + 1) = (DWORD)lpHookFunc - (DWORD)OrgProc - JMP_SIZE;

    WriteReadOnlyMemory((LPBYTE)OrgProc, lpPatchBuffer, dwPatchSize);

    __free(lpPatchBuffer);

    *RealProc = (void *)((DWORD)lpHookFunc + JMP_SIZE);

    return TRUE;
}

BOOL UnInlineHook(
    void *OrgProc,  /* ��Ҫ�ָ�Hook�ĺ�����ַ */
    void *RealProc  /* ԭʼ��������ڵ�ַ */
    )
{
	BOOL bResult =FALSE;
    DWORD dwPatchSize;
    //DWORD dwOldProtect;
    LPBYTE lpBuffer;

    //�ҵ�����Ŀռ�
    lpBuffer = (LPBYTE)((DWORD)RealProc - (sizeof(DWORD) + JMP_SIZE));
    //�õ�dwPatchSize
    dwPatchSize = *(DWORD *)lpBuffer;

    bResult=WriteReadOnlyMemory((LPBYTE)OrgProc, (LPBYTE)RealProc, dwPatchSize);

    //�ͷŷ������ת�����Ŀռ�
    __free(lpBuffer);

    return bResult;
}


bool IATHook(char *LibraryName,PVOID Hook,PVOID NewFunctionAddress)
{
	PIMAGE_DOS_HEADER pDosHead =NULL;
	PIMAGE_NT_HEADERS pNtHead = NULL;
	DWORD ImportLibNum = 0;  // �����Ŀ����
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
	// ���㵼���ĸ���
	ImportLibNum = pNtHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
	ImportLibNum--;
	if (ImportLibNum<1)
	{
		return false;
	}
	// ��λ�� �����
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
/* ͨ���������������ȡҪHook��RVA    Add By Wm 2015��4��28��13:37:24  
   ����˵��:
           hModule : Ҫ���ĸ�ģ������
		   pPattern: ������?? �滻�� 2B
		   dwPatternLen: �����볤��*/
/************************************************************************/
void *GetRvaBySearchPattern(HMODULE hModule, unsigned char *pPattern, DWORD dwPatternLen) 
{ 

	MEMORY_BASIC_INFORMATION mem;
	if (!VirtualQuery(hModule, &mem, sizeof(MEMORY_BASIC_INFORMATION))) 
		return NULL;


	DWORD dwStartAddr = (DWORD)mem.AllocationBase; 
	DWORD dwSearchLen = ((IMAGE_NT_HEADERS *)((DWORD)hModule + ((IMAGE_DOS_HEADER *)hModule)->e_lfanew))->OptionalHeader.SizeOfImage;
	DWORD dwEndAddr = dwStartAddr + dwSearchLen - dwPatternLen-1;


	while (dwStartAddr < dwEndAddr) //������ļ��Ŀ�ʼλ��ɨ��,���û���ҵ�ָ���������λ�õĻ�,�ͻ�����ѭ��������ɨ�蹤��;����᷵�����鵽��ַ
	{ 
		bool found = true;

		for (DWORD i = 0; i < dwPatternLen-1; i++) 
		{ 
			unsigned char code = *(unsigned char *)(dwStartAddr + i);
			//0x2AΪ��ת���ת��,���統ĳһ����Ϊ E8 AB CD 2E 76     call sub_xxxxxxxxʱ,
			//��ô��ʱ����E8֮��,������Ӧ�ø���Ϊ2A
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



