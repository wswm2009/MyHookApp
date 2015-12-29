#ifndef _HOOKFUNC_H
#define _HOOKFUNC_H




#include <windows.h>



#ifdef __cplusplus
extern "C"
{
#endif


#define __malloc(_s)    VirtualAlloc(NULL, _s, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
#define __free(_p)        VirtualFree(_p, 0, MEM_RELEASE)
#define JMP_SIZE        5



BOOL WriteReadOnlyMemory(LPBYTE    lpDest,LPBYTE    lpSource,ULONG    Length);

BOOL GetPatchSize(
             IN    void *Proc,            /* ��ҪHook�ĺ�����ַ */
             IN    DWORD dwNeedSize,    /* Hook����ͷ��ռ�õ��ֽڴ�С */
             OUT LPDWORD lpPatchSize    /* ���ظ��ݺ���ͷ������Ҫ�޲��Ĵ�С */
             );

BOOL InlineHook(
           IN    void *OrgProc,        /* ��ҪHook�ĺ�����ַ */
           IN    void *NewProc,        /* ���汻Hook�����ĵ�ַ */
           OUT    void **RealProc        /* ����ԭʼ��������ڵ�ַ */
           );

BOOL UnInlineHook(
				  void *OrgProc,  /* ��Ҫ�ָ�Hook�ĺ�����ַ */
				  void *RealProc  /* ԭʼ��������ڵ�ַ */
                  );

//Add 2014/11/24  
/************************************************************************/
/* ����:IATHOOK                                                         */
/************************************************************************/
bool IATHook(char *LibraryName,PVOID Hook,PVOID NewFunctionAddress);


/************************************************************************/
/* ͨ���������������ȡҪHook��RVA    Add By Wm 2015��4��28��13:37:24
����˵��:
hModule : Ҫ���ĸ�ģ������
pPattern: ������?? �滻�� 2B
dwPatternLen: �����볤��*/
/************************************************************************/
void *GetRvaBySearchPattern(HMODULE hModule, unsigned char *pPattern, DWORD dwPatternLen);

#ifdef __cplusplus
}
#endif


#endif