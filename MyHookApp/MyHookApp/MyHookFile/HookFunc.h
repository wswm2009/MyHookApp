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
             IN    void *Proc,            /* 需要Hook的函数地址 */
             IN    DWORD dwNeedSize,    /* Hook函数头部占用的字节大小 */
             OUT LPDWORD lpPatchSize    /* 返回根据函数头分析需要修补的大小 */
             );

BOOL InlineHook(
           IN    void *OrgProc,        /* 需要Hook的函数地址 */
           IN    void *NewProc,        /* 代替被Hook函数的地址 */
           OUT    void **RealProc        /* 返回原始函数的入口地址 */
           );

BOOL UnInlineHook(
				  void *OrgProc,  /* 需要恢复Hook的函数地址 */
				  void *RealProc  /* 原始函数的入口地址 */
                  );

//Add 2014/11/24  
/************************************************************************/
/* 功能:IATHOOK                                                         */
/************************************************************************/
bool IATHook(char *LibraryName,PVOID Hook,PVOID NewFunctionAddress);


/************************************************************************/
/* 通过特征码的搜索获取要Hook的RVA    Add By Wm 2015年4月28日13:37:24
参数说明:
hModule : 要在哪个模块搜索
pPattern: 特征码?? 替换成 2B
dwPatternLen: 特征码长度*/
/************************************************************************/
void *GetRvaBySearchPattern(HMODULE hModule, unsigned char *pPattern, DWORD dwPatternLen);

#ifdef __cplusplus
}
#endif


#endif