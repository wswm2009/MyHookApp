#ifndef _HOOKAPITST_H
#define _HOOKAPITST_H

#ifdef __cplusplus
extern "C"
{
#endif

#ifdef  HSDHDLSL
#define DLL_EXPORT_IMPORT __declspec(dllexport)
#else
#define DLL_EXPORT_IMPORT __declspec(dllimport)
#endif

#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <time.h>
#include <string.h>


//特征码宏定义
#define  PATTERNSIG  "\xC7\x45\x0C\x2B\x2B\x2B\x2B\xC7\x45\x10\x2B\x2B\x2B\x2B\x8D\x0C\xF5\x00\x00\x00\x00\x0F\xB7\xD1\x89\x55\x14\xDB\x45\x14\xDC\x0D\x2B\x2B\x2B\x2B\xD9\x5D\x14\xD9\x45\x14\xDD\x45\xDC\xD9\xC5\xDA\xE9\xDF\xE0"


//函数的声明
DLL_EXPORT_IMPORT BOOL InstallHook();
DLL_EXPORT_IMPORT BOOL UninstallHook();
BOOL HookInit();

//全局变量的声明






#ifdef __cplusplus
};
#endif

#endif