#ifndef _DATAOPERATE_H
#define _DATAOPERATE_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <time.h>
#include <string.h>

void MyHex2Str(UCHAR* Des, UCHAR *Src, int len);
void Fix_Dispatch1(DWORD Src);
void Fix_Dispatch2(DWORD Src,DWORD dwOffset);
void Fix_Dispatch3(float Src1, float Src2, float Src3, float Src4, float Src5, float Src6, float Src7, float Src8);


#ifdef __cplusplus
};
#endif

#endif