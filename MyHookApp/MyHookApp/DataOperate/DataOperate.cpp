#include "DataOperate.h"

void MyHex2Str(UCHAR* Des, UCHAR *Src, int len)
{
	int j = 0;
	bool isret = false;
	for (int i = 0; i < len; i++)
	{
		if (0 == i % 0x10 && i != 0)
		{
			sprintf_s((char *)(Des + j),strlen("\n"),"\n");
			isret = true;
		}
		if (isret)
		{
			++j;
			sprintf_s((char *)(Des + j),3, "%02x ", *(Src + i));
			isret = false;
		}
		else
		{
			sprintf_s((char *)(Des + j),3,"%02x ", *(Src + i));
		}

		j += 3;
	}
}

void Fix_Dispatch1(DWORD Src)
{
	char buff[256];
	ZeroMemory(buff,sizeof(buff));

	FILE *pSrcFile =NULL;
	fopen_s(&pSrcFile,"C:\\SrcMidValue.txt","a+");
	if (!pSrcFile)
	{
		return;
	}
	MyHex2Str((UCHAR *)buff, (UCHAR *)Src, 0x30);
	fprintf_s(pSrcFile,buff);
	//fwrite(buff, 1, strlen(buff), pSrcFile);
	//fwrite("\n", 1, strlen("\n"), pSrcFile);
	//fwrite("\n", 1, strlen("\n"), pSrcFile);
	fclose(pSrcFile);

}




void Fix_Dispatch2(DWORD Src,DWORD dwOffset)
{
	static int iCount;
	char buff[256];
	ZeroMemory(buff,sizeof(buff));

	FILE *pSrcFile = fopen("C:\\SrcMidData2.txt", "a+");
	if (!pSrcFile)
	{
		return;
	}
	sprintf(buff, "%11.6f,", *(float *)(Src + dwOffset));
	fwrite((const void *)(buff),strlen(buff),1,pSrcFile);
	++iCount;
	if (iCount % 0x24 == 0)
	{
		fwrite("\n", 1, strlen("\n"), pSrcFile);
	}
	fclose(pSrcFile);

}

void Fix_Dispatch3(float Src1, float Src2, float Src3, float Src4, float Src5, float Src6, float Src7, float Src8)
{
	static int iCount;
	char buff[256];
	ZeroMemory(buff, sizeof(buff));
	float *buff1 = new float[8250];
	ZeroMemory(buff1, 8250);
	FILE *pSrcFile = fopen("C:\\SrcMidData3.txt", "a+");
	if (!pSrcFile)
	{
		return;
	}
	sprintf(buff, "%11.6f,%11.6f,%11.6f,%11.6f,%11.6f,%11.6f,%11.6f,%11.6f,", Src1, Src2, Src3, Src4, Src5, Src6, Src7, Src8);
	fwrite((const void *)(buff), strlen(buff), 1, pSrcFile);
	++iCount;
	if (iCount%0x24==0)
	{
		fwrite("\n", 1, strlen("\n"), pSrcFile);
	}

	fclose(pSrcFile);

}