
#include "MyPing.h"

#pragma comment(lib,"wsock32")

void main()
{
	char hostBuf[64] = { 0L }; // 要测试的主机名、域名
	CPing *ping = NULL;
	char quit[2] = { 0L };

	cprintf("Detecter_test \n");
	ping = new CPing();
	if(NULL == ping)
	{
		cprintf("===   err!   ===\n");
		exit(-1);
	}

_TEST:
	cprintf("\nPlease input the Aim_IP: ");
	memset(hostBuf, 0, 64);
	scanf("%s", hostBuf);
	//gets(hostBuf);
	//scanf("%c", &quit[0]);
_CYC:
	cprintf("\n");

	int bResult = ping->Ping(hostBuf);
	switch(bResult)
	{
	case -2:
		cprintf("Program not valid initialized.\n");
		break;
	case -1:
		cprintf("Host name is invalid or the host is not responding.\n");
		break;
	default:
		break;
	}

	cprintf("\nPress F|f to finish\n G|g to keep cycle , else to contnue: ");
	scanf("%s", quit);
	switch(quit[0]) // not equal to "char quit=0;"
	{
	case 'f':
	case 'F':
		break;
	case'G':
	case'g':
		goto _CYC;

	default:
		goto _TEST; // 在复杂的逻辑中不推荐使用
	}

	HangUntilKeyboartHit();
}

void HangUntilKeyboartHit()
{
    printf("\nPress any key to continue.\n");
    while (!kbhit()) { /* do nothing */ };
}