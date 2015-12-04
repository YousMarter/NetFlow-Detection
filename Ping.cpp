
#include "Ping.h"

CPing::CPing()
{
	bValid = FALSE;
	WSADATA wsaData;			// WSADATA
	int nRet;					// General use return code

	// Dynamically load the ICMP.DLL
	hndlIcmp = LoadLibrary("ICMP.DLL");
	if (hndlIcmp == NULL)
	{
		cprintf("Error: Could not load ICMP.DLL\n");
		return;
	}
	// Retrieve ICMP function pointers
	pIcmpCreateFile  = (HANDLE (WINAPI *)(void))GetProcAddress((HMODULE)hndlIcmp, "IcmpCreateFile");
	pIcmpCloseHandle = (BOOL (WINAPI *)(HANDLE))GetProcAddress((HMODULE)hndlIcmp, "IcmpCloseHandle");
	pIcmpSendEcho = (DWORD (WINAPI *)(HANDLE, DWORD, LPVOID, WORD, PIPINFO, LPVOID, DWORD, DWORD))GetProcAddress((HMODULE)hndlIcmp, "IcmpSendEcho");
	// Check all the function pointers
	if (pIcmpCreateFile == NULL	|| pIcmpCloseHandle == NULL	|| pIcmpSendEcho == NULL)
	{
		cprintf("Error: Error loading ICMP.DLL\n");
		FreeLibrary((HMODULE)hndlIcmp);
		return;
	}

	// Init WinSock
	nRet = WSAStartup(0x0101, &wsaData );
    if (nRet)
    {
		cprintf("Error: WSAStartup() error\n");
        WSACleanup();
		FreeLibrary((HMODULE)hndlIcmp);
        return;
    }
    // Check WinSock version
    if (0x0101 != wsaData.wVersion)
    {
		cprintf("Error: No WinSock version 1.1 support found\n");
        WSACleanup();
		FreeLibrary((HMODULE)hndlIcmp);
        return;
    }
	bValid = TRUE;
}

CPing::~CPing()
{
    WSACleanup();
	FreeLibrary((HMODULE)hndlIcmp);
}

int CPing::Ping(char* strHost)
{
	u_char FAR data[4] = { 0L };	//
	//unsigned long Status = 0L;	//
	int PingTimes = 0;				//
	int Received  = 0;				//
	unsigned long Minimum = 1000000;// 最小值设置为超时值
	unsigned long Maximum = 0;		// 最大值设置为0
	unsigned long Time = 0;			// microsecond
	unsigned long Sum = 0;			//
	char hostIpBuf[64] = { 0L };	//
	struct in_addr iaDest;			// Internet address structure
    LPHOSTENT pHost = NULL;			// Pointer to host entry structure
	DWORD *dwAddress = NULL;		// IP Address
	IPINFO ipInfo;					// IP Options structure
	ICMPECHO icmpEcho;				// ICMP Echo reply buffer
	HANDLE hndlFile = NULL;			// Handle for IcmpCreateFile()	
	
	LARGE_INTEGER litmp;
	QueryPerformanceFrequency(&litmp);
    LONGLONG dfFreq = litmp.QuadPart; // 获得计数器的时钟频率 
    
    if(!bValid)
	{
		return -2;
	}
	
	memset(data, '\xAA', 4); //data
	memset(hostIpBuf, 0, 64);

	// Lookup destination Use inet_addr() to determine if we're dealing with a name or an address
    iaDest.s_addr = inet_addr(strHost);
    if (iaDest.s_addr == INADDR_NONE)
	{
        pHost = gethostbyname(strHost);
	}
    else
	{
        pHost = gethostbyaddr((const char *)&iaDest, sizeof(struct in_addr), AF_INET);
	}
	if (pHost == NULL)
	{
		return -1; // 非法的或不存在的主机
	}

	// Copy the IP address
	dwAddress = (DWORD *)(*pHost->h_addr_list);
	cprintf("Pinging %s with %d bytes of data:\n", strHost, sizeof(icmpEcho)/* + sizeof(data)*/);
	
	// Get an ICMP echo request handle, 打开ping服务      
	hndlFile = pIcmpCreateFile();
		
    LONGLONG QPartB, QPartE;
	/*unsigned long tickB, tickE;*/
	while(PingTimes < PING_TIMES)
	{
		Sleep();

		PingTimes++;

		// Set some reasonable default values
		ipInfo.Ttl = 255;
		ipInfo.Tos = 0;
		ipInfo.IPFlags = 0;
		ipInfo.OptSize = 0;
		ipInfo.Options = NULL;	
		icmpEcho.Status = 0;
		
		//SYSTEMTIME timeBg;
		//GetSystemTime(&timeBg);
		/*tickB = GetTickCount();*/
		QueryPerformanceCounter(&litmp);
		QPartB = litmp.QuadPart; // 获得初始值

		// Reqest an ICMP echo
		pIcmpSendEcho(
			hndlFile,		// Handle from IcmpCreateFile()
			*dwAddress,		// Destination IP address
			NULL/*data*/,			// Pointer to buffer to send
			0/*sizeof(data)*/,	// Size of buffer in bytes
			&ipInfo,		// Request options
			&icmpEcho,		// Reply buffer
			sizeof(icmpEcho)/* + sizeof(data)*/,
			1000);			// Time to wait in milliseconds

		//SYSTEMTIME timeEd;
		//GetSystemTime(&timeEd);
		/*tickE = GetTickCount();*/
		QueryPerformanceCounter(&litmp);
		QPartE = litmp.QuadPart; // 获得终止值

		// Print the results
		iaDest.s_addr = icmpEcho.Source;
		//Status += icmpEcho.Status;
		if (icmpEcho.Status)
		{
			cprintf("Request time out!\n");
		}
		else
		{			
			/*if(tickE -tickB == 0)
			{
				cprintf("Reply from %s: bytes=%d time=%dμs TTL=%d\n", 
					strHost, sizeof(icmpEcho) + sizeof(icmpEcho.pData),  (QPartE - QPartB)*1000000/dfFreq, icmpEcho.ipInfo.Ttl);
			}
			else //ping本地局域网网关时得到的
			{
				cprintf("Reply from %s: bytes=%d time=%dms TTL=%d\n", 
					strHost, sizeof(icmpEcho) + sizeof(icmpEcho.pData), tickE -tickB, icmpEcho.ipInfo.Ttl);
			}
			Sum += tickE -tickB;
			if(tickE -tickB > Maximum)
			{
				Maximum = tickE -tickB;
			}
			if(tickE -tickB < Minimum)
			{
				Minimum = tickE -tickB;
			}*/			
			Time = (unsigned long)((QPartE - QPartB)*1000000/dfFreq);
			cprintf("Reply from %s: bytes=%d time=%dms%dμs TTL=%d\n", 
					strHost, sizeof(icmpEcho), Time/1000, Time%1000, icmpEcho.ipInfo.Ttl);
			Received++;
			Sum += Time;
			if(Time > Maximum)
			{
				Maximum = Time;
			}
			if(Time < Minimum)
			{
				Minimum = Time;
			}
		}

		Sleep(500);
	}

	cprintf("\nPing statistics for %s:", strHost);
	cprintf("\n    Packets: Sent = %d, Received = %d, Lost = %d (%d%% loss),", 
		PING_TIMES, Received, PING_TIMES - Received, (PING_TIMES - Received) * 100 / PING_TIMES);
	if(Received > 0)
	{
		cprintf("\nApproximate round trip times in milli-seconds:");
		cprintf("\n    Minimum = %dms%dμs, Maximum = %dms%dμs, Average = %dms%dμs\n",
			Minimum/1000, Minimum%1000, Maximum/1000, Maximum%1000, (Sum/Received)/1000, (Sum/Received)%1000);
	}
	else { cprintf("\n"); }

	cprintf("\n");

	// Close the echo request file handle
	pIcmpCloseHandle(hndlFile);

	return Received;
}
