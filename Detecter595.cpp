#include "stdafx.h"
#include "pcap.h"
#include "winsock2.h"
#pragma comment(lib,"ws2_32.lib")

/* 4字节的IP地址 */
typedef struct ip_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* IPv4 首部 */
typedef struct ip_header{
	u_char  ver_ihl;        // 版本 (4 bits) + 首部长度 (4 bits)
	u_char  tos;            // 服务类型(Type of service) 
	u_short tlen;           // 总长(Total length) 
	u_short identification; // 标识(Identification)
	u_short flags_fo;       // 标志位(Flags) (3 bits) + 段偏移量(Fragment offset) (13 bits)
	u_char  ttl;            // 存活时间(Time to live)
	u_char  proto;          // 协议(Protocol)
	u_short crc;            // 首部校验和(Header checksum)
	ip_address  saddr;      // 源地址(Source address)
	ip_address  daddr;      // 目的地址(Destination address)
	u_int   op_pad;         // 选项与填充(Option + Padding)
}ip_header;

/* UDP 首部*/
typedef struct udp_header{
	u_short sport;          // 源端口(Source port)
	u_short dport;          // 目的端口(Destination port)
	u_short len;            // UDP数据包长度(Datagram length)
	u_short crc;            // 校验和(Checksum)
}udp_header;

typedef struct wy_add{
	u_char b1=0;
	u_char b2=0;
	u_char b3=0;
	u_char b4=0;
}wy_add;

FILE *file;
struct tm *ltime;
struct tm *ltime1;
struct tm *ltime2;
char timestr[16]; char t1[16]; char t2[16];
ip_header *ih;
udp_header *uh;
u_int ip_len;
u_short sport, dport;
time_t local_tv_sec;
ip_header ih_start;
ip_header ih_end;
wy_add aim_add;
char buffer123[20];
u_short ipid;
float  dt;
float m[100000];

void caltime(char t1[], char t2[])
{
	int hh1, mm1, ss1;
	int hh2, mm2, ss2;
	hh1 = atoi(t1);
	mm1 = atoi(t1 + 3);
	ss1 = atoi(t1 + 6);

	hh2 = atoi(t2);
	mm2 = atoi(t2 + 3);
	ss2 = atoi(t2 + 6);
   dt = (ss2 - ss1) + (mm2 - mm1) * 60 + (hh2 - hh1) * 3600;
}
int main()
{ 
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	int res;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct tm *ltime;
	char timestr[16];
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	time_t local_tv_sec;
	u_int netmask;
	struct bpf_program fcode;
	u_char p1;
	u_char p2;
	u_char p3;
	u_char p4;
	ih_start.identification = 0;
	ih_end.identification = 0;
	int flag = 1;
	long dd = 0;

	//get the aim_Ip as wy_add structure.//
	printf("entry aim IP address as X.X.X.X \n");
	scanf("%d", &p1);
	scanf("%d", &p2);
	scanf("%d", &p3);
	scanf("%d", &p4);
	aim_add.b1 = p1;
	aim_add.b2 = p2;
	aim_add.b3 = p3;
	aim_add.b4 = p4;
	printf("%d.%d.%d.%d\n",aim_add.b1, aim_add.b2,aim_add.b3,aim_add.b4);

	/* 获取本机设备列表 */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* 打印列表 */
	printf("net interface founded:");
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* 跳转到已选中的适配器 */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

	/* 打开设备 */
	if ((adhandle = pcap_open(d->name,          // 设备名
		65536,            // 要捕捉的数据包的部分 
		// 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
		PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
		1000,             // 读取超时时间
		NULL,             // 远程机器验证
		errbuf            // 错误缓冲池
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* 释放设列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	if (d->addresses != NULL)
		/* 获取接口第一个地址的掩码 */
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* 如果这个接口没有地址，那么我们假设这个接口在C类网络中 */
		netmask = 0xffffff;


	//compile the filter//
	if (pcap_compile(adhandle, &fcode, "icmp", 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//set the filter//
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* 获取数据包 */
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0){

		if (res == 0)
			/* 超时时间到 */
			continue;

		/* 将时间戳转换成可识别的格式 */
		local_tv_sec = header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

		/* 获得IP数据包头部的位置 */
		ih = (ip_header *)(pkt_data +
			14); //以太网头部长度       
		
		if (ih->saddr.byte1 == aim_add.b1&&ih->saddr.byte2 == aim_add.b2&&ih->saddr.byte3 == aim_add.b3&&ih->saddr.byte4 == aim_add.b4){
			printf(">>>>>>");
			printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);

			printf("%d.%d.%d.%d -> %d.%d.%d.%d\n",
				ih->saddr.byte1,
				ih->saddr.byte2,
				ih->saddr.byte3,
				ih->saddr.byte4,

				ih->daddr.byte1,
				ih->daddr.byte2,
				ih->daddr.byte3,
				ih->daddr.byte4);
			if (ih_start.identification == 0){  //如果d1是空的
			strftime(t1, sizeof t1, "%H:%M:%S", ltime);//d1的时间存在t1里，标准时间格式
			ipid = ntohs(ih->identification);//把ipid网络序列转为主机序列
			ih_start.identification = ipid;//把ipid传给d1.
			printf("初始包ID: %d\n",ih_start.identification );
			}
			if ((ih_start.identification != 0)&&(ih_start.identification != ih->identification)){//若d1不空且d1和ih.id不同  
				if (ih_start.identification > ih->identification){ dd=2; }
				strftime(t2, sizeof t2, "%H:%M:%S", ltime);//将当前包时间戳存在t2
				ipid = ntohs(ih->identification);
				ih_end.identification = ipid;
				caltime(t1, t2);
				printf("后续包ID：%d\n", ih_end.identification);
				if (dt != 0){
					printf("packages/n:%f\n", (ih_end.identification - ih_start.identification) / dt);     
					float de = (ih_end.identification - ih_start.identification) / dt;
					ih_start.identification = ih_end.identification;
					strftime(t1, sizeof t1, "%H:%M:%S", ltime);
					m[flag] = de;
					file = fopen("data.txt", "w");
					fprintf(file,"%f\n", m[flag]);
					flag++;
				}
			}
		}
	
	}

	if (res == -1){
		printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
		return -1;
	}

	return 0;
}