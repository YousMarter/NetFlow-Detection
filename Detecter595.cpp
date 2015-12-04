#include "stdafx.h"
#include "pcap.h"
#include "winsock2.h"
#pragma comment(lib,"ws2_32.lib")

/* 4�ֽڵ�IP��ַ */
typedef struct ip_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* IPv4 �ײ� */
typedef struct ip_header{
	u_char  ver_ihl;        // �汾 (4 bits) + �ײ����� (4 bits)
	u_char  tos;            // ��������(Type of service) 
	u_short tlen;           // �ܳ�(Total length) 
	u_short identification; // ��ʶ(Identification)
	u_short flags_fo;       // ��־λ(Flags) (3 bits) + ��ƫ����(Fragment offset) (13 bits)
	u_char  ttl;            // ���ʱ��(Time to live)
	u_char  proto;          // Э��(Protocol)
	u_short crc;            // �ײ�У���(Header checksum)
	ip_address  saddr;      // Դ��ַ(Source address)
	ip_address  daddr;      // Ŀ�ĵ�ַ(Destination address)
	u_int   op_pad;         // ѡ�������(Option + Padding)
}ip_header;

/* UDP �ײ�*/
typedef struct udp_header{
	u_short sport;          // Դ�˿�(Source port)
	u_short dport;          // Ŀ�Ķ˿�(Destination port)
	u_short len;            // UDP���ݰ�����(Datagram length)
	u_short crc;            // У���(Checksum)
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

	/* ��ȡ�����豸�б� */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* ��ӡ�б� */
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
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* ��ת����ѡ�е������� */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

	/* ���豸 */
	if ((adhandle = pcap_open(d->name,          // �豸��
		65536,            // Ҫ��׽�����ݰ��Ĳ��� 
		// 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
		PCAP_OPENFLAG_PROMISCUOUS,    // ����ģʽ
		1000,             // ��ȡ��ʱʱ��
		NULL,             // Զ�̻�����֤
		errbuf            // ���󻺳��
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* �ͷ����б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	if (d->addresses != NULL)
		/* ��ȡ�ӿڵ�һ����ַ������ */
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* �������ӿ�û�е�ַ����ô���Ǽ�������ӿ���C�������� */
		netmask = 0xffffff;


	//compile the filter//
	if (pcap_compile(adhandle, &fcode, "icmp", 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//set the filter//
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* ��ȡ���ݰ� */
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0){

		if (res == 0)
			/* ��ʱʱ�䵽 */
			continue;

		/* ��ʱ���ת���ɿ�ʶ��ĸ�ʽ */
		local_tv_sec = header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

		/* ���IP���ݰ�ͷ����λ�� */
		ih = (ip_header *)(pkt_data +
			14); //��̫��ͷ������       
		
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
			if (ih_start.identification == 0){  //���d1�ǿյ�
			strftime(t1, sizeof t1, "%H:%M:%S", ltime);//d1��ʱ�����t1���׼ʱ���ʽ
			ipid = ntohs(ih->identification);//��ipid��������תΪ��������
			ih_start.identification = ipid;//��ipid����d1.
			printf("��ʼ��ID: %d\n",ih_start.identification );
			}
			if ((ih_start.identification != 0)&&(ih_start.identification != ih->identification)){//��d1������d1��ih.id��ͬ  
				if (ih_start.identification > ih->identification){ dd=2; }
				strftime(t2, sizeof t2, "%H:%M:%S", ltime);//����ǰ��ʱ�������t2
				ipid = ntohs(ih->identification);
				ih_end.identification = ipid;
				caltime(t1, t2);
				printf("������ID��%d\n", ih_end.identification);
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