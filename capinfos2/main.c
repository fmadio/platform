//-------------------------------------------------------------------------------------------------------------------
//
// Copyright (c) 2021-2022, fmad engineering group 
//
// LICENSE: refer to https://github.com/fmadio/platform/blob/main/LICENSE.md
//
// Packet verification tool 
//
//-------------------------------------------------------------------------------------------------------------------

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <fcntl.h>
#include <math.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/ioctl.h>
#include <sys/errno.h>
#include <linux/sched.h>

typedef unsigned char		u8;
typedef char				s8;

typedef unsigned short		u16;
typedef short				s16;

typedef unsigned int 		u32;
typedef int					s32;

typedef unsigned long long	u64;
typedef long long			s64;

typedef unsigned int 		bool;

#define true		1
#define false		0

// ethernet header
typedef struct fEther_t
{
	u8		Dst[6];
	u8		Src[6];
	u16		Proto;

} fEther_t;

typedef struct
{
	union
	{
		u32		IP4;	
		u8		IP[4];
	};

} IPv4_t;

#define ETHER_PROTO_IPV4		0x0800 
#define ETHER_PROTO_IPV6		0x86dd 
#define ETHER_PROTO_IP  		0x0888		// special made up type indicating ipv4 or ipv6 
#define ETHER_PROTO_VLAN		0x8100	
#define ETHER_PROTO_VNTAG		0x8926		// vntag / etag
#define ETHER_PROTO_MPLS		0x8847
#define ETHER_PROTO_ARP			0x0806
#define ETHER_PROTO_802_1ad		0x88a8
#define ETHER_PROTO_STP			0x0027

typedef struct
{
	u32		HLen  	 : 4;
	u32		Version	 : 4;
	u32		Service	 : 8;
	u32		Len		 : 16;
	u16		Ident;
	u16		Frag;
	u8		TTL;
	u8		Proto;
	u16		CSum;

	IPv4_t	Src;
	IPv4_t	Dst;

} __attribute__((packed)) IPv4Header_t;


#define PCAPHEADER_MAGIC_NANO		0xa1b23c4d
#define PCAPHEADER_MAGIC_USEC		0xa1b2c3d4

typedef struct
{

	u32				Magic;
	u16				Major;
	u16				Minor;
	u32				TimeZone;
	u32				SigFlag;
	u32				SnapLen;
	u32				Link;

} __attribute__((packed)) PCAPHeader_t;


typedef struct PCAPPacket_t
{
	u32				Sec;					// time stamp sec since epoch 
	u32				NSec;					// nsec fraction since epoch

	u32				LengthCapture;			// captured length, inc trailing / aligned data
	u32				Length; 				// [14:0]  length on the wire
											// [15]    port number 
											// [31:16] reserved 

} __attribute__((packed)) PCAPPacket_t;


static inline volatile u64 rdtsc(void)
{
	u32 hi, lo;
	__asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi) );
	return (((u64)hi)<<32ULL) | (u64)lo;
}

static inline double inverse(const double a)
{
	if (a == 0) return 0;
	return 1.0 / a;
}


//-------------------------------------------------------------------------------------------------

typedef struct
{
	u64* 						SubnetSrc[256];
	u64* 						SubnetDst[256];

} IPHistoEntry_t;

typedef struct IPHistoSort_t
{
	u8							IP[4];
	u64							SrcCnt;
	u64							DstCnt;
	struct IPHistoSort_t*		Next;

} IPHistoSort_t;

//-------------------------------------------------------------------------------------------------

static u64 		s_PayloadCRC64 	= 0;

static bool 	s_SeqValidate		= false;			// enable sequence no validation
static bool 	s_SeqValidateHisto	= false;			// dump seq # histogram 
static u32 		s_SeqNo[32]			= {0, 0, 0, 0, 0, 0, 0, 0, 0};
static u64 		s_SeqNoError		= 0;

static u64 		s_TotalCaptureByte	= 0;
static u64 		s_TotalWireByte		= 0;				// total bytes on the wire
static u64 		s_TotalPacket		= 0;
static u32		s_LastByte			= 0;
static s32		s_LengthFCS			= 0; 				// optional include /remove FCS from seq check / packet size check

static u64		s_PacketSeqCnt		= 0;				// number of packets before reset

static u32		s_SeqStart[32]		= {0, 0, 0, 0, 0, 0, 0, 0};		// first seq number found
static bool		s_SeqStartVld[32]	= {false, false, false, false, false, false, false, false};	// first seq number not set yet
static u32		s_SeqEnd[32]		= {0, 0, 0, 0, 0, 0, 0, 0};		// last seq number found

static u64		s_PortPacketCnt[32]  = {0,0,0,0, 0, 0, 0, 0, 0};		// nmber of packets per port

static bool		g_TimeOrderCheck	= false;			// enable check for negative time 
static u64		s_TimeOrderFail		= 0;				// time order is strict (no negative times)

static bool		s_CheckFCS			= false;			// check FCS output
static u64		s_ErrorFCS			= 0;				// number of FCS errors

static bool		s_SeqPrefixHistoEnable = false;			// enable/dislabe printing sequence histogram
static u64		s_SeqPrefixHisto[256];					// histogram of sequence preqfix

static bool		s_EnableMACPortID		= true;			// enable port id from MAC address

static u64		s_TScale				= 1;			// subseccond scaling factor nsec vs usec
static bool		s_IsPktPCAP				= true;			// by default pkt input is in pcap format 
static bool		s_IsPktFMAD				= false;		// input is in fmad chunked packet format

static bool		s_TSPrint				= false;		// print each packets timestamp
static u64		s_TSFirst				= -1;			// first TS seen
static u64		s_TSLast				= 0;			// last TS seen 

static bool		s_SingleDump			= false;		// dump contents of the packet as a single line  


double TSC2Nano = 0;

//-------------------------------------------------------------------------------------------------

static u64		s_LastTS		= 0;
static u64		s_PktCnt[32]	= {0, 0, 0, 0, 0, 0, 0, 0, 0};			// port 4 is for anything not classified by MAC address 

void ProcessPacket(u8* Payload8, u32 Length, u64 TS)
{
	u32* Payload = (u32*)Payload8;
	for (int i=0; i < Length / 4; i++)
	{
		s_PayloadCRC64 += Payload[i];
	}
	u32 Port = 4;

	// skip mac + dont include FCS
	if (s_SeqValidate)
	{
		u32* MAC = (u32*)Payload; 
		fEther_t* Ether = (fEther_t*)MAC;

		u32 StartPos = 0;
		if (s_EnableMACPortID)
		{
			switch (MAC[0])
			{
			case 0x11111100: Port = 0; break;
			case 0x22222200: Port = 1; break;
			case 0x33333300: Port = 2; break;
			case 0x44444400: Port = 3; break;
			case 0x55555500: Port = 4; break;
			case 0x66666600: Port = 5; break;
			case 0x77777700: Port = 6; break;
			case 0x88888800: Port = 7; break;
			default:
				{
					// 20G system does not increment header, while 100G does
					u32 PortInc = 0;

					// 20Gv2 Port 0					
					if ( (Ether->Dst[0] == 0x00) && (Ether->Dst[1] == 0xaf) && (Ether->Dst[2] == 0x20) && (Ether->Dst[3] == 0x02) &&   (Ether->Dst[4] == 0x01) && (Ether->Dst[5] == 0x00)) { Port = 0;  PortInc = 0; }

					// 20Gv2 Port 1					
					if ( (Ether->Dst[0] == 0x00) && (Ether->Dst[1] == 0xaf) && (Ether->Dst[2] == 0x20) && (Ether->Dst[3] == 0x02) &&   (Ether->Dst[4] == 0x02) && (Ether->Dst[5] == 0x00)) { Port = 1;  PortInc = 0; }

					// 20Gp2 Port 0					
					if ( (Ether->Dst[0] == 0x00) && (Ether->Dst[1] == 0xaf) && (Ether->Dst[2] == 0x2a) && (Ether->Dst[3] == 0x02) &&   (Ether->Dst[4] == 0x01) && (Ether->Dst[5] == 0x00)) { Port = 0;  PortInc = 0; }

					// 20Gp2 Port 1					
					if ( (Ether->Dst[0] == 0x00) && (Ether->Dst[1] == 0xaf) && (Ether->Dst[2] == 0x2a) && (Ether->Dst[3] == 0x02) &&   (Ether->Dst[4] == 0x02) && (Ether->Dst[5] == 0x00)) { Port = 1;  PortInc = 0; }


					// 20Gv3 Port 0					
					if ( (Ether->Dst[0] == 0x00) && (Ether->Dst[1] == 0xaf) && (Ether->Dst[2] == 0x20) && (Ether->Dst[3] == 0x03) &&   (Ether->Dst[4] == 0x01) && (Ether->Dst[5] == 0x00)) { Port = 0;  PortInc = 0; }

					// 20Gv3 Port 1					
					if ( (Ether->Dst[0] == 0x00) && (Ether->Dst[1] == 0xaf) && (Ether->Dst[2] == 0x20) && (Ether->Dst[3] == 0x03) &&   (Ether->Dst[4] == 0x02) && (Ether->Dst[5] == 0x00)) { Port = 1;  PortInc = 0; }

					// 20Gp3 Port 0					
					if ( (Ether->Dst[0] == 0x00) && (Ether->Dst[1] == 0xaf) && (Ether->Dst[2] == 0x2a) && (Ether->Dst[3] == 0x03) &&   (Ether->Dst[4] == 0x01) && (Ether->Dst[5] == 0x00)) { Port = 0;  PortInc = 0; }

					// 20Gp3 Port 1					
					if ( (Ether->Dst[0] == 0x00) && (Ether->Dst[1] == 0xaf) && (Ether->Dst[2] == 0x2a) && (Ether->Dst[3] == 0x03) &&   (Ether->Dst[4] == 0x02) && (Ether->Dst[5] == 0x00)) { Port = 1;  PortInc = 0; }


					// 100Gv2 Port 0
					if ( (Ether->Dst[0] == 0x00) && (Ether->Dst[1] == 0xaf) && (Ether->Dst[2] == 0xa0) && (Ether->Dst[3] == 0x02) &&   (Ether->Dst[4] == 0x01) && (Ether->Dst[5] == 0x00)) { Port = 0;  PortInc = 4; }

					// 100Gv2 Port 1
					if ( (Ether->Dst[0] == 0x00) && (Ether->Dst[1] == 0xaf) && (Ether->Dst[2] == 0xa0) && (Ether->Dst[3] == 0x02) &&   (Ether->Dst[4] == 0x02) && (Ether->Dst[5] == 0x00)) { Port = 2;  PortInc = 4; }
			
				//printf("mac %02x:%02x:%02x:%02x:%02x:%02x\n", Ether->Dst[0],  Ether->Dst[1],  Ether->Dst[2],  Ether->Dst[3],  Ether->Dst[4], Ether->Dst[5]);

					s_SeqNo[Port] += PortInc;
				}	
			}

			// first 16B contains port info 
			StartPos  = 4;
		}	
		else
		{
			// seq number where MAC address would be
			//s_SeqNo[Port] += 4;

			// dont skip the mac address
			StartPos = 0;
		}

		s_PortPacketCnt[Port]++;

		for (int i=StartPos; i < (Length + s_LengthFCS) / 4; i++)
		{
			//printf("[%08x] %08x expect %08x Port:%i\n", i, Payload[i], s_SeqNo[Port], Port);
			if ((s_SeqNo[Port] == 0) || (Payload[i] == ((1+Port) << 28)))
			{
				s_SeqNo[Port] = Payload[i];

				printf("Port:%i new seq: %08x Packets: %lli Length:%4i\n", Port, Payload[i], s_PktCnt[Port], Length);
				if ((s_PktCnt[Port] != 0) && (s_PacketSeqCnt != 0))
				{
					if (s_PktCnt[Port] != s_PacketSeqCnt)
					{
						printf("Port:%i expected %lli Packs in sequence, found %lli : Result FAIL\n", Port, s_PacketSeqCnt, s_PktCnt[Port]);	
					 	exit(0);	
					}
				}
				s_PktCnt[Port] = 0;
			}

			if (Payload[i] != s_SeqNo[Port])
			{
				s_SeqNoError++;
				//if (s_SeqNoError < 10000)
				{
					printf("[%016llx] SeqNo fail: Port: %i Expect:%08x Found:%08x (%08x) : Offset:%06x Length:%i : %lli Pkts\n", 
								s_TotalCaptureByte, Port, s_SeqNo[Port], Payload[i], s_SeqNo[Port] ^ Payload[i], i*4, Length, s_PktCnt[0] + s_PktCnt[1] + s_PktCnt[2] + s_PktCnt[3] + s_PktCnt[4]);
				}
				s_SeqNo[Port] = Payload[i];
				s_PktCnt[Port] = 0;
			}

			if (!s_SeqStartVld[Port])
			{
				s_SeqStartVld[Port] 	= true;
				s_SeqStart[Port]		= Payload[i];
			}

			// prefix histogram
			u32 Prefix = Payload[i] >> 24;
			s_SeqPrefixHisto[Prefix]++;

			// start/end
			s_SeqEnd[Port] = Payload[i];

			s_SeqNo[Port]++;
			s_LastByte = Payload[i];
		}
	}

	/*
	// check time ordering
	u64 TS = ((u64)Pkt->Sec) * 1000000000ULL  + ((u64)Pkt->NSec) * s_TScale;
	if (g_TimeOrderCheck)
	{
		// ignore first packet
		if (s_LastTS != 0)
		{
			// check for negative timestamps 
			if ( ((TS - s_LastTS) < 0) || ((Pkt->NSec * s_TScale) > 1e9))
			{
				printf("negative time: %lli : Port:%i PktNo:%lli : PktTS:%lli (%s) LastTS:%lli (%s)\n", TS - s_LastTS, Port, s_PktCnt[Port], TS, FormatTS(TS), s_LastTS, FormatTS(s_LastTS));
				s_TimeOrderFail++;
			}
			//printf("%lli: %lli\n", s_PktCnt, TS);
		}	

		// time delta histo

		u64 dTS = TS - s_LastTS;
		if (dTS < 10000)
		{
			s_DeltaHisto[dTS]++;
		}
		s_LastTS = TS;
	}
	*/

	// update first/last time
	s_TSFirst 	= (s_TSFirst < TS) ? s_TSFirst : TS;
	s_TSLast 	= (s_TSLast  > TS) ? s_TSLast  : TS;

	s_PktCnt[Port]++;
}

//-------------------------------------------------------------------------------------------------

static void Help(void)
{
	printf("capinfos2 <pcap file>\n");
	printf("\n");
	printf("-v                   : verbose output\n");
	printf("--seq                : check 32b sequental sequence numbers\n");
	printf("--with-fcs           : dont include FCS 32b word as a sequence number\n");
	printf("--disable-portid     : no port identification from MAC address\n");
	printf("--enable-timecheck   : enable time order checking\n");
	printf("\n");
}

//-------------------------------------------------------------------------------------------------

int main(int argc, char* argv[])
{
	bool Verbose 			= false;
	bool SeqValidate 		= false; 		//  ensure  all packets are 32b sequential numbers
	u32 PacketSize 			= 0;			// ensure all packets are of a fixed size
	s32 CPUID				= -1;

	for (int i=0; i < argc; i++)
	{
		if (strcmp(argv[i], "-v") == 0) Verbose = true;
		if (strcmp(argv[i], "--seq") == 0) s_SeqValidate = true;
		if (strcmp(argv[i], "--seq-histogram") == 0) s_SeqValidateHisto = true;
		if (strcmp(argv[i], "--packet-size") == 0)
		{
			PacketSize = atoi(argv[i+1]);
			fprintf(stderr, "PacketSize: %i\n", PacketSize);
		}
		if (strcmp(argv[i], "--check-fcs") == 0) s_CheckFCS = true;
		if (strcmp(argv[i], "--with-fcs") == 0) s_LengthFCS = -4; 
		if (strcmp(argv[i], "--packet-seq-cnt") == 0)
		{
			s_PacketSeqCnt = atoi(argv[i+1]);
			i++;
		}
		if (strcmp(argv[i], "--seq-prefix-histo") == 0)
		{
			s_SeqPrefixHistoEnable  = true;
		}
		if (strcmp(argv[i], "--help") == 0)
		{
			Help();
			return 0;
		}
		if (strcmp(argv[i], "--disable-portid") == 0)
		{
			fprintf(stderr, "No PortID\n");
			s_EnableMACPortID = false;
		}
		if (strcmp(argv[i], "--enable-timecheck") == 0)
		{
			fprintf(stderr, "Time Ordering Checks\n");
			g_TimeOrderCheck = true;
		}
		if (strcmp(argv[i], "--ts-print") == 0)
		{
			s_TSPrint = true;
			fprintf(stderr, "Printing Timestamp info\n");
		}
		if (strcmp(argv[i], "--cpu") == 0) 
		{
			CPUID = atoi(argv[i+1]);
			i++;	
			fprintf(stderr, "capinfos2 CPU Affinity: %i\n", CPUID);
		}
		if (strcmp(argv[i], "--single-dump") == 0) 
		{
			s_SingleDump	= true;
			fprintf(stderr, "dumps data as a single line\n");
		}
	}

	u32 BufferPos 	= 0;
	u32 BufferMax 	= 1024*1024;
	u8* Buffer 		= malloc(1024*1024+128*1024); 

	// chunked fmad buffer
	u8* FMADChunkBuffer = NULL; 

	// read pcap header in first
	PCAPHeader_t	Header;
	assert(fread(&Header, 1, sizeof(Header), stdin) == sizeof(Header));

	switch (Header.Magic)
	{
	case PCAPHEADER_MAGIC_NANO: 
		printf("PCAP nano\n"); 
		s_TScale = 1;
		break;

	case PCAPHEADER_MAGIC_USEC: 
		printf("PCAP usec\n"); 
		s_TScale = 1000; 
		break;

	default:
		printf("invalid magic: %08x\n", Header.Magic);	
		assert(false);
	}

	u64 ErrorPktSize = 0;
	u64 LastByte = 0;
	u64 LastPacket = 0;
	u64 LastTSC = 0;

	u64 NextPrintTSC = rdtsc();
	while (!feof(stdin))
	{

		if (s_IsPktPCAP)
		{
			int rlen = fread(Buffer + BufferPos, 1, BufferMax - BufferPos, stdin);	
			if (rlen < 0)
			{
				printf("data end\n");
				break;
			}

			u32 BufferOffset = 0;
			u32 BufferEnd = BufferPos + rlen; 
			while (true)
			{
				PCAPPacket_t* Pkt = (PCAPPacket_t*)(Buffer + BufferOffset);

				if (BufferOffset + sizeof(PCAPPacket_t) >= BufferEnd) break;
				//printf("[%08x] Pkt: %i\n", BufferOffset, Pkt->Length);

				assert(Pkt->Length > 0);
				assert(Pkt->Length < 16*1024);
				if ((PacketSize != 0) && ( (Pkt->Length + s_LengthFCS) != PacketSize) )
				{
					printf("[%016llx] PktSize Error: %08x Expect %08x\n", s_TotalCaptureByte, Pkt->Length + s_LengthFCS, PacketSize);
					printf("%08x %08x %08x %8x\n", Pkt->Sec, Pkt->NSec, Pkt->Length, Pkt->LengthCapture);
					ErrorPktSize++;
				}

				if (BufferOffset + Pkt->LengthCapture + sizeof(PCAPPacket_t) > BufferEnd)
				{
					break;
				}
		
				/*
				if (Pkt->Length < s_SizeHistoMax)
				{
					s_SizeHistoWire[ Pkt->Length ]++;
				}
				if (Pkt->LengthCapture < s_SizeHistoMax)
				{
					s_SizeHistoCapture[ Pkt->LengthCapture ]++;
				}
				*/

				u64 TS = ((u64)Pkt->Sec) * 1000000000ULL  + ((u64)Pkt->NSec) * s_TScale;

				ProcessPacket( (u8*)(Pkt+1), Pkt->LengthCapture, TS);

				s_TotalPacket++;
				s_TotalCaptureByte 		+= sizeof(PCAPPacket_t) + Pkt->LengthCapture;
				s_TotalWireByte 	+= Pkt->Length;

				BufferOffset 	+= sizeof(PCAPPacket_t) + Pkt->LengthCapture;
			}

			u32 Remain = BufferMax - BufferOffset;	
			memmove(Buffer, Buffer + BufferOffset, Remain);	
			BufferPos = Remain;
		}
	}
	printf("Total Packets: %lli\n", s_TotalPacket);

	s64 dTime = s_TSLast - s_TSFirst;

	// stats
	printf("TotalBytes     : %lli\n", s_TotalWireByte);
	printf("TotalPackets   : %lli\n", s_TotalPacket);
	printf("PayloadCRC     : %llx\n", s_PayloadCRC64);
	printf("ErrorSeq       : %lli\n", s_SeqNoError);
	printf("ErrorPktSize   : %lli\n", ErrorPktSize);
	printf("LastByte       : 0x%08x\n", s_LastByte);
	printf("SeqStart       : 0x%08x 0x%08x 0x%08x 0x%08x : 0x%08x\n", s_SeqStart[0], s_SeqStart[1], s_SeqStart[2], s_SeqStart[3], s_SeqStart[4]);
	printf("SeqEnd         : 0x%08x 0x%08x 0x%08x 0x%08x : 0x%08x\n", s_SeqEnd[0], s_SeqEnd[1], s_SeqEnd[2], s_SeqEnd[3], s_SeqEnd[4]);
	printf("PacketCnt      : %lli %lli %lli %lli\n", s_PortPacketCnt[0], s_PortPacketCnt[1], s_PortPacketCnt[2], s_PortPacketCnt[3]); 
	printf("TimeOrder      : %lli\n", s_TimeOrderFail); 
	printf("CRCFail        : %lli\n", s_ErrorFCS); 
	printf("TotalPCAPTime  : %lli ns\n", dTime); 
	printf("Bandwidth      : %.3f Mbps\n", ((s_TotalWireByte * 8) / (dTime/1e9)) / 1e6); 
	printf("Packet Rate    : %.3f Kpps\n",  ((s_TotalPacket) / (dTime/1e9)) / 1e3); 
	printf("\n");

	// dump sequence histogram
	if (s_SeqValidateHisto)
	{
		for (int i=0; i < 256; i++)
		{
			if (s_SeqPrefixHisto[i] > 0)
			{
				printf("  0x%02xxxxxxx PrefixCnt: %10lli\n", i, s_SeqPrefixHisto[i]);
			}
		}
	}

	printf("Complete\n");

	return 0;
}
