//---------------------------------------------------------------------------------------------
//
// Copyright (c) 2015-2025 Fmad Engineering Pte. Ltd.
//
// Layer 1 soft MAC 
//
// LICENSE: refer to https://github.com/fmadio/platform/blob/main/LICENSE.md
//
//---------------------------------------------------------------------------------------------

#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sched.h> 
#include <pthread.h> 

#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/shm.h>

#include "include/fmadio_packet.h"


//-------------------------------------------------------------------------------------------------

static bool		s_IsPktPCAP			= true;					// input format is a PCAP
static bool		s_IsPktFMAD			= false;				// input format is a FMAD Chunked 
static bool		s_IsPrintPacket		= false;				// print the raw packet to console 
static bool		s_IsPrintXGMII		= false;				// print every xgmii cycles data 

static u64 		s_TScale 			= 0;					// timescale of the pcap

static bool		s_Exit				= false;				// exit from main loop


static u64		s_TotalPacket		= 0;					// total packet count
static u64		s_TotalCaptureByte	= 0;					// total bytes captured 
static u64		s_TotalWireByte		= 0;					// total bytes on the wire 

static u64		s_TotalSOFCnt[4]	= {0, 0, 0, 0};			// total number of SOFs found
static u64		s_TotalEOFCnt[4]	= {0, 0, 0, 0};			// total number of EOFs found

static bool		g_Verbose			= false;				// verbose output

double TSC2Nano = 0;

static u64		s_LastSeqNo[32];							// last sequence number per lane
static u64		s_TotalGap			= 0;					// total number of gaps

static u32		s_FilterPort		= (u32)-1;				// filter for a specific port

//-------------------------------------------------------------------------------------------------
// misc utils

static inline u32 swap32(const u32 a)
{
	return (((a>>24)&0xFF)<<0) | (((a>>16)&0xFF)<<8) | (((a>>8)&0xFF)<<16) | (((a>>0)&0xFF)<<24);
}

static inline u16 swap16(const u16 a)
{
	return (((a>>8)&0xFF)<<0) | (((a>>0)&0xFF)<<8);
}

static inline u64 swap64(const u64 a)
{
	return swap32(a>>32ULL) | ( (u64)swap32(a) << 32ULL); 
}

static inline u32 bitswap8(const u32 a)
{
	u32 b = 0;

	b |= ((a >> 0) & 1 ) << 7;		
	b |= ((a >> 1) & 1 ) << 6;		
	b |= ((a >> 2) & 1 ) << 5;		
	b |= ((a >> 3) & 1 ) << 4;		
	b |= ((a >> 4) & 1 ) << 3;		
	b |= ((a >> 5) & 1 ) << 2;		
	b |= ((a >> 6) & 1 ) << 1;		
	b |= ((a >> 7) & 1 ) << 0;		

	return b;
}

static inline void  ns2str(u8* Str, u64 TS) 
{

	time_t t0 = TS / 1e9;

	struct tm* t = localtime(&t0);

	u32 year	= 1900 + t->tm_year;
	u32 month	= 1 + t->tm_mon;
	u32 day		= t->tm_mday;
	u32 hour	= t->tm_hour;
	u32 min		= t->tm_min;
	u32 sec0	= t->tm_sec;

	u64 sec = TS % ((u64)1e9);	
	int msec = sec / 1000000ULL; 
	int usec = (sec - msec*1000000ULL)/ 1000ULL; 
	int nsec = (sec - msec*1000000ULL- usec*1000ULL);

	sprintf(Str, "%04i%02i%02i_%02i%02i%02i.%03i_%03i_%03i", year, month, day, hour, min, sec0, msec, usec, nsec);
}

//-------------------------------------------------------------------------------------------------

// L1 encapsulation format
//
// 2025/03: origial header
// typedef struct packed {
//     logic [23:0] debug;
//     logic [7:0]  fifo_errors;
//     logic [7:0]  fifo_overflow_cnt;
//     logic [7:0]  fifo_underflow_cnt;
//     logic [7:0]  lock_status;
//     logic [79:0] timestamp;
//     logic [63:0] idle_cnt;
//     logic [63:0] idle_cnt_total;
//     logic [63:0] eof_cnt;
//     logic [63:0] seq_no;
//     logic [7:0]  lane_no;
//     logic [15:0] ethertype;
//     logic [47:0] src_mac;
//     logic [47:0] dst_mac;
// 
//   } metadata_t;
//
// 2025/4/24 : reduce compression coutners 
//             (from FW 10842+)
//
// typedef struct packed {
//    logic [23:0] debug;
//    logic [7:0]  fifo_errors;
//    logic [7:0]  fifo_overflow_cnt;
//    logic [7:0]  fifo_underflow_cnt;
//    logic [7:0]  lock_status;
//    logic [79:0] timestamp;
//    logic [63:0] unused;
//    logic [31:0] compress_cnt;
//    logic [63:0] compress_total;
//    logic [31:0] compress_data;
//    logic [63:0] seq_no;
//    logic [7:0]  lane_no;
//    logic [15:0] ethertype;
//    logic [47:0] src_mac;
//    logic [47:0] dst_mac;
//
//  } metadata_t;

typedef struct
{
	u8				mac_dst[6];
	u8				mac_src[6];
	u16				ethertype;					// 0xfeed
	u8				lane_no;					// port the traffic was captured on
	u64				seq_no;						// L1 block data was captured on

	u32				compress_data;
	u64				compress_total;
	u32				compress_cnt;
	u64				pad0;

	u16				timestamp_frac;				// fractions of ns
	u64				timestamp_ns;				// epoch nanos 

	u8				lock_status;				// internal

	u8				fifo_underflow_cnt;			// internal fifo underflow counter 
	u8				fifo_overflow_cnt;			// internal fifo overflow counter

	u8				fifo_errors;				// internal fifo flags

	u8				debug[3];

} __attribute__((packed)) fL1Header_t;

// packet state

typedef struct
{
	bool			InPacket;					// current in a packet
	u64				SOFTS;						// start of frame TS

	u32 			BufferPos;					// position in the buffer
	u8 				BufferCtl[16*1024];			// raw l1 ctrl for the packet
	u8 				BufferDat[16*1024];			// raw l1 data for the packet

} Packet_t;

static Packet_t		s_Packet[16];

static void GeneratePacket(Packet_t* P)
{
	if (s_IsPrintPacket)
	{
		fprintf(stderr, "Generate packet: TS:%lli Bytes:%i\n", P->SOFTS, P->BufferPos);
		for (int i=0; i < P->BufferPos; i++)
		{
			fprintf(stderr, "%2i", P->BufferCtl[i]);
		}
		fprintf(stderr, "\n");
		for (int i=0; i < P->BufferPos; i++)
		{
			fprintf(stderr, "%02x", P->BufferDat[i]);
		}
		fprintf(stderr, "\n");
	}

	// check for valid pre-amble
	bool IsValid = true;
	if ((P->BufferCtl[0] != 1) || (P->BufferDat[0] != 0xfb)) IsValid = false;
	if ((P->BufferCtl[1] != 0) || (P->BufferDat[1] != 0x55)) IsValid = false;
	if ((P->BufferCtl[2] != 0) || (P->BufferDat[2] != 0x55)) IsValid = false;
	if ((P->BufferCtl[3] != 0) || (P->BufferDat[3] != 0x55)) IsValid = false;
	if ((P->BufferCtl[4] != 0) || (P->BufferDat[4] != 0x55)) IsValid = false;
	if ((P->BufferCtl[5] != 0) || (P->BufferDat[5] != 0x55)) IsValid = false;
	if ((P->BufferCtl[6] != 0) || (P->BufferDat[6] != 0x55)) IsValid = false;
	if ((P->BufferCtl[7] != 0) || (P->BufferDat[7] != 0xd5)) IsValid = false;

	// invalid preamble
	if (!IsValid)
	{
		fprintf(stderr, "invalid preamble\n");
	}

	// calculate length of the packet
	s32 PacketLength = P->BufferPos - 8 - 1;

	// if no preamble then cant output anything 
	if (PacketLength <= 0) 
	{
		fprintf(stderr, "invalid packet size: %i\n", P->BufferPos);

		P->InPacket 	= false;
		P->BufferPos 	= 0;
		return;
	}


	// pcap header
	PCAPPacket_t PCAPPacket;

	PCAPPacket.Sec 			= P->SOFTS / (u64)1e9;
	PCAPPacket.NSec 		= P->SOFTS % (u64)1e9;
	PCAPPacket.LengthCapture= PacketLength;
	PCAPPacket.LengthWire	= PacketLength;
	fwrite(&PCAPPacket, sizeof(PCAPPacket), 1, stdout);

	// payload
	fwrite(P->BufferDat + 8, PacketLength, 1, stdout);


	P->InPacket 	= false;
	P->BufferPos 	= 0;
}

static void ProcessXGMII(u32 PortNo, u32 Ctrl, u64 Data, u64 TS)
{
	if (s_IsPrintXGMII) fprintf(stderr, "cap%i %02x %016llx\n", PortNo, Ctrl, Data);

	assert(PortNo < 16);
	Packet_t* P = &s_Packet[PortNo];

	u8 Data8[8];
	Data8[0] = (Data >> 0*8)&0xFF;
	Data8[1] = (Data >> 1*8)&0xFF;
	Data8[2] = (Data >> 2*8)&0xFF;
	Data8[3] = (Data >> 3*8)&0xFF;
	Data8[4] = (Data >> 4*8)&0xFF;
	Data8[5] = (Data >> 5*8)&0xFF;
	Data8[6] = (Data >> 6*8)&0xFF;
	Data8[7] = (Data >> 7*8)&0xFF;

	for (int i=7; i >= 0; i--)
	{
		u32 Ctrl1 = (Ctrl >> i) & 1;

		// start of the packet
		if ( Ctrl1 && (Data8[i] == 0xfb))
		{
			P->InPacket 	= true;
			P->SOFTS		= TS; 
		}

		// append byte to the packet
		if (P->InPacket)
		{
			P->BufferCtl[P->BufferPos] = Ctrl1;
			P->BufferDat[P->BufferPos] = Data8[i];
			P->BufferPos				+= 1;
		}

		// end of the frame
		if ( Ctrl1 && (Data8[i] == 0xfd))
		{
			GeneratePacket(P);
		}

		// end of packet oversized
		if (P->BufferPos > 9600)
		{
			GeneratePacket(P);
		}
	}
}

static void ProcessPacket(u8* Payload, u32 Length, u64 TS, u32 Flag)
{
	fL1Header_t* Header = (fL1Header_t*)(Payload);

	u8 HeaderStr[128];
	ns2str(HeaderStr, TS); 

	u64 L1TS = Header->timestamp_ns; //) | ( ((u64)Header->timestamp1) << 32);

	// check sequence numbers
	s64 dSeq = Header->seq_no - s_LastSeqNo[ Header->lane_no ];

	u8* dSeqStr = "  ";
	// seq number will not wrap around in any real use case
	if ((dSeq != 1) && (s_LastSeqNo[Header->lane_no] != 0))
	{
		s_TotalGap += 1;
		dSeqStr = "GAP";
		fprintf(stderr, "cap%i SeqNo:%016llx Gap count: %lli\n", Header->lane_no, Header->seq_no, dSeq); 
	}

	// filter for specific port only
	if (s_FilterPort != (u32)-1)
	{
		if (Header->lane_no != s_FilterPort) return;
	}


	if (g_Verbose) fprintf(stderr, "%s cap%i SeqNo:%016llx CompressCnt:%8i CompressWord:%08x Timestamp:%16llx Underflow:%4i Overflow:%4i FIFOError:%08x Gaps:%lli %s\n", 
										HeaderStr,
										Header->lane_no, 
										Header->seq_no, 
										Header->compress_cnt, 
										Header->compress_data, 
										L1TS,
										Header->fifo_underflow_cnt,
										Header->fifo_overflow_cnt,
										Header->fifo_errors,
										s_TotalGap,
										dSeqStr

	); 

	s_LastSeqNo[ Header->lane_no ] = Header->seq_no;

	// generate packet 
	{

		// ctrl is 64 words @ 8 bits
		// data is 64 words @ 64 bits
		u8* C8 = (u8*)(Header + 1);
		u8* D8 = (u8*)(C8     + 64);

		for (int w=0; w < 64; w++)
		{
			u8* sof = " ";
			u8* eof = " ";

			for (int i=0; i < 8; i++) if (( (C8[0] >> i) & 1)  && (D8[i] == 0xfb))
			{
				sof = "S";
				s_TotalSOFCnt[Header->lane_no]++;
			}
			for (int i=0; i < 8; i++) if (( (C8[0] >> i) & 1)  && (D8[i] == 0xfd))
			{
				eof = "E";
				s_TotalEOFCnt[Header->lane_no]++;
			}


			u32 PortNo = Header->lane_no;

			u32 Ctrl = bitswap8(C8[0]);

			u64 Data = 	( (u64)D8[0] << (u64)(7*8)) | 
						( (u64)D8[1] << (u64)(6*8)) | 
						( (u64)D8[2] << (u64)(5*8)) | 
						( (u64)D8[3] << (u64)(4*8)) | 
						( (u64)D8[4] << (u64)(3*8)) | 
						( (u64)D8[5] << (u64)(2*8)) | 
						( (u64)D8[6] << (u64)(1*8)) | 
						( (u64)D8[7] << (u64)(0*8));

			ProcessXGMII(PortNo, Ctrl, Data, L1TS);
			C8 += 1;
			D8 += 8;
		}	
	}
}

//-------------------------------------------------------------------------------------------------

static void PrintHelp(void)
{
	printf(
		"Usage: pcap_l1softmac [options]\n"
		"\n"
		"Copyright (c) 2015-2026 Fmad Engineering Pte. Ltd.\n"
		"\n"
		"Note that input *must* come from stdin.\n"
		"\n"
		"Options:\n"
		"\n"
		"  --help                      : print this message and then exit\n"
		"  --version, -V               : print the program's version information and then exit\n"
		"\n"
	);
}

static void PrintVersion(void)
{
	printf("%s compiled on %s %s\n", GIT_COMMIT, __DATE__, __TIME__);
}

//-------------------------------------------------------------------------------------------------

enum
{
	EXIT_BADARG = EXIT_FAILURE + 1,
	EXIT_MISSINGARG,
};

int main(int argc, char* argv[])
{
	// sanity check should be 64B
	assert(sizeof(fL1Header_t) == 64);

	// Early-out if appropriate.
	for (int i = 1; i < argc; ++i)
	{
		if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0)
		{
			PrintHelp();
			return EXIT_SUCCESS;
		}
		else if (strcmp(argv[i], "--version") == 0 || strcmp(argv[i], "-V") == 0)
		{
			PrintVersion();
			return EXIT_SUCCESS;
		}
	}

	bool Verbose 			= false;
	s32 CPUID				= -1;

	for (int i = 1; i < argc; i++)
	{
		if (strcmp(argv[i], "--cpu") == 0) 
		{
			if ((i + 1) >= argc)
			{
				fprintf(stderr, "argument '%s' expects a following integer argument\n", argv[i]);
				return EXIT_MISSINGARG;
			}

			CPUID = atoi(argv[i + 1]);
			fprintf(stderr, "CPU Affinity: %i\n", CPUID);
			i++;
		}
		else if (strcmp(argv[i], "-v") == 0)
		{
			g_Verbose = true;
			fprintf(stderr, "Verbose output\n");
		}
		// select a specific port only
		else if (strcmp(argv[i], "--port") == 0)
		{
			s_FilterPort = atoi(argv[i+1]);
			fprintf(stderr, "Output only cap%i\n", s_FilterPort);
			i++;
		}
		// print packet layer1 data 
		else if (strcmp(argv[i], "--xgmii-packet") == 0)
		{
			s_IsPrintPacket = true;
			fprintf(stderr, "Print XGMII Packet Data\n");
			i++;
		}
		// print very xgmii cycle 
		else if (strcmp(argv[i], "--xgmii") == 0)
		{
			s_IsPrintXGMII = true;
			fprintf(stderr, "Print XGMII stream\n");
			i++;
		}
		else
		{
			fprintf(stderr, "Unrecognized argument: '%s'\n", argv[i]);
			return EXIT_BADARG;
		}
	}

	// set cpu affinity
	if (CPUID != -1)
	{
		cpu_set_t	MainCPUS;
		CPU_ZERO(&MainCPUS);
		CPU_SET(CPUID, &MainCPUS);
		pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &MainCPUS);
	}

	u32 BufferPos 	= 0;
	u32 BufferMax 	= 1024*1024;
	u8* Buffer 		= malloc(1024*1024+128*1024); 

	// chunked fmad buffer
	u8* FMADChunkBuffer = NULL; 

	// read pcap header in first
	PCAPHeader_t	Header;
	assert(fread(&Header, 1, sizeof(Header), stdin) == sizeof(Header));


	// assume its pcap
	s_IsPktPCAP 	= true;
	s_IsPktFMAD 	= false;
	switch (Header.Magic)
	{
	case PCAPHEADER_MAGIC_NANO: 
		fprintf(stderr, "PCAP nano\n"); 
		s_TScale = 1;
		break;

	case PCAPHEADER_MAGIC_USEC: 
		fprintf(stderr, "PCAP usec\n"); 
		s_TScale = 1000; 
		break;

	case PCAPHEADER_MAGIC_FMAD: 
		fprintf(stderr, "FMAD Format Chunked\n");
		s_TScale = 1; 
		s_IsPktPCAP 	= false;
		s_IsPktFMAD 	= true;

		// allocate buffer
		FMADChunkBuffer = malloc(1024*1024);
		break;

	default:
		fprintf(stderr, "invalid PCAP header magic: %08x\n", Header.Magic);	
		assert(false);
	}

	// write output header 
	PCAPHeader_t		OutHeader;
	OutHeader.Magic 	= PCAPHEADER_MAGIC_NANO;
	OutHeader.Major 	= PCAPHEADER_MAJOR;
	OutHeader.Minor 	= PCAPHEADER_MINOR;
	OutHeader.TimeZone 	= 0;
	OutHeader.SigFlag 	= 0;
	OutHeader.SnapLen 	= 9600;
	OutHeader.Link 		= PCAPHEADER_LINK_ETHERNET;
	fwrite(&OutHeader, sizeof(OutHeader), 1, stdout);


	memset(s_LastSeqNo, 0, sizeof(s_LastSeqNo) );

	u64 LastTSC 	= rdtsc();
	u64 LastByte 	= 0;
	u64 LastPacket 	= 0;

	u64 NextPrintTSC = rdtsc();
	while (!s_Exit)
	{
		if (s_IsPktPCAP)
		{
			int rlen = fread(Buffer + BufferPos, 1, BufferMax - BufferPos, stdin);	
			if (rlen <= 0)
			{
				fprintf(stderr, "no more data\n");
				break;
			}

			u32 BufferOffset = 0;
			u32 BufferEnd = BufferPos + rlen; 
			while (true)
			{
				PCAPPacket_t* Pkt = (PCAPPacket_t*)(Buffer + BufferOffset);

				if (BufferOffset + sizeof(PCAPPacket_t) >= BufferEnd) break;
				//printf("[%08x] Pkt: %i\n", BufferOffset, Pkt->Length);

				assert(Pkt->LengthWire > 0);
				assert(Pkt->LengthWire < 16*1024);

				if (BufferOffset + Pkt->LengthCapture + sizeof(PCAPPacket_t) > BufferEnd)
				{
					break;
				}
		
				u64 TS = ((u64)Pkt->Sec) * 1000000000ULL  + ((u64)Pkt->NSec) * s_TScale;

				ProcessPacket( (u8*)(Pkt+1), Pkt->LengthCapture, TS, 0);

				s_TotalPacket++;
				s_TotalCaptureByte 		+= sizeof(PCAPPacket_t) + Pkt->LengthCapture;
				s_TotalWireByte 	+= Pkt->LengthWire;

				BufferOffset 	+= sizeof(PCAPPacket_t) + Pkt->LengthCapture;
			}

			u32 Remain = BufferMax - BufferOffset;	
			memmove(Buffer, Buffer + BufferOffset, Remain);	
			BufferPos = Remain;
		}

		// show status
		/*
		if (rdtsc() > NextPrintTSC)
		{
			u64 TSC = rdtsc();
			NextPrintTSC = TSC + ns2tsc(1e9);

			float dT =  tsc2ns(TSC - LastTSC) / 1e9;
			float dByte = s_TotalCaptureByte - LastByte;
			float dPkt = s_TotalPacket - LastPacket;
			float Bps = (dByte * 8) / dT;
			float pps = dPkt / dT;

			fprintf(stderr, "%.2fGB %8.3f Gbps %8.3f Mpps \n", (float)s_TotalCaptureByte/1e9, Bps/1e9, pps/1e6);
			fflush(stderr);

			LastByte = s_TotalCaptureByte;
			LastPacket = s_TotalPacket;
			LastTSC  = TSC;
		}
		*/
	}

	for (int p=0; p < 4; p++)
	{

		fprintf(stderr, "cap%i : SOFCnt %10lli EOFCnt: %10lli Delta:%8lli\n", p, s_TotalSOFCnt[p],  s_TotalEOFCnt[p], s_TotalSOFCnt[p] - s_TotalEOFCnt[p] );
	}

	return 0;
}
