//---------------------------------------------------------------------------------------------
//
// Copyright (c) 2015-2025 Fmad Engineering Pte. Ltd.
//
// Layer 1 decoding utility 
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
static bool		s_IsPrintXGMII		= true;					// by default print XGMII traffic

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

	u64				timestamp0;					// total of 80bits
	u16				timestamp1;

	u8				lock_status;				// internal

	u8				fifo_underflow_cnt;			// internal fifo underflow counter 
	u8				fifo_overflow_cnt;			// internal fifo overflow counter

	u8				fifo_errors;				// internal fifo flags

	u8				debug[3];

} __attribute__((packed)) fL1Header_t;

static void ProcessPacket(u8* Payload, u32 Length, u64 TS, u32 Flag)
{
	fL1Header_t* Header = (fL1Header_t*)(Payload);


	u8 HeaderStr[128];
	ns2str(HeaderStr, TS); 

	u64 L1TS = (Header->timestamp0 <<16) | Header->timestamp1;

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


	if (g_Verbose) printf("%s cap%i SeqNo:%016llx CompressCnt:%8i CompressWord:%08x Timestamp:%16llx Underflow:%4i Overflow:%4i FIFOError:%08x Gaps:%lli %s\n", 
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



	// print traffic
	{

		if (Header->compress_cnt > 0)
		{
			if (s_IsPrintXGMII)
			{
				printf("%s %3i : cap%i %s %s %02s %s (rep %i x %08x)\n",

					HeaderStr,
					0,

					Header->lane_no,
					" ",
					" ",

					"--",	

					"----------------",

					Header->compress_cnt,
					Header->compress_data
				);
			}
		}

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

			if (s_IsPrintXGMII)
			{
				printf("%s %3i : cap%i %s %s %02x %02x%02x%02x%02x%02x%02x%02x%02x\n", 

						HeaderStr,
						w,

						Header->lane_no,
						sof,
						eof,

						bitswap8(C8[0]),

						D8[0],
						D8[1],
						D8[2],
						D8[3],
						D8[4],
						D8[5],
						D8[6],
						D8[7]
				);
			}
			C8 += 1;
			D8 += 8;
		}	
	}
}

//-------------------------------------------------------------------------------------------------

static void PrintHelp(void)
{
	printf(
		"Usage: pcap_l1decode [options]\n"
		"\n"
		"Copyright (c) 2015-2025 Fmad Engineering Pte. Ltd.\n"
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
		else if (strcmp(argv[i], "--disable-xgmii") == 0)
		{
			s_IsPrintXGMII = false;
			fprintf(stderr, "Disable XGMII Printout\n");
		}
		// select a specific port only
		else if (strcmp(argv[i], "--port") == 0)
		{
			s_FilterPort = atoi(argv[i+1]);
			fprintf(stderr, "Output only cap%i\n", s_FilterPort);
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
		printf("PCAP nano\n"); 
		s_TScale = 1;
		break;

	case PCAPHEADER_MAGIC_USEC: 
		printf("PCAP usec\n"); 
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
		printf("invalid magic: %08x\n", Header.Magic);	
		assert(false);
	}

	// reset seq number check
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
				printf("no more data\n");
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
	}

	for (int p=0; p < 4; p++)
	{

		printf("cap%i : SOFCnt %10lli EOFCnt: %10lli Delta:%8lli\n", p, s_TotalSOFCnt[p],  s_TotalEOFCnt[p], s_TotalSOFCnt[p] - s_TotalEOFCnt[p] );
	}

	return 0;
}
