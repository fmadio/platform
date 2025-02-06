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

static u64 		s_TScale 			= 0;					// timescale of the pcap

static bool		s_Exit				= false;				// exit from main loop


static u64		s_TotalPacket		= 0;					// total packet count
static u64		s_TotalCaptureByte	= 0;					// total bytes captured 
static u64		s_TotalWireByte		= 0;					// total bytes on the wire 

static bool		g_Verbose			= false;				// verbose output

double TSC2Nano = 0;

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

//-------------------------------------------------------------------------------------------------

// L1 encapsulation format
//
//  typedef struct packed {
//    logic [23:0] debug;
//    logic [7:0]  fifo_errors;
//    logic [63:0] fifo_overflow_cnt;
//    logic [63:0] fifo_underflow_cnt;
//    logic [7:0]  lock_status;
//    logic [79:0] timestamp;
//    logic [63:0] idle_cnt;
//    logic [63:0] idle_cnt_total;
//    logic [63:0] eof_cnt;
//    logic [63:0] seq_no;
//    logic [7:0]  lane_no;
//
//  } metadata_t;

typedef struct
{
	u8				lane_no;					// port the traffic was captured on
	u64				seq_no;						// L1 block data was captured on

	u64				eof_cnt;					// End of Frame counter
	u64				idle_cnt_total;				// total number of idles seen
	u64				idle_cnt;					// number of idels before this block

	u64				timestamp0;					// total of 80bits
	u16				timestamp1;

	u8				lock_status;				// internal

	u64				fifo_underflow_cnt;			// internal fifo underflow counter 
	u64				fifo_overflow_cnt;			// internal fifo overflow counter

	u8				fifo_errors;				// internal fifo flags

	u8				debug[3];

} __attribute__((packed)) fL1Header_t;

static void ProcessPacket(u8* Payload, u32 Length, u64 TS, u32 Flag)
{
	fL1Header_t* Header = (fL1Header_t*)(Payload);

	u64 L1TS = (Header->timestamp0 <<16) | Header->timestamp1;

	if (g_Verbose) printf("Lane:%3i SeqNo:%016llx IdleCnt:%8lli IdleTotal:%8lli EOF Cnt:%8lli Timestamp:%16llx Underflow:%8lli Overflow:%8lli FIFOError:%08x\n", 
										Header->lane_no, 
										swap64(Header->seq_no), 
										swap64(Header->idle_cnt), 
										swap64(Header->idle_cnt_total), 
										swap64(Header->eof_cnt), 
										L1TS,
										swap64(Header->fifo_underflow_cnt),
										swap64(Header->fifo_overflow_cnt),
										Header->fifo_errors

	); 


	// ctrl is 64 words @ 8 bits
	// data is 64 words @ 64 bits
	u8* C8 = (u8*)(Header + 1);
	u8* D8 = (u8*)(C8     + 64);

	for (int w=0; w < 64; w++)
	{
		u8* sof = " ";
		u8* eof = " ";

		for (int i=0; i < 8; i++) if (( (C8[0] >> i) & 1)  && (D8[i] == 0xfb)) sof = "S";
		for (int i=0; i < 8; i++) if (( (C8[0] >> i) & 1)  && (D8[i] == 0xfd)) eof = "E";

		printf("%s %s %02x %02x%02x%02x%02x%02x%02x%02x%02x\n", 

				sof,
				eof,

				C8[0],

				D8[0],
				D8[1],
				D8[2],
				D8[3],
				D8[4],
				D8[5],
				D8[6],
				D8[7]
		);
		C8 += 1;
		D8 += 8;
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

	u64 LastTSC 	= rdtsc();
	u64 LastByte 	= 0;
	u64 LastPacket 	= 0;

	u64 NextPrintTSC = rdtsc();
	while (!s_Exit)
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

	return 0;
}
