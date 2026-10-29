//-------------------------------------------------------------------------------------------------------------------
//
// Copyright (c) 2021-2026, fmad engineering group 
//
// LICENSE: refer to https://github.com/fmadio/platform/blob/main/LICENSE.md
//
// Minimial example to filter ARP traffic from the incomming to generate an exportable trace file
//
//-------------------------------------------------------------------------------------------------------------------

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

#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/time.h>

#include "include/fmadio_packet.h"

// ethernet header
typedef struct fEther_t
{
	u8		Dst[6];
	u8		Src[6];
	u16		Proto;

} fEther_t;


static u16 swap16(const u16 a)
{
	return (((a>>8)&0xFF)<<0) | (((a>>0)&0xFF)<<8);
}

// epoch in nanos in GMT timezone 
static u64 clock_ns(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);

	return (u64)tv.tv_sec *(u64)1e9 +(u64)tv.tv_usec * (u64)1e3;
}

static char* FormatTS(u64 ts)
{
	u64 usec = ts / 1000ULL;
	u64 msec = usec / 1000ULL;
	u64 sec = msec / 1000ULL;
	u64 min = sec / 60ULL;
	u64 hour = min / 60ULL;

	u64 nsec = ts - usec*1000ULL;
	usec = usec - msec*1000ULL;
	msec = msec - sec*1000ULL;
	sec = sec - min*60ULL;
	min = min - hour*60ULL;

	static char List[16][128];
	static int Pos = 0;

	char* S = List[Pos];
	Pos = (Pos + 1) & 0xf;

	sprintf(S, "%02lli:%02lli:%02lli.%03lli.%03lli.%03lli", hour % 24, min, sec, msec,usec, nsec);
	return S;
}

//------------------------------------------------------------------------------

static bool					s_IsRING	= false;			// shm ring format
static u8*					s_RINGPath	= NULL;				// path to shm file
static int					s_RINGfd;						// ring file handle
static fFMADRingHeader_t*	s_RING		= NULL;  			// mapping
static bool					s_NoSleep	= false;			// by default dont use the busy/poll

//------------------------------------------------------------------------------
static void help(void)
{
	fprintf(stderr, "fmadio2trace <options>\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Converts FMADIO Ring buffer to a filtered CSV trace extract\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "fmadio2trace -i /opt/fmadio/queue/lxc_ring0 > test.pcap.csv\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Options:>\n");
	fprintf(stderr, "   -i <path to fmadio ring file>    : location of fmad ring file\n");
	fprintf(stderr, "\n");
}

//------------------------------------------------------------------------------
// signal handler for clean exit
volatile bool s_Exit 		= false;
static void signal_handler(int sig)
{
	fprintf(stderr, "ctrl-c\n");
	fflush(stdout);
	s_Exit  = true;
}

//------------------------------------------------------------------------------

int main(int argc, char* argv[])
{
	fprintf(stderr, "fmadio2trace\n");

	int CPU = -1;
	for (int i=0; i < argc; i++)
	{
		// location of shm ring file 
		if (strcmp(argv[i], "-i") == 0)
		{
			s_IsRING		= true;
			s_RINGPath 		= argv[i+1];
			fprintf(stderr, "FMAD Ring [%s]\n", s_RINGPath);
		}
		if (strcmp(argv[i], "--help") == 0)
		{
			help();
			return 0;
		}
	}

	if (!s_IsRING)
	{
		fprintf(stderr, "specify ring interface with -i <path to ring file>\n");
		return 0;
	}

	if (CPU != -1)
	{
		cpu_set_t  mask;

		CPU_ZERO(&mask);
		CPU_SET(CPU, &mask);
		sched_setaffinity(0, sizeof(mask), &mask);
	}

	//map the ring file
	if (FMADPacket_OpenRx(&s_RINGfd, &s_RING, true, s_RINGPath) < 0)
	{
		fprintf(stderr, "failed to open FMAD Ring [%s]\n", s_RINGPath);	
		return 0;
	}

	// signal handlers
	signal(SIGINT,  signal_handler);
	signal(SIGHUP,  signal_handler);
	signal(SIGPIPE, signal_handler);

	// write file to stoud
	FILE* FCSV 		= stdout; 

	// write csv header
	fprintf(FCSV, "ts_begin,hostname,storage_id\n");


	u32 PktBufferMax = 128*1024;
	u8* PktBuffer = malloc(PktBufferMax);
	memset(PktBuffer, 0, PktBufferMax);

	u64 TotalPkt 	= 0;
	u64 TotalByte 	= 0;
	u64 TotalPktFCS	= 0;			// total number of packets with FCS errors

	u32 LastSec		= 0;
	u64 LastTS		= 0;
	u64 LastByte	= 0;
	u64 LastPkt		= 0;

	u64 NextPrintTSC = 0;

	u8* HostName	= "";

	while (!s_Exit)
	{
		u64 TS;
		PCAPPacket_t* Pkt	= (PCAPPacket_t*)PktBuffer;


		// fetch packet from ring without blocking
		u64 StorageID = 0;
		int ret = FMADPacket_RecvV1a(s_RING, false, &TS, &Pkt->LengthWire, &Pkt->LengthCapture, NULL, NULL, &StorageID, Pkt + 1);


		// if it has valid data
		if (ret > 0)
		{
			// santize it
			assert(Pkt->LengthCapture > 0);	
			assert(Pkt->LengthCapture < 16*1024);	

			// general stats
			TotalPkt 	+= 1;
			TotalByte 	+= ret;

			// only output broadcast packets 
			fEther_t* Ether = (fEther_t*)(Pkt + 1);

			u32 Proto = swap16(Ether->Proto);
			//printf("EtherType:%04x\n", Proto);

			// arp requests only
			if (Proto == 0x0806)
			{
				// output trace
				printf("%lli,%s,%lli, %016llx\n", TS, HostName, StorageID, TS);

			}	
		}

		// end of stream
		if (ret < 0) break;

		// request is nonblocking, run less hot, use usleep(0) to reduce cpu usage more 
		if (ret == 0)
		{
			usleep(0);
		}

		u64 TSC = rdtsc();
		if (TSC > NextPrintTSC)
		{
			u64 TS 	= clock_ns();
			s64 dTS = TS - LastTS;

			float dT = dTS / 1e9;

			s64 dByte = TotalByte - LastByte;
			s64 dPkt = TotalPkt - LastPkt;

			float bps = (dByte * 8.0);
			float pps = (dPkt * 1.0);

			fprintf(stderr, "[%s] Pkt: %10lli %8.3f Gbps %8.3f Mpps\n", FormatTS(TS), TotalPkt, bps / 1e9, pps/1e6);

			NextPrintTSC = TSC + 4e9;

			LastPkt 	= TotalPkt;
			LastByte 	= TotalByte;
			LastTS 		= TS;
		}
	}
	fflush(stdout);

	// summary stats 
	fprintf(stderr, "TotalPkt: %lli TotalByte:%lli TotalFCSError:%lli\n", TotalPkt, TotalByte, TotalPktFCS);

	return 0;
}
