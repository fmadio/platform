//-------------------------------------------------------------------------------------------------------------------
//
// Copyright (c) 2021-2022, fmad engineering group 
//
// LICENSE: refer to https://github.com/fmadio/platform/blob/main/LICENSE.md
//
// Minimial example to convert FMADIO Packet ring buffer to a standard PCAP. 
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

#include "include/fmadio_packet.h"

//------------------------------------------------------------------------------

static bool					s_IsRING	= false;			// shm ring format
static u8*					s_RINGPath	= NULL;				// path to shm file
static int					s_RINGfd;						// ring file handle
static fFMADRingHeader_t*	s_RING		= NULL;  			// mapping
static bool					s_NoSleep	= false;			// by default dont use the busy/poll

//------------------------------------------------------------------------------
static void help(void)
{
	fprintf(stderr, "fmadio2pcap <options>\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Converts FMADIO Ring buffer to a PCAP outputing the pcap on STDOUT\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Example: (writes nanosecond pcap to local file system)\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "fmadio2pcap -i /opt/fmadio/queue/lxc_ring0 > test.pcap\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Options:>\n");
	fprintf(stderr, "   -i <path to fmadio ring file>    : location of fmad ring file\n");
	fprintf(stderr, "   --cpu <cpu number>               : pin the process on the specified CPU\n");
	fprintf(stderr, "   --no-sleep                       : use ndelay for a tight busy polly loop\n");
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
	fprintf(stderr, "fmadio2pcap\n");

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

		// pin on a specific CPU
		if (strcmp(argv[i], "--cpu") == 0)
		{
			fprintf(stderr, "setting cpu affinity\n");
			if (argv[i+1] != NULL) 
			{
				CPU = atoi( argv[i+1] );
			}
			else 
			{
				fprintf(stderr, "invalid cpu setting\n");
				return 0;
			}
		}
		if (strcmp(argv[i], "--no-sleep") == 0)
		{
			s_NoSleep = true;
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
	FILE* FPCAP 		= stdout; 

	// write pcap header
	PCAPHeader_t Header;
	Header.Magic 		= PCAPHEADER_MAGIC_NANO;
	Header.Major 		= PCAPHEADER_MAJOR;
	Header.Minor 		= PCAPHEADER_MINOR;
	Header.TimeZone 	= 0;
	Header.SigFlag 		= 0;
	Header.SnapLen 		= 0xffff;
	Header.Link 		= PCAPHEADER_LINK_ETHERNET;
	fwrite(&Header, 1, sizeof(Header), FPCAP);

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

	while (!s_Exit)
	{
		u64 TS;
		PCAPPacket_t* Pkt	= (PCAPPacket_t*)PktBuffer;

		u32 PktFlag = 0;

		// fetch packet from ring without blocking
		int ret = FMADPacket_RecvV1(s_RING, false, &TS, &Pkt->LengthWire, &Pkt->LengthCapture, NULL, &PktFlag, Pkt + 1);

		// if it has valid data
		if (ret > 0)
		{
			// count flaged FCS packets
			if (PktFlag & FMADRING_FLAG_FCSERR)
			{
				TotalPktFCS++;
			}

			// santize it
			assert(Pkt->LengthCapture > 0);	
			assert(Pkt->LengthCapture < 16*1024);	

			// convert 64b epoch into sec/subsec for pcap
			Pkt->Sec 			= TS / (u64)1e9;
			Pkt->NSec 			= TS % (u64)1e9;

			// write PCAP header and payload 	
			fwrite(PktBuffer, 1, sizeof(PCAPPacket_t) + Pkt->LengthCapture, FPCAP); 

			// general stats
			TotalPkt 	+= 1;
			TotalByte 	+= ret;
		}	

		// end of stream
		if (ret < 0) break;

		// request is nonblocking, run less hot, use usleep(0) to reduce cpu usage more 
		if (ret == 0)
		{
			if (s_NoSleep)
			{
				ndelay(100);
			}
			else
			{
				usleep(0);
			}
		}
	}
	fflush(stdout);

	// summary stats 
	fprintf(stderr, "TotalPkt: %lli TotalByte:%lli TotalFCSError:%lli\n", TotalPkt, TotalByte, TotalPktFCS);

	return 0;
}
