//-------------------------------------------------------------------------------------------------------------------
//
// Copyright (c) 2021-2022, fmad engineering group 
//
// LICENSE: refer to https://github.com/fmadio/platform/blob/main/LICENSE.md
//
// output stats about the specififed ring 
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
// util to format epoch ns

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

	// dont do this at home.. this is only used for printf single use
	static u8 str[1024];
	sprintf(str, "%02lli:%02lli:%02lli.%03lli.%03lli.%03lli", hour % 24, min, sec, msec,usec, nsec);

	return str;
}

//------------------------------------------------------------------------------
static void help(void)
{
	fprintf(stderr, "fmadio2stat <options>\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Dumps statistics about the specified  FMADIO Ring buffer\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "fmadio2stat -i /opt/fmadio/queue/lxc_ring0\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Options:>\n");
	fprintf(stderr, "   -i <path to fmadio ring file>    : location of fmad ring file\n");
	fprintf(stderr, "\n");
}

//------------------------------------------------------------------------------

int main(int argc, char* argv[])
{
	fprintf(stderr, "fmadio2stat\n");

	int IsJSON = false;
	for (int i=0; i < argc; i++)
	{
		// location of shm ring file 
		if (strcmp(argv[i], "-i") == 0)
		{
			s_IsRING		= true;
			s_RINGPath 		= argv[i+1];
			fprintf(stderr, "FMAD Ring [%s]\n", s_RINGPath);
		}

		if (strcmp(argv[i], "--json") == 0)
		{
			IsJSON = true;
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

	// map the ring file readonly
	if (FMADPacket_OpenMon(&s_RINGfd, &s_RING, s_RINGPath) < 0)
	{
		fprintf(stderr, "failed to open FMAD Ring [%s]\n", s_RINGPath);	
		return 0;
	}

	// human
	if (!IsJSON)
	{
		printf("RING[%-50s] : Upstream: %20lli Bytes   (%10.2f GB)\n", 	s_RING->Path, s_RING->PendingB, s_RING->PendingB / 1e9);
		printf("RING[%-50s] :                                     \n", 	s_RING->Path);

		printf("RING[%-50s] : Put     : %20lli Pkts   (%10.2f Bn)\n", 	s_RING->Path, s_RING->Put, s_RING->Put / 1e9);
		printf("RING[%-50s] : Get     : %20lli Pkts   (%10.2f Bn)\n", 	s_RING->Path, s_RING->Get, s_RING->Get / 1e9);
		printf("RING[%-50s] :           %20lli\n", 						s_RING->Path, s_RING->Put - s_RING->Get);

		printf("RING[%-50s] : PutByte : %20lli Bytes  (%10.2f GB)\n", 	s_RING->Path, s_RING->PutByte, s_RING->PutByte / 1e9);
		printf("RING[%-50s] : GetByte : %20lli Bytes  (%10.2f GB)\n", 	s_RING->Path, s_RING->GetByte, s_RING->GetByte / 1e9);
		printf("RING[%-50s] :           %20lli\n", 						s_RING->Path, s_RING->PutByte - s_RING->GetByte);

		printf("RING[%-50s] : PutTS   : %20lli Epoch  (%s)\n", 			s_RING->Path, s_RING->PutPktTS, FormatTS(s_RING->PutPktTS) );
		printf("RING[%-50s] : GetTS   : %20lli Epoch  (%s)\n", 			s_RING->Path, s_RING->GetPktTS, FormatTS(s_RING->GetPktTS) );
		printf("RING[%-50s] :           %20lli\n", 						s_RING->Path, s_RING->PutPktTS - s_RING->GetPktTS);
	}
	else
	{
		printf("{\"ring\":\"%s\",", s_RING->Path);

		printf("\"UpstreamByte\":%lli,", s_RING->PendingB);
		printf("\"Put\":%lli,", s_RING->Put);
		printf("\"Get\":%lli,", s_RING->Get);
		printf("\"dPutGet\":%lli,", s_RING->Put - s_RING->Get);

		printf("\"PutByte\":%lli,", s_RING->PutByte);
		printf("\"GetByte\":%lli,", s_RING->GetByte);
		printf("\"dByte\":%lli,", s_RING->PutByte - s_RING->GetByte);

		printf("\"PutPktTS\":%lli,", s_RING->PutPktTS);
		printf("\"GetPktTS\":%lli,", s_RING->GetPktTS);
		printf("\"dPktTS\":%lli,", s_RING->PutPktTS - s_RING->GetPktTS);


		printf("\"zero\":0}\n");
	}

	return 0;
}
