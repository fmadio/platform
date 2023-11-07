// Copyright (c) 2023, FMAD Engineering (SNG) Pte. Ltd. 
// 
// pcap2fmadio

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/shm.h>

#include "include/fmadio_packet.h"

volatile sig_atomic_t s_Exit = false;

static void signal_handler(int i, siginfo_t* si, void* ctx)
{
	if (i == SIGINT || i == SIGTERM)
		exit(0);
}

static void PrintHelp()
{
	fprintf(stderr,
		"pcap2fmadio [options]\n"
		"\n"
		"Reads a PCAP file via stdin and writes its data to an FMADIO ring buffer\n"
		"\n"
		"Options:\n"
		"    -i <path to FMADIO ring file> (required)\n"
		"    --cpu <integer> : pin the process to the specified CPU core\n");
}

int main(int argc, char* argv[])
{
	int CPU = -1;
	u8* RingPath = NULL;

	for (int i = 0; i < argc; ++i)
	{
		if (strcmp(argv[i], "-i") == 0)
		{
			if ((i + 1) >= argc)
			{
				fprintf(stderr,
					"argument `-i` expects a following file path argument");

				return 1;
			}

			RingPath = argv[i + 1];
			i += 1;
		}
		else if (strcmp(argv[i], "--cpu") == 0)
		{
			if ((i + 1) >= argc)
			{
				fprintf(stderr,
					"argument `--cpu` expects a following integer argument");
				return 1;
			}

			CPU = atoi(argv[i + 1]);
			i += 1;
		}
		else if (strcmp(argv[i], "--help") == 0)
		{
			PrintHelp();
			return 0;
		}
	}

	signal(SIGINT, (sighandler_t)signal_handler);
	signal(SIGTERM, (sighandler_t)signal_handler);

	if (CPU != -1)
	{
		cpu_set_t  mask;
		CPU_ZERO(&mask);
		CPU_SET(CPU, &mask);
		sched_setaffinity(0, sizeof(mask), &mask);
	}

	if (RingPath == NULL)
	{
		fprintf(stderr, "Missing arguments `-i <path to FMADIO ring file>`\n");
		return 1;
	}

	u64 TimeScale;
	PCAPFile_t* PCAPFile = PCAP_Open(&TimeScale);

	if (PCAPFile == NULL)
		return 2;

	int PFD = -1;
	fFMADRingHeader_t* Ring = NULL;
	
	int Result = FMADPacket_OpenTx(&PFD, &Ring, false, RingPath, false, 1e6);

	if (Result < 0)
		return 3;

	while (true)
	{
		PCAPPacket_t* Pkt = PCAP_Read(PCAPFile);

		if (Pkt == NULL)
		{
			FMADPacket_SendEOFV1(Ring, PCAPFile->TS);
			fprintf(stderr, "Reached end of PCAP file.\n");
			return 0;
		}

		u64 TS = PCAP_TimeStamp(Pkt, TimeScale, 0 /* No time zone offset yet */);

		FMADPacket_SendV1(
			Ring,
			TS,
			Pkt->LengthWire,
			Pkt->LengthCapture,
			(u32)-1, /* port argument goes unused */
			Pkt + 1);

		PCAPFile->TS = TS;
	}

	return 0;
}

