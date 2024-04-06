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

#define k1E9 1000000000ULL

typedef struct
{
	char*	Path;			// path to the file
	char	Name[128];		// short name
	FILE*	F;			// buffered io file handle
	int	fd;			// file handler of the mmap attached data
	u64	Length;			// exact file length
	u64	MapLength;		// 4KB aligned mmap length
	u8*	Map;			// raw mmap ptr

	u64	ReadPos;		// current read pointer
	u64	PktCnt;			// number of packets processed

	u8*	PacketBuffer[256];	// packet queue 
	u32	PacketPut;		// packet head 
	u32	PacketGet;		// packet tail 
	u32	PacketMsk;		// wrap  
	u32	PacketMax;		// number of packet slots

	u8*	ReadBuffer;
	s32	ReadBufferPos;
	s32	ReadBufferLen;
	s32	ReadBufferMax;

	bool	Finished;		// read completed

	u64	TS;			// last TS processed

} PCAPFile_t;

static inline PCAPFile_t* PCAP_Open(u64* PCAPTimeScale)
{
	PCAPFile_t* F = (PCAPFile_t*)malloc( sizeof(PCAPFile_t) );
	assert(F != NULL);
	memset(F, 0, sizeof(PCAPFile_t));

	F->F 		= stdin;
	F->Length 	= 1e15;

	// Note: always map as read-only. 
	PCAPHeader_t Header1;

	PCAPHeader_t* Header = NULL; 

	{
		int ret = fread(&Header1, 1, sizeof(Header1), F->F);

		if (ret != sizeof(PCAPHeader_t))
		{
			fprintf(stderr, "failed to read header %i\n", ret);
			return NULL;
		}

		Header = &Header1;
		F->PacketPut	= 0;
		F->PacketGet	= 0;
		F->PacketMsk	= 255;
		F->PacketMax	= 256;

		for (int i=0; i < F->PacketMax; i++)
		{
			F->PacketBuffer[i]	= malloc(16 * 1024);
			assert(F->PacketBuffer != NULL);
		}
	}

	switch (Header->Magic)
	{
	case PCAPHEADER_MAGIC_USEC:
		fprintf(stderr, "USec PCAP\n");
		*PCAPTimeScale = 1000;
		break;
	case PCAPHEADER_MAGIC_NANO:
		fprintf(stderr, "Nano PCAP\n");
		*PCAPTimeScale = 1;
		break;
	default:
		fprintf(stderr, "invalid pcap header %08x\n", Header->Magic);
		return NULL;
	}

	F->ReadPos +=  sizeof(PCAPHeader_t);

	// allocate read buffer
	F->ReadBufferMax	= 1024*1024;
	F->ReadBufferPos	= 0; 
	F->ReadBuffer 		= malloc( F->ReadBufferMax );

	return F;
}

static inline PCAPPacket_t* PCAP_Read(PCAPFile_t* PCAP)
{
	int ret;
	PCAPPacket_t* Pkt = (PCAPPacket_t*)PCAP->PacketBuffer[PCAP->PacketPut];
	PCAP->PacketPut = (PCAP->PacketPut + 1) & PCAP->PacketMsk; 

	ret = fread(Pkt, 1, sizeof(PCAPPacket_t), PCAP->F);

	if (ret != sizeof(PCAPPacket_t))
	{
		fprintf(stderr, "header invalid: %i expect %lu\n", ret, sizeof(PCAPPacket_t));
		return NULL;
	}

	if (PCAP->ReadPos + sizeof(PCAPPacket_t) + Pkt->LengthCapture > PCAP->Length)
	{
		fprintf(
			stderr,
			"offset : %llu expect %llu\n",
			PCAP->ReadPos + sizeof(PCAPPacket_t) + Pkt->LengthCapture, PCAP->Length
		);

		fprintf(
			stderr,
			"read %llu LenCap: %i Length %llu\n",
			PCAP->ReadPos, Pkt->LengthCapture, PCAP->Length
		);

		return NULL; 
	}

	ret = fread(Pkt + 1, 1, Pkt->LengthCapture, PCAP->F);

	if (ret != Pkt->LengthCapture)
	{
		fprintf(stderr, "length %i expect %i\n",  ret, Pkt->LengthCapture);
		return NULL;
	}

	PCAP->ReadPos += Pkt->LengthCapture;
	return Pkt;
}

static inline u64 PCAP_TimeStamp(PCAPPacket_t* Pkt, u64 TimeScale, u64 TimeZoneOffs)
{
	return TimeZoneOffs + Pkt->Sec * k1E9 + Pkt->NSec * TimeScale;
}

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
			fprintf(stderr, "Will pin thread to CPU %i.\n", CPU);
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
			(u32)0, 				// assume port 0 
			(u32)0, 				// packet flag
			Pkt + 1);

		PCAPFile->TS = TS;
	}

	return 0;
}

