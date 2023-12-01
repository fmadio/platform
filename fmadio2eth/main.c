//--------------------------------------------------------------------------------------------------
// (c) 2023, FMAD Engineering Pty. Ltd. 
//
// LICENSE: refer to https://github.com/fmadio/platform/blob/main/LICENSE.md
//
// Emits captured packets from an FMAD ring buffer to a Linux network interface.
//--------------------------------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sched.h>
#include <string.h>
#include <poll.h>

#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>

#include "include/fmadio_packet.h"

#define CLOSE_SOCK \
	if (close(Socket) < 0) \
	{ \
		fprintf(stderr, "Error during socket close: %s\n", strerror(errno)); \
		return EXIT_SOCKETCLOSE; \
	}

enum {		
	EXIT_UNKNOWNARG = EXIT_FAILURE + 64,
	EXIT_MISSINGARG,
	EXIT_FMADRING,
	EXIT_OPEN,
	EXIT_PACKETLEN,
	EXIT_PACKETVERS,
	EXIT_IFINDEX,
	EXIT_BIND,
	EXIT_TXRING,
	EXIT_MTU,
	EXIT_MMAP,
	EXIT_POLL,
	EXIT_SOCKETCLOSE,
};

typedef struct {
	struct iovec* RD;
	u8 *Map;
	struct tpacket_req Req;
} TRing_t;

typedef struct {
	u64 ReceivedPkt, ReceivedByte;
	u64 SentPkt, SentByte;
	u64 FailedPkt, FailedByte;
	u64 TruncatedPkt, TruncatedByte;
} Stats_t;

volatile sig_atomic_t s_Exit = false;

static void SignalHandler(int Sig)
{
	if (s_Exit && (Sig == SIGTERM || Sig == SIGINT))
		exit(EXIT_SUCCESS);

	fflush(stderr);
	s_Exit = true;
}

static void PrintHelp(void)
{
	fprintf(stderr,
			"fmadio2eth [options]\n"
			"\n"
			"Emits captured packets from an FMAD ring buffer to a network interface\n"
			"\n"
			"Options:\n"
			"		-i <path to FMAD ring file> (required)\n"
			"		-e <interface name> (required)\n"
			"		--cpu <integer> : pin the process to the specified CPU core\n"
			"		--no-sleep : use `ndelay` for a high-frequency loop\n");
}

static void PrintStats(Stats_t* Stats)
{
	fprintf(stderr, "\nByte counts are in capture length (not wire length) where applicable.\n");

	fprintf(stderr, "Received: %lli packets (%lliB)\n",
			Stats->ReceivedPkt, Stats->ReceivedByte);
	fprintf(stderr, "Sent: %lli packets (%lliB)\n",
			Stats->SentPkt, Stats->SentByte);
	fprintf(stderr, "Failed to send: %lli packets (%lliB)\n",
			Stats->FailedPkt, Stats->FailedByte);
	fprintf(stderr, "Truncated: %lli packets (%lliB lost in total)\n",
			Stats->TruncatedPkt, Stats->TruncatedByte);
}

int main(int argc, char* argv[])
{
	int CPU = -1;
	u8* RingPath = NULL;
	u8* IFace = NULL;
	bool NoSleep = false;

	for (int i = 1; i < argc; ++i)
	{
		if (strcmp(argv[i], "-i") == 0)
		{
			if ((i + 1) >= argc)
			{
				fprintf(stderr,
						"argument `-i` expects a following file path argument.\n");

				return EXIT_MISSINGARG;
			}

			RingPath = argv[i + 1];
			i += 1;
		}
		else if (strcmp(argv[i], "-e") == 0)
		{
			if ((i + 1) >= argc)
			{
				fprintf(stderr,
						"argument `-e` expects a following string argument.\n");

				return EXIT_MISSINGARG;
			}

			IFace = argv[i + 1];
			i += 1;
		}
		else if (strcmp(argv[i], "--cpu") == 0)
		{
			if ((i + 1) >= argc)
			{
				fprintf(stderr,
						"argument `--cpu` expects a following integer argument.\n");
				return EXIT_MISSINGARG;
			}

			CPU = atoi(argv[i + 1]);
			fprintf(stderr, "Will pin thread to CPU %i.\n", CPU);
			i += 1;
		}
		else if (strcmp(argv[i], "--no-sleep") == 0)
		{
			NoSleep = true;
		}
		else if (strcmp(argv[i], "--help") == 0)
		{
			PrintHelp();
			return EXIT_SUCCESS;
		}
		else
		{
			fprintf(stderr, "Unrecognized argument: %s\n", argv[i]);
			fprintf(stderr, "Use `--help` for a list of parameters\n");
			return EXIT_UNKNOWNARG;
		}
	}

	// signal handlers
	signal(SIGINT,  SignalHandler);
	signal(SIGHUP,  SignalHandler);
	signal(SIGPIPE, SignalHandler);

	if (CPU != -1)
	{
		cpu_set_t mask;
		CPU_ZERO(&mask);
		CPU_SET(CPU, &mask);
		sched_setaffinity(0, sizeof(mask), &mask);
	}

	if (RingPath == NULL)
	{
		fprintf(stderr, "Specify ring buffer with `-i <path to ring file>`\n");
		return EXIT_MISSINGARG;
	}

	if (IFace == NULL)
	{
		fprintf(stderr, "Specify an interface with `-e <interface name>`\n");
		return EXIT_MISSINGARG;
	}

	int RingFD = -1;
	fFMADRingHeader_t* Ring = NULL;

	if (FMADPacket_OpenRx(&RingFD, &Ring, true, RingPath) < 0)
	{
		fprintf(stderr, "Failed to open FMAD ring: `%s`\n", RingPath);	
		return EXIT_FMADRING;
	}

	int Socket = socket(PF_PACKET, SOCK_RAW, 0);

	if (Socket < 0)
	{
		fprintf(stderr, "Failed to open socket: %s\n", strerror(errno));
		return EXIT_OPEN;
	}

	{
		int V = TPACKET_V2;
		int Err = setsockopt(Socket, SOL_PACKET, PACKET_VERSION, &V, sizeof(V));

		if (Err < 0)
		{
			fprintf(stderr, "Failed to set TPACKET_V2: %s\n", strerror(errno));
			return EXIT_PACKETVERS;
		}
	}

	struct ifreq IFR;
	strcpy(IFR.ifr_name, IFace);

	if (ioctl(Socket, SIOCGIFINDEX, &IFR))
	{
		fprintf(stderr, "Failed to retrieve index for interface named: `%s`\n", IFace);
		return EXIT_IFINDEX;
	}

	struct sockaddr_ll LL;
	memset(&LL, 0, sizeof(LL));
	LL.sll_family = AF_PACKET;
	LL.sll_protocol = 0;
	LL.sll_ifindex = IFR.ifr_ifindex;
	LL.sll_hatype = 0;
	LL.sll_pkttype = 0;
	LL.sll_halen = ETH_ALEN;
	memset(&LL.sll_addr, 0xff, ETH_ALEN);

	{
		int Err = bind(Socket, (struct sockaddr*) &LL, sizeof(LL));

		if (Err < 0)
		{
			fprintf(stderr, "Failed to bind socket: %s\n", strerror(errno));
			return EXIT_BIND;
		}
	}

	TRing_t TRing;
	memset(&TRing, 0, sizeof(TRing_t));

	static const unsigned int RING_FRAME_COUNT = 64;

	TRing.Req.tp_block_size = RING_FRAME_COUNT * getpagesize();
	TRing.Req.tp_block_nr = 1;
	TRing.Req.tp_frame_size = getpagesize();
	TRing.Req.tp_frame_nr = RING_FRAME_COUNT;

	{
		int Result = setsockopt(Socket,
								SOL_PACKET,
								PACKET_TX_RING,
								(void*)&TRing.Req,
								sizeof(TRing.Req));

		if (Result < 0)
		{
			fprintf(stderr, "Failed to set up TX ring: %s (%i)\n", strerror(errno), errno);
			return EXIT_TXRING;
		}
	}

	TRing.Map = mmap(NULL,
					 TRing.Req.tp_block_size * TRing.Req.tp_block_nr,
					 PROT_READ | PROT_WRITE,
					 MAP_SHARED | MAP_LOCKED,
					 Socket,
					 0);

	if (TRing.Map == MAP_FAILED)
	{
		fprintf(stderr, "Failed to memory-map TX ring: %s\n", strerror(errno));
		return EXIT_MMAP;
	}

	size_t MTU;

	{
		char* CmdBuf = (char*)malloc(64 + strlen(IFace));
		sprintf(CmdBuf, "ifconfig %s | sed -n 's/.*mtu \\([0-9]\\+\\).*/\\1/p'", IFace);
		FILE* Pipe = popen(CmdBuf, "r");

		if (Pipe == NULL)
		{
			fprintf(stderr, "Failed to get MTU of interface: `%s` (%s)\n", IFace, strerror(errno));
			return EXIT_MTU;
		}

		char Output[5];

		fgets(Output, sizeof(Output), Pipe);
		MTU = (size_t)atoll(Output);
		pclose(Pipe);
		fprintf(stderr, "Packets will be truncated to MTU: %luB\n", MTU);
	}

	TRing.RD = malloc(TRing.Req.tp_block_nr * sizeof(*TRing.RD));
	assert(TRing.RD);

	for (int i = 0; i < TRing.Req.tp_block_nr; ++i)
	{
		TRing.RD[i].iov_base = TRing.Map + (i * TRing.Req.tp_block_size);
		TRing.RD[i].iov_len = TRing.Req.tp_block_size;
	}

	ssize_t RingOffs = 0;
	u64 WaitingPkt = 0, WaitingByte = 0;

	u32 PktBufferMax = 128 * 1024;
	u8* PktBuffer = malloc(PktBufferMax);
	memset(PktBuffer, 0, PktBufferMax);

	Stats_t Stats = {0};
	fprintf(stderr, "Ring receive loop starting...\n");

	while (!s_Exit)
	{		
		u64 TS;
		PCAPPacket_t* Pkt	= (PCAPPacket_t*)PktBuffer;

		// fetch packet from ring without blocking
		int Result = FMADPacket_RecvV1(Ring,
									   false,
									   &TS,
									   &Pkt->LengthWire, &Pkt->LengthCapture,
									   NULL, Pkt + 1);

		if (Result > 0)
		{
			Stats.ReceivedPkt += 1;
			Stats.ReceivedByte += Result;

			// sanitize it
			assert(Pkt->LengthCapture > 0);	
			assert(Pkt->LengthCapture < (16 * 1024));

			Pkt->Sec = TS / (u64)1e9;
			Pkt->NSec = TS % (u64)1e9;

			size_t Len = sizeof(PCAPPacket_t) + Pkt->LengthCapture;

			if (Len > MTU)
			{
				Stats.TruncatedPkt += 1;
				Stats.TruncatedByte += (Len - MTU);
				Len = MTU;
			}

			struct tpacket2_hdr* Header = (void*)TRing.Map + (RingOffs * TRing.Req.tp_frame_size);
			assert((((unsigned long)Header) & (getpagesize() - 1)) == 0);

			// wait for previous packet to complete sending
			struct pollfd Pollset;
			while (Header->tp_status != TP_STATUS_AVAILABLE)
			{
				Pollset.fd = Socket;
				Pollset.events = POLLOUT;
				Pollset.revents = 0;

				int P = poll(&Pollset, 1, 1000);

				if (P < 0)
				{
					if (errno != EINTR)
					{
						fprintf(stderr, "TX ring poll failed: %s\n", strerror(errno));
						PrintStats(&Stats);
						CLOSE_SOCK
						return EXIT_POLL;
					}

					fprintf(stderr, "TX ring polling interrupted.\n");
					PrintStats(&Stats);
					CLOSE_SOCK
					return EXIT_SUCCESS;
				}
			}

			// where to write data to
			u8* Dest = (u8*)Header + sizeof(struct tpacket2_hdr);
			u8* Src  = (u8*)(Pkt + 1);
			memcpy(Dest, Src, Len);

			// tell tpacket about it 
			Header->tp_sec		= Pkt->Sec;
			Header->tp_nsec 	= Pkt->NSec;
			Header->tp_len 		= Len;
			Header->tp_status	= TP_STATUS_SEND_REQUEST;

			RingOffs = (RingOffs + 1) & (RING_FRAME_COUNT - 1);
			WaitingPkt += 1;
			WaitingByte += Result;

			if (WaitingPkt == RING_FRAME_COUNT)
			{
				int R = send(Socket, NULL, 0, 0);

				if (R == -1)
				{
					fprintf(stderr, "Failed to send packets: %s\n", strerror(errno));
					Stats.FailedPkt += WaitingPkt;
					Stats.FailedByte += Result;
					WaitingPkt = 0;
					WaitingByte = 0;
					continue;
				}

				Stats.SentPkt += WaitingPkt;
				Stats.SentByte += R;
				WaitingPkt = 0;
				WaitingByte = 0;
			}
		}
		else if (Result < 0)
		{
			// End of stream
			break;
		}
		// request is nonblocking, run less hot, use usleep(0) to reduce CPU usage more 
		else
		{
			if (WaitingPkt > 0)
			{
				int R = send(Socket, NULL, 0, 0);

				if (R == -1)
				{
					fprintf(stderr, "Failed to send packets: %s\n", strerror(errno));
					Stats.FailedPkt += WaitingPkt;
					Stats.FailedPkt += WaitingByte;
				}
				else
				{
					Stats.SentPkt += WaitingPkt;
					Stats.SentByte += R;
				}

				WaitingPkt = 0;
				WaitingByte = 0;
			}

			if (NoSleep)
			{
				ndelay(100);
			}
			else
			{
				usleep(0);
			}
		}
	}

	{
		int R = send(Socket, NULL, 0, 0);

		if (R == -1)
		{
			fprintf(stderr, "Failed to send packets: %s\n", strerror(errno));
			Stats.FailedPkt += WaitingPkt;
			Stats.FailedPkt += WaitingByte;
		}
		else
		{
			Stats.SentPkt += WaitingPkt;
			Stats.SentByte += R;
		}
	}

	fflush(stdout);
	PrintStats(&Stats);
	CLOSE_SOCK
	return EXIT_SUCCESS;
}

