//------------------------------------------------------------------------------------------------------------------
//
// Copyright (c) 2021-2022, fmad engineering group 
//
// LICENSE: refer to https://github.com/fmadio/platform/blob/main/LICENSE.md
//
//-------------------------------------------------------------------------------------------------------------------

#ifndef  __FMADIO_PACKET_H__
#define  __FMADIO_PACKET_H__

//---------------------------------------------------------------------------------------------

#ifndef __F_TYPES_H__

#ifndef __cplusplus

typedef unsigned char		bool;
#define false				0
#define true				1

#endif

typedef unsigned char		u8;
typedef char				s8;

typedef unsigned short		u16;
typedef short				s16;

typedef unsigned int 		u32;
typedef int					s32;

typedef unsigned long long	u64;
typedef long long			s64;


//---------------------------------------------------------------------------------------------

static inline volatile u64 rdtsc(void)
{
	u32 hi, lo;
	__asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi) );
	return (((u64)hi)<<32ULL) | (u64)lo;
}


static inline void sfence(void)
{
	__asm__ volatile("sfence");
}

static inline void mfence(void)
{
	__asm__ volatile("mfence");
}

static inline void lfence(void)
{
	__asm__ volatile("lfence");
}

// not great but dont need to calibrate or have any external dependencies
static inline u64 ns2tsc(u64 ns)
{
	return ns * 2;		// assume a 2Ghz cpu
}
static inline u64 tsc2ns(u64 tsc)
{
	return tsc / 2;		// assume a 2Ghz cpu
}


static void ndelay(u64 ns)
{
	u64 NextTS = rdtsc() + ns2tsc(ns);
	while (rdtsc() < NextTS)
	{
		__asm__ volatile("pause");
		__asm__ volatile("pause");
		__asm__ volatile("pause");
		__asm__ volatile("pause");
	}
}

#endif

//---------------------------------------------------------------------------------------------

#define FMADRING_VERSION		0x00000100			// ring version 
#define FMADRING_MAPSIZE		(16*1024*1024)		// total size of the map file. deliberately larger than the structure size
#define FMADRING_ENTRYSIZE		(10*1024)			// total size header and payload of each packet 
#define FMADRING_ENTRYCNT		(1*1024)			// number of entries in the ring 

#define FMADRING_FLAG_EOF		(1<<0)				// end of file exit
#define FMADRING_FLAG_FCSERR	(1<<1)				// packet has an FCS error 

typedef struct fFMADRingPacket_t
{
	u64				TS;								// 64b nanosecond epoch	
	u16				LengthWire;						// packet length on the wire
	u16				LengthCapture;					// packet length capture 
	
	u8				Port;							// capture port 
	u8				Flag;							// various flags
	u8				pad1;
	u8				pad2;

	u64				StorageID;						// Storage ID

	u8				Payload[FMADRING_ENTRYSIZE];	// payload ensure each entry is 10KB

	u8				padAlign[2024];					// keep it 4KB page aligned	

} __attribute__((packed)) fFMADRingPacket_t;

typedef struct fFMADRingHeader_t
{
	u32				Version;						// FMADRing version
	u32				Size;							// size of entire structure 
	u32				SizePacket;						// size of a packet 

	u8				Path[128];						// path of ring
		
	u64				Depth;							// depth of the ring 
	u64				Mask;							// counter mask 

	u32				IsTxFlowControl;				// tx has flow control enabled 
	u64				TxTimeout;						// tx maximum timeout to wait

	u64				PendingB;						// number of bytes pending (on the Put side)

	u8				align0[4096-4*4-4*8-128];		// keep header/put/get all on seperate 4K pages

	//--------------------------------------------------------------------------------	
	
	volatile s64	Put;							// write pointer (not maseked)
	volatile u64	PutByte;						// total number of bytes 
	volatile u64	PutPktTS;						// pcap timestamp of last put packet 
	u8				align1[4096-3*8];				// keep header/put/get all on seperate 4K pages

	//--------------------------------------------------------------------------------	

	volatile s64	Get;							// read pointer	(not maseked)
	volatile u64	GetByte;						// read total bytes 
	volatile u64	GetPktTS;						// pcap tiemstamp of last read packet 
	u8				align2[4096-3*8];				// keep header/put/get all on seperate 4K pages

	fFMADRingPacket_t	Packet[FMADRING_ENTRYCNT];	// actual ring size does not need to be that deep

} __attribute__((packed)) fFMADRingHeader_t;

//---------------------------------------------------------------------------------------------
// open fmad packet ring for tx 
static inline int FMADPacket_OpenTx(	int* 				pfd, 
										fFMADRingHeader_t** pRing, 
										bool 				IsReset, 
										u8* 				Path,
										bool				IsFlowControl,
										u64					TimeoutNS
){
	//check ring file size is correct
	struct stat s;
	memset(&s, 0, sizeof(s));
	stat(Path, &s);

	//including if no file created 
	if (s.st_size != sizeof(fFMADRingHeader_t))
	{
		fprintf(stderr, "RING[%-50s] Size missmatch %lli %lli\n", Path, (u64)s.st_size, (u64)sizeof(fFMADRingHeader_t) );

		int fd = open64(Path,  O_RDWR | O_CREAT, 0666);	
		if (fd < 0)
		{
			fprintf(stderr, "RING[%-50s] failed to create new ring  errno:%i %s\n", Path, errno, strerror(errno)); 
		}
		assert(fd > 0);

		ftruncate(fd, sizeof(fFMADRingHeader_t)); 
		close(fd);
	}

	// open
	int fd  = open64(Path,  O_RDWR, S_IRWXU | S_IRWXG | 0777);	
	if (fd < 0)
	{
		fprintf(stderr, "RING[%-50s] failed to create FMADRing file errno:%i %s\n",  Path, errno, strerror(errno));
		return -1;
	}

	// map it
	u8* Map = mmap64(0, FMADRING_MAPSIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (Map == (u8*)-1)
	{
		fprintf(stderr, "RING[%-50s]failed to map RING\n", Path);
		return -1;	
	}

	fFMADRingHeader_t* RING = (fFMADRingHeader_t*)Map;

	// check version
	fprintf(stderr, "RING[%-50s] Size   : %li %i\n", Path, sizeof(fFMADRingHeader_t), FMADRING_MAPSIZE);
	fprintf(stderr, "RING[%-50s] Version: %8x %8x\n", Path, RING->Version, FMADRING_VERSION); 

	// version wrong then force reset
	if (RING->Version != FMADRING_VERSION)
	{
		fprintf(stderr, "RING[%-50s] version wrong force reset\n", Path);
		IsReset = true;
	}

	//reset ring
	if (IsReset)
	{
		memset(RING, 0, sizeof(fFMADRingHeader_t)); 

		RING->Size			= sizeof(fFMADRingHeader_t);		
		RING->SizePacket	= sizeof(fFMADRingPacket_t);		

		RING->Depth			= FMADRING_ENTRYCNT;
		RING->Mask			= FMADRING_ENTRYCNT - 1;

		RING->Put			= 0;
		RING->Get			= 0;

		sfence();	

		// set version last as sential the ring has been setup
		RING->Version		= FMADRING_VERSION;		

		// copy path for debug 
		strncpy(RING->Path, Path, sizeof(RING->Path));

		// fixed settings
		RING->IsTxFlowControl	= IsFlowControl;	
		RING->TxTimeout			= TimeoutNS;	
	}

	// check everything matches 
	assert(RING->Size 		== sizeof(fFMADRingHeader_t)); 
	assert(RING->SizePacket	== sizeof(fFMADRingPacket_t)); 
	assert(RING->Depth 		== FMADRING_ENTRYCNT); 
	assert(RING->Mask		== FMADRING_ENTRYCNT - 1); 

	fprintf(stderr, "RING[%-50s] Put:%llx %llx %p\n", RING->Path, RING->Put, RING->Put & RING->Mask, &RING->Put);
	fprintf(stderr, "RING[%-50s] Get:%llx %llx %p\n", RING->Path, RING->Get, RING->Get & RING->Mask, &RING->Get);


	// update files
	if (pfd) 	pfd[0] 		= fd;
	if (pRing) 	pRing[0] 	= RING;

	return 0;
}

//---------------------------------------------------------------------------------------------
// open fmad packet ring for rx 
static inline int FMADPacket_OpenRx(	int* 				pfd, 
										fFMADRingHeader_t** pRing, 
										bool 				IsWait, 
										u8* 				Path
){
	int fd = 0;	

	fd  = open64(Path,  O_RDWR, S_IRWXU | S_IRWXG | 0777);	
	if (fd < 0)
	{
		fprintf(stderr, "RING[%-50s] failed to create FMADRing file errno:%i %s\n",  Path, errno, strerror(errno));
		return -1;
	}

	// map it
	u8* Map = mmap64(0, FMADRING_MAPSIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (Map == (u8*)-1)
	{
		fprintf(stderr, "RING[%-50s] failed to map RING\n", Path);
		return -1;	
	}

	fFMADRingHeader_t* RING = (fFMADRingHeader_t*)Map;

	// check version
	fprintf(stderr, "RING[%-50s] Size   : %li %i %i\n", Path, sizeof(fFMADRingHeader_t), RING->Size, FMADRING_MAPSIZE);
	fprintf(stderr, "RING[%-50s] Version: %8x %8x\n", Path, RING->Version, FMADRING_VERSION); 

	// version wrong then force reset
	if (RING->Version != FMADRING_VERSION)
	{
		fprintf(stderr, "RING[%-50s] version wrong\n", Path);
		assert(false);
	}

	// check everything matches 
	assert(RING->Size 		== sizeof(fFMADRingHeader_t)); 
	assert(RING->SizePacket	== sizeof(fFMADRingPacket_t)); 
	assert(RING->Depth 		== FMADRING_ENTRYCNT); 
	assert(RING->Mask		== FMADRING_ENTRYCNT - 1); 

	//reset get point to current write pointer 
	RING->Get = RING->Put;

	fprintf(stderr, "RING[%-50s] Path:%s", Path, RING->Path);
	fprintf(stderr, "RING[%-50s] Put:%llx %llx\n", Path, RING->Put, RING->Put & RING->Mask);
	fprintf(stderr, "RING[%-50s] Get:%llx %llx\n", Path, RING->Get, RING->Get & RING->Mask);

	// update files
	if (pfd) 	pfd[0] 		= fd;
	if (pRing) 	pRing[0] 	= RING;

	return 0;
}

//---------------------------------------------------------------------------------------------
// open fmad packet ring for monitoring only (read only) 
static inline int FMADPacket_OpenMon(	int* 				pfd, 
										fFMADRingHeader_t** pRing, 
										u8* 				Path
){
	int fd = 0;	

	fd  = open64(Path,  O_RDONLY, S_IRWXU | S_IRWXG | 0777);	
	if (fd < 0)
	{
		fprintf(stderr, "RING[%-50s] ERROR failed to open FMADRing file errno:%i %s\n",  Path, errno, strerror(errno));
		return -1;
	}

	// map it
	u8* Map = mmap64(0, FMADRING_MAPSIZE, PROT_READ, MAP_SHARED, fd, 0);
	if (Map == (u8*)-1)
	{
		fprintf(stderr, "RING[%-50s] ERROR failed to map RING (read only)\n", Path);
		return -1;	
	}

	fFMADRingHeader_t* RING = (fFMADRingHeader_t*)Map;

	// version wrong then force reset
	if (RING->Version != FMADRING_VERSION)
	{
		fprintf(stderr, "RING[%-50s] ERROR version wrong\n", Path);
		return -1;
	}

	// check everything matches 
	assert(RING->Size 		== sizeof(fFMADRingHeader_t)); 
	assert(RING->SizePacket	== sizeof(fFMADRingPacket_t)); 
	assert(RING->Depth 		== FMADRING_ENTRYCNT); 
	assert(RING->Mask		== FMADRING_ENTRYCNT - 1); 

	fprintf(stderr, "RING[%-50s] Status GOOD\n", Path);

	// update files
	if (pfd) 	pfd[0] 		= fd;
	if (pRing) 	pRing[0] 	= RING;

	return 0;
}


//---------------------------------------------------------------------------------------------
// write packet 
static inline int FMADPacket_SendV1(	fFMADRingHeader_t* 	RING, 
										u64 				TS, 
										u32 				LengthWire,
										u32 				LengthCapture,
										u32 				Port,
										u32					Flag,
										u64					StorageID,
										void*	 			Payload
									)
{
	// wait for space 
	u64 TS0 = rdtsc();
	while (RING->IsTxFlowControl)
	{
		s64 dQueue = RING->Put - RING->Get;
		if (dQueue < RING->Depth-1) break; 

		usleep(0);

		u64 dTSC = (rdtsc() - TS0);
		if (tsc2ns(dTSC) > RING->TxTimeout)
		{
			fprintf(stderr, "RING[%-50s] ERROR RING wait for drain timeout %lli > %lli\n", RING->Path, tsc2ns(dTSC), RING->TxTimeout);
			return -1;
		}
	}

	// write packet
	fFMADRingPacket_t* FPkt = &RING->Packet[ RING->Put & RING->Mask ];
	FPkt->TS				= TS;
	FPkt->LengthWire		= LengthWire;
	FPkt->LengthCapture		= LengthCapture;
	FPkt->Port				= 0; 
	FPkt->Flag				= Flag; 
	FPkt->StorageID			= StorageID; 
	memcpy(&FPkt->Payload[0], Payload, LengthCapture);

	sfence();

	// publish 
	RING->Put 				+= 1;
	RING->PutByte 			+= LengthCapture;
	RING->PutPktTS 			= TS;

	return LengthCapture;
}


//---------------------------------------------------------------------------------------------
// send EOF marker 
static inline int FMADPacket_SendEOFV1(	fFMADRingHeader_t* 	RING, u64 TS)
{
	// wait for space 
	u64 TS0 = rdtsc();
	while (RING->IsTxFlowControl)
	{
		s64 dQueue = RING->Put - RING->Get;
		if (dQueue < RING->Depth-1) break; 

		usleep(0);

		u64 dTSC = (rdtsc() - TS0);
		if (tsc2ns(dTSC) > RING->TxTimeout)
		{
			fprintf(stderr, "RING[%-50s] ERROR: RING wait for drain timeout EOF %lli %lli\n", RING->Path, tsc2ns(dTSC), RING->TxTimeout);
			return -1;
		}
	}

	// write packet
	fFMADRingPacket_t* FPkt = &RING->Packet[ RING->Put & RING->Mask ];
	FPkt->TS				= TS;
	FPkt->LengthWire		= 0;
	FPkt->LengthCapture		= 0;
	FPkt->Port				= 0; 
	FPkt->Flag				= FMADRING_FLAG_EOF; 

	sfence();

	// publish 
	RING->Put 				+= 1;
	RING->PutPktTS			= TS;

	return 0; 
}

//---------------------------------------------------------------------------------------------
// get a packet non-zero copy way but simple interface 
static inline int FMADPacket_RecvV1a(	fFMADRingHeader_t* RING, 
										bool IsWait,
										u64*		pTS,	
										u32*		pLengthWire,	
										u32*		pLengthCapture,	
										u32*		pPort,	
										u32*		pFlag,	
										u64*		pStorageID,	
										void*		Payload	
										) 
{
	fFMADRingPacket_t* Pkt = NULL;
	do 
	{
		if (RING->Put != RING->Get)
		{
			if (RING->Put < RING->Get) break;

			Pkt = &RING->Packet[ RING->Get & RING->Mask ]; 
			break;
		}
		//usleep(0);
		ndelay(100);

	} while (IsWait);

	if (!Pkt)
	{
		//ndelay(100);
		return 0;
	}

	// data stream finished
	if (Pkt->Flag & FMADRING_FLAG_EOF)
	{
		return -1;
	}

	// make copy of relevant data
	if (pTS) 			pTS[0] 				= Pkt->TS;
	if (pLengthWire) 	pLengthWire[0] 		= Pkt->LengthWire;
	if (pLengthCapture) pLengthCapture[0] 	= Pkt->LengthCapture;
	if (pPort)			pPort[0]			= Pkt->Port;
	if (pFlag)			pFlag[0]			= Pkt->Flag;
	if (pStorageID)		pStorageID[0]		= Pkt->StorageID;
	if (Payload)		memcpy(Payload, Pkt->Payload, Pkt->LengthCapture);

	//sfence();

	// next
	RING->Get 		+= 1;
	RING->GetByte 	+= Pkt->LengthCapture;
	RING->GetPktTS	= Pkt->TS; 

	return Pkt->LengthCapture;
}

// backwards compat
static inline int FMADPacket_RecvV1(	fFMADRingHeader_t* RING, 
										bool 		IsWait,
										u64*		pTS,	
										u32*		pLengthWire,	
										u32*		pLengthCapture,	
										u32*		pPort,	
										u32*		pFlag,	
										void*		Payload	
									) 
{

	return FMADPacket_RecvV1a(RING, IsWait, pTS, pLengthWire, pLengthCapture, pPort, pFlag, NULL, Payload);
}


//---------------------------------------------------------------------------------------------
// set/get the pending bytes 
static inline void FMADPacket_PendingByteSet(	fFMADRingHeader_t* RING, u64 PendingB)
{
	RING->PendingB = PendingB;
}
static inline u64 FMADPacket_PendingByteGet(	fFMADRingHeader_t* RING)
{
	return RING->PendingB;
}

//---------------------------------------------------------------------------------------------
// get total byte counts
static inline u64 FMADPacket_TotaBytePut( fFMADRingHeader_t* RING)
{
	return RING->PutByte;
}
static inline u64 FMADPacket_TotaByteGet( fFMADRingHeader_t* RING)
{
	return RING->GetByte;
}

//---------------------------------------------------------------------------------------------
// get timestamp of last Put and Get packet 
static inline u64 FMADPacket_PktTSPut( fFMADRingHeader_t* RING)
{
	return RING->PutPktTS;
}
static inline u64 FMADPacket_PktTSGet( fFMADRingHeader_t* RING)
{
	return RING->GetPktTS;
}

//---------------------------------------------------------------------------------------------
// common pcap fields 

// pcap headers
#define PCAPHEADER_MAGIC_NANO       0xa1b23c4d
#define PCAPHEADER_MAGIC_USEC       0xa1b2c3d4
#define PCAPHEADER_MAGIC_FMAD       0x1337bab3      // chunked FMAD packets
#define PCAPHEADER_MAGIC_FMADRING   0x1337bab7      // shm ring buffer interface
#define PCAPHEADER_MAJOR            2
#define PCAPHEADER_MINOR            4
#define PCAPHEADER_LINK_ETHERNET    1
#define PCAPHEADER_LINK_ERF         197

typedef struct
{
    u32             Magic;
    u16             Major;
    u16             Minor;
    u32             TimeZone;
    u32             SigFlag;
    u32             SnapLen;
    u32             Link;

} __attribute__((packed)) PCAPHeader_t;

typedef struct PCAPPacket_t
{
    u32             Sec;                    // time stamp sec since epoch
    u32             NSec;                   // nsec fraction since epoch

    u32             LengthCapture;          // captured length, inc trailing / aligned data
    u32             LengthWire;             // [14:0]  length on the wire
                                            // [15]    port number
                                            // [31:16] reserved

} __attribute__((packed)) PCAPPacket_t;

//---------------------------------------------------------------------------------------------

#endif

// vim:sw=4:ts=4

