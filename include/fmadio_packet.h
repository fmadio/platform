//------------------------------------------------------------------------------------------------------------------
//
// Copyright (c) 2021-2022, fmad engineering group 
//
// PRIVATE AND CONFIDENTIAL DO NOT DISTRIBUTE
//
//-------------------------------------------------------------------------------------------------------------------

#ifndef  __FMADIO_PACKET_H__
#define  __FMADIO_PACKET_H__

//---------------------------------------------------------------------------------------------

#define FMADRING_VERSION		0x00000100			// ring version 
#define FMADRING_MAPSIZE		(16*1024*1024)		// total size of the map file. deliberately larger than the structure size
#define FMADRING_ENTRYSIZE		(10*1024)			// total size header and payload of each packet 
#define FMADRING_ENTRYCNT		(1024)				// number of entries in the ring 

#define FMADRING_FLAG_EOF			(1<<0)			// end of file exit

typedef struct
{
	u64				TS;								// 64b nanosecond epoch	
	u16				LengthWire;						// packet length on the wire
	u16				LengthCapture;					// packet length capture 
	
	u8				Port;							// capture port 
	u8				Flag;							// various flags
	u8				pad1;
	u8				pad2;

	u32				pad3;
	u32				pad4;

	u8				Payload[FMADRING_ENTRYSIZE-32];	// payload ensure each entry is 10KB

} __attribute__((packed)) fFMADRingPacket_t;

typedef struct
{
	u32				Version;						// FMADRing version
	u32				Size;							// size of entire structure 
	u32				SizePacket;						// size of a packet 
		
	u64				Depth;							// depth of the ring 
	u64				Mask;							// counter mask 

	u32				IsTxFlowControl;				// tx has flow control enabled 
	u64				TxTimeout;						// tx maximum timeout to wait

	u8				align0[4096-3*4-2*8];			// keep header/put/get all on seperate 4K pages

	//--------------------------------------------------------------------------------	
	
	volatile s64	Put;							// write pointer (not maseked)
	u8				align1[4096-1*8];				// keep header/put/get all on seperate 4K pages

	//--------------------------------------------------------------------------------	

	volatile s64	Get;							// read pointer	(not maseked)
	u8				align2[4096-1*8];				// keep header/put/get all on seperate 4K pages

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
	int fd  = open64(Path,  O_RDWR, S_IRWXU | S_IRWXG | 0777);	
	if (fd < 0)
	{
		fprintf(stderr, "failed to create FMADRing file [%s] errno:%i %s\n",  Path, errno, strerror(errno));
		return -1;
	}

	// map it
	u8* Map = mmap64(0, FMADRING_MAPSIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (Map == (u8*)-1)
	{
		fprintf(stderr, "failed to map RING [%s]\n", Path);
		return -1;	
	}

	fFMADRingHeader_t* RING = (fFMADRingHeader_t*)Map;

	// check version
	fprintf(stderr, "Ring size   : %i %i\n", sizeof(fFMADRingHeader_t), FMADRING_MAPSIZE);
	fprintf(stderr, "Ring Version: %8x %8x\n", RING->Version, FMADRING_VERSION); 

	// version wrong then force reset
	if (RING->Version != FMADRING_VERSION)
	{
		fprintf(stderr, "RING version wrong force reset\n");
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
	}

	// check everything matches 
	assert(RING->Size 		== sizeof(fFMADRingHeader_t)); 
	assert(RING->SizePacket	== sizeof(fFMADRingPacket_t)); 
	assert(RING->Depth 		== FMADRING_ENTRYCNT); 
	assert(RING->Mask		== FMADRING_ENTRYCNT - 1); 

	fprintf(stderr, "RING: Put:%llx\n", RING->Put, RING->Put & RING->Mask);
	fprintf(stderr, "RING: Get:%llx\n", RING->Get, RING->Get & RING->Mask);

	// settings
	RING->IsTxFlowControl	= IsFlowControl;	
	RING->TxTimeout			= TimeoutNS;	

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
		fprintf(stderr, "failed to create FMADRing file [%s] errno:%i %s\n",  Path, errno, strerror(errno));
		return -1;
	}

	// map it
	u8* Map = mmap64(0, FMADRING_MAPSIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (Map == (u8*)-1)
	{
		fprintf(stderr, "failed to map RING [%s]\n", Path);
		return -1;	
	}

	fFMADRingHeader_t* RING = (fFMADRingHeader_t*)Map;

	// check version
	fprintf(stderr, "Ring size   : %i %i %i\n", sizeof(fFMADRingHeader_t), RING->Size, FMADRING_MAPSIZE);
	fprintf(stderr, "Ring Version: %8x %8x\n", RING->Version, FMADRING_VERSION); 

	// version wrong then force reset
	if (RING->Version != FMADRING_VERSION)
	{
		fprintf(stderr, "RING version wrong\n");
		assert(false);
	}

	// check everything matches 
	assert(RING->Size 		== sizeof(fFMADRingHeader_t)); 
	assert(RING->SizePacket	== sizeof(fFMADRingPacket_t)); 
	assert(RING->Depth 		== FMADRING_ENTRYCNT); 
	assert(RING->Mask		== FMADRING_ENTRYCNT - 1); 

	//reset get point to current write pointer 
	RING->Get = RING->Put;

	fprintf(stderr, "RING: Put:%llx\n", RING->Put, RING->Put & RING->Mask);
	fprintf(stderr, "RING: Get:%llx\n", RING->Get, RING->Get & RING->Mask);

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

		u64 dT= tsc2ns(rdtsc() - TS0);
		if (dT > RING->TxTimeout)
		{
			fprintf(stderr, "ERROR: RING wait for drain timeout\n");
			return -1;
		}
	}

	// write packet
	fFMADRingPacket_t* FPkt = &RING->Packet[ RING->Put & RING->Mask ];
	FPkt->TS				= TS;
	FPkt->LengthWire		= LengthWire;
	FPkt->LengthCapture		= LengthCapture;
	FPkt->Port				= 0; 
	memcpy(&FPkt->Payload[0], Payload, LengthCapture);

	// publish 
	RING->Put 				+= 1;

	return LengthCapture;
}

//---------------------------------------------------------------------------------------------
// get a packet non-zero copy way but simple interface 
static inline int FMADPacket_RecvV1(	fFMADRingHeader_t* RING, 
											bool IsWait,
											u64*		pTS,	
											u32*		pLengthWire,	
											u32*		pLengthCapture,	
											u32*		pPort,	
											void*		Payload	
										) 
{
	fFMADRingPacket_t* Pkt = NULL;
	do 
	{
		if (RING->Put != RING->Get)
		{
			if (RING->Put< RING->Get) break;

			Pkt = &RING->Packet[ RING->Get & RING->Mask ]; 
			break;
		}
		//usleep(0);
		ndelay(100);

	} while (IsWait);

	if (!Pkt) return 0;

	// make copy of relevant data
	if (pTS) 			pTS[0] 				= Pkt->TS;
	if (pLengthWire) 	pLengthWire[0] 		= Pkt->LengthWire;
	if (pLengthCapture) pLengthCapture[0] 	= Pkt->LengthCapture;
	if (pPort)			pPort[0]			= Pkt->Port;
	if (Payload)		memcpy(Payload, Pkt->Payload, Pkt->LengthCapture);


	// next
	RING->Get += 1;

	return Pkt->LengthCapture;
}

// consume the packet 
static inline void FMADPacket_RecvV1_Complete(	fFMADRingHeader_t* 	RING)
{
}



#endif

// vim:sw=4:ts=4

