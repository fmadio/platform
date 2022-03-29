//---------------------------------------------------------------------------------------------
//
// Copyright (c) 2021, fmad engineering llc
//
// The MIT License (MIT) see LICENSE file for details
//
//---------------------------------------------------------------------------------------------

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <math.h>
#include <string.h>
#include <sys/time.h>

#include "fTypes.h"
#include "ITCH.h"

u32 t_scale = 1;
u8 is_reverse_endian = 0;
u64 g_total_gap_count = 0;
u64 g_total_ooo_count = 0;

bool g_MetamakoFooter = false;
bool g_VLANFound = false;

u64 g_LastOutputTime = 0;
// How often (in nanoseconds) we should drop current gap state and output gap/ooo counts
u64 output_sample_time = 60 * S_TO_NS;

// How often (in seconds) to output the stats index (msgs/s)
double stat_sample_time = 1;

ITCHState_t *ITCHStateList = NULL;

// converts a deciable to char
static inline u8 Num2Char(u32 Value)
{
	switch (Value)
	{
	case 0x0: return '0';
	case 0x1: return '1';
	case 0x2: return '2';
	case 0x3: return '3';
	case 0x4: return '4';
	case 0x5: return '5';
	case 0x6: return '6';
	case 0x7: return '7';
	case 0x8: return '8';
	case 0x9: return '9';
	}
	return ' ';
}
// write a nicely formated timestamp (FormatTS but without libc)
static inline u8* WriteTSFormat(u8* Output, double timestamp)
{
	// timestamp is in sec, convert to ts in nsec
	u64 ts = timestamp * 1e9;

	u64 usec	= ts   / 1000ULL;
	u64 msec	= usec / 1000ULL;
	u64 sec		= msec / 1000ULL;
	u64 min		= sec  / 60ULL;
	u64 hour	= min  / 60ULL;

	u64 nsec	= ts   - usec*1000ULL;
	usec		= usec - msec*1000ULL;
	msec		= msec - sec*1000ULL;
	sec			= sec  - min*60ULL;
	min			= min  - hour*60ULL;


	// clip hour to 24 as it contains the full epoch in hours
	hour		= hour % 24;

	*Output++	= Num2Char( hour / 10);
	*Output++	= Num2Char( hour % 10);
	*Output++	= ':';

	*Output++	= Num2Char( min / 10);
	*Output++	= Num2Char( min % 10);
	*Output++	= ':';

	*Output++	= Num2Char( sec / 10);
	*Output++	= Num2Char( sec % 10);
	*Output++	= '.';

	*Output++	= Num2Char( msec / 100);
	*Output++	= Num2Char((msec / 10)%10);
	*Output++	= Num2Char( msec % 10 );
	*Output++	= '.';


	*Output++	= Num2Char( usec / 100);
	*Output++	= Num2Char((usec / 10)%10);
	*Output++	= Num2Char( usec % 10 );
	*Output++	= '.';

	*Output++	= Num2Char( nsec / 100);
	*Output++	= Num2Char((nsec / 10)%10);
	*Output++	= Num2Char( nsec % 10 );

	*Output++	= 0;
}

ITCHState_t* get_itch_state(IP4Header_t *IP4, UDPHeader_t *UDP, MoldUDP64_t *mold, u16 vlan_id)
{
	// Find entry if it already exists
	ITCHState_t *state = ITCHStateList;
	// TODO: Use Hash to speed up finding the state?
	while (state != NULL)
	{
		if (state->SrcPort == UDP->PortSrc && state->DstPort == UDP->PortDst &&
			state->SrcIP.IP4 == IP4->Src.IP4 && state->DstIP.IP4 == IP4->Dst.IP4 &&

			state->Session[0] == mold->Session[0] &&
			state->Session[1] == mold->Session[1] &&
			state->Session[2] == mold->Session[2] &&
			state->Session[3] == mold->Session[3] &&
			state->Session[4] == mold->Session[4] &&
			state->Session[5] == mold->Session[5] &&
			state->Session[6] == mold->Session[6] &&
			state->Session[7] == mold->Session[7] &&
			state->Session[8] == mold->Session[8] &&
			state->Session[9] == mold->Session[9] &&
			state->VLAN == vlan_id
			)
		{
			// Found an existing record
			break;
		}
		state = state->Next;
	}

	if (state == NULL)
	{
		// Create new record since no match was found
		ITCHState_t *new_state = malloc(sizeof(ITCHState_t));

		/*
		fprintf(stderr, "[dbg] New state  session=%x.%x.%x.%x.%x.%x.%x.%x.%x.%x src=%u.%u.%u.%u:%u dst=%u.%u.%u.%u:%u seq=%llu\n",
				mold->Session[0], mold->Session[1], mold->Session[2], mold->Session[3], mold->Session[4], mold->Session[5], mold->Session[6], mold->Session[7], mold->Session[8], mold->Session[9],

				IP4->Src.IP[0], IP4->Src.IP[1], IP4->Src.IP[2], IP4->Src.IP[3], swap16(UDP->PortSrc),
				IP4->Dst.IP[0], IP4->Dst.IP[1], IP4->Dst.IP[2], IP4->Dst.IP[3], swap16(UDP->PortDst),
				swap64(mold->SeqNo)
			);
		*/

		new_state->SrcPort = UDP->PortSrc;
		new_state->DstPort = UDP->PortDst;

		new_state->SrcIP.IP4 = IP4->Src.IP4;
		new_state->DstIP.IP4 = IP4->Dst.IP4;

		new_state->Session[0] = mold->Session[0];
		new_state->Session[1] = mold->Session[1];
		new_state->Session[2] = mold->Session[2];
		new_state->Session[3] = mold->Session[3];
		new_state->Session[4] = mold->Session[4];
		new_state->Session[5] = mold->Session[5];
		new_state->Session[6] = mold->Session[6];
		new_state->Session[7] = mold->Session[7];
		new_state->Session[8] = mold->Session[8];
		new_state->Session[9] = mold->Session[9];

		new_state->VLAN = vlan_id;

		new_state->SeqStart = swap64(mold->SeqNo);
		new_state->SeqCurrent = swap64(mold->SeqNo);

		new_state->Next = ITCHStateList;
		ITCHStateList = new_state;

		state = new_state;
	}
	return state;
}

void output_stats(ITCHState_t *state, double timestamp)
{
	u8 TStr[128];
	WriteTSFormat(TStr, timestamp);

	fprintf(stdout, "{ \"_index\": \"stats\", \"srcIP\": \"%u.%u.%u.%u\", \"dstIP\": \"%u.%u.%u.%u\", \"srcPort\": %u, \"dstPort\": %u, \"session\":\"%c%c%c%c%c%c%c%c%c%c\", \"timestamp\": \"%lf\", \"TS\": \"%s\" \"messageCount\": %llu, \"gapCount\": %llu",
			state->SrcIP.IP[0], state->SrcIP.IP[1], state->SrcIP.IP[2], state->SrcIP.IP[3],
			state->DstIP.IP[0], state->DstIP.IP[1], state->DstIP.IP[2], state->DstIP.IP[3],
			swap16(state->SrcPort), swap16(state->DstPort),
			state->Session[0], state->Session[1], state->Session[2], state->Session[3], state->Session[4], state->Session[5], state->Session[6], state->Session[7], state->Session[8], state->Session[9],
			timestamp, TStr, state->MessageCount, state->SeqGapCount
		);
	if (g_VLANFound)
	{
		fprintf(stdout, ", \"vlan_id\": %u", state->VLAN);
	}
	fprintf(stdout, " }\n");
	state->TS = timestamp;
}

void output_itch_events(IP4Header_t *IP4, UDPHeader_t *UDP, MoldUDP64_t *mold_udp, double timestamp, u8 *payload, u16 vlan_id)
{
	u32 offset = 0;
	u16 msg_cnt = swap16(mold_udp->MsgCnt);

	u8 TStr[128];
	WriteTSFormat(TStr, timestamp);

	u8* event_str = "";
	if (msg_cnt == 0xffff)
	{
		event_str = "EndSession";
		fprintf(stdout, "{ \"_index\": \"events\", \"srcIP\": \"%u.%u.%u.%u\", \"dstIP\": \"%u.%u.%u.%u\", \"srcPort\": %u, \"dstPort\": %u, \"session\":\"%c%c%c%c%c%c%c%c%c%c\", \"timestamp\": \"%lf\", \"TS\": \"%s\", \"event\": \"%s\"",
				IP4->Src.IP[0], IP4->Src.IP[1], IP4->Src.IP[2], IP4->Src.IP[3],
				IP4->Dst.IP[0], IP4->Dst.IP[1], IP4->Dst.IP[2], IP4->Dst.IP[3],
				swap16(UDP->PortSrc), swap16(UDP->PortDst),
				mold_udp->Session[0], mold_udp->Session[1], mold_udp->Session[2], mold_udp->Session[3], mold_udp->Session[4], mold_udp->Session[5], mold_udp->Session[6], mold_udp->Session[7], mold_udp->Session[8], mold_udp->Session[9],
				timestamp, TStr, event_str
			);
		if (g_VLANFound)
		{
			fprintf(stdout, ", \"vlan_id\": %u", vlan_id);
		}
		fprintf(stdout, " }\n");

		return;
	}

	for (u16 i = 0; i < msg_cnt; i++)
	{
		u16 msg_length = swap16(*((u16*) (payload + offset)));
		char *msg_type = (payload + offset + 2);
		assert(msg_length > 0 && msg_length < UDP_MAX_PKTLEN);

		if (msg_type[0] == 'S')
		{
			fITCH_System_t* msg = (fITCH_System_t*) msg_type;
			switch (msg->Event)
			{
			case 'O': event_str = "StartMessages"; break;
			case 'S': event_str = "StartSystemHours"; break;
			case 'Q': event_str = "StartMarketHours"; break;
			case 'M': event_str = "EndMarketHours"; break;
			case 'E': event_str = "EndSystemHours"; break;
			case 'C': event_str = "EndMessages"; break;
			}

			//fprintf(stderr, "[dbg] ITCH System Event %s\n", event_str);


			fprintf(stdout, "{ \"_index\": \"events\", \"srcIP\": \"%u.%u.%u.%u\", \"dstIP\": \"%u.%u.%u.%u\", \"srcPort\": %u, \"dstPort\": %u, \"session\":\"%c%c%c%c%c%c%c%c%c%c\", \"timestamp\": \"%lf\", \"TS\": \"%s\", \"event\": \"%s\" }\n",
					IP4->Src.IP[0], IP4->Src.IP[1], IP4->Src.IP[2], IP4->Src.IP[3],
					IP4->Dst.IP[0], IP4->Dst.IP[1], IP4->Dst.IP[2], IP4->Dst.IP[3],
					swap16(UDP->PortSrc), swap16(UDP->PortDst),
					mold_udp->Session[0], mold_udp->Session[1], mold_udp->Session[2], mold_udp->Session[3], mold_udp->Session[4], mold_udp->Session[5], mold_udp->Session[6], mold_udp->Session[7], mold_udp->Session[8], mold_udp->Session[9],
					timestamp, TStr, event_str
				);
		}
		offset += msg_length + 2;
	}
}

void process_mold_udp(IP4Header_t *IP4, UDPHeader_t *UDP, MoldUDP64_t *mold, double timestamp, u16 vlan_id)
{
	ITCHState_t *state = get_itch_state(IP4, UDP, mold, vlan_id);
	u64 SeqNo = swap64(mold->SeqNo);
	u16 MessageCount = swap16(mold->MsgCnt);

	state->MessageCount += MessageCount;

	if (timestamp - state->TS >= stat_sample_time)
	{
		output_stats(state, timestamp);
	}

	if (state->SeqCurrent + 1 == SeqNo)
	{
		// Seq number in order as expected, return early
		state->SeqCurrent += MessageCount;
		return;
	}
	else if (state->SeqCurrent == SeqNo)
	{
		// Heartbeat/dupe message so don't increment expected Seq
		return;
	}
	else if (SeqNo < state->SeqStart)
	{
		// TODO: Here SeqNo comes after SeqStart, but has the earlier timestamp?
		if (state->SeqStart - SeqNo > 1)
		{
			// Edge-case for when the first seq no. we saw was out of order, so we
			// add a gap for it and let the OOO counter handle it if it arrives
			state->SeqStart = SeqNo;
			GapRange_t *new_gap = malloc(sizeof(GapRange_t));
			new_gap->Start = SeqNo;
			new_gap->End = state->SeqStart;
			// In this case the timestamp is of the gap->Start seq no. (unlike
			// all the other cases - hopefully that's not an issue)
			new_gap->TS = timestamp;
			new_gap->Next = state->GapRanges;
			state->GapRanges = new_gap;
		}
		else
		{
			state->SeqOOOCount++;
			g_total_ooo_count++;
		}
	}
	else if (SeqNo < state->SeqCurrent)
	{
		state->SeqOOOCount++;
		g_total_ooo_count++;

/*
		fprintf(stderr, "[ooo] ooo src=%u.%u.%u.%u:%u dst=%u.%u.%u.%u:%u seq=%llu\n",
				IP4->Src.IP[0], IP4->Src.IP[1], IP4->Src.IP[2], IP4->Src.IP[3], swap16(UDP->PortSrc),
				IP4->Dst.IP[0], IP4->Dst.IP[1], IP4->Dst.IP[2], IP4->Dst.IP[3], swap16(UDP->PortDst),
				SeqNo
			);
*/

		// Out of order sequence number detected
		// We should have an existing GapRange where this seq no. fits in so we
		// need to find the GapRange and update it

		// Find Gap
		GapRange_t *gap = state->GapRanges;
		while (gap != NULL)
		{
			if (gap->Start < SeqNo && gap->End > SeqNo)
			{
				break;
			}
			gap = gap->Next;
		}
		if (gap == NULL)
		{
			/*
			fprintf(stderr, "[err] OOO packet but gap not found!\nsession=%c%c%c%c%c%c%c%c%c%c src=%u.%u.%u.%u:%u dst=%u.%u.%u.%u:%u seq=%llu last_seq=%llu msg_cnt=%u\n",
					mold->Session[0], mold->Session[1], mold->Session[2], mold->Session[3], mold->Session[4], mold->Session[5], mold->Session[6], mold->Session[7], mold->Session[8], mold->Session[9],

					IP4->Src.IP[0], IP4->Src.IP[1], IP4->Src.IP[2], IP4->Src.IP[3], swap16(UDP->PortSrc),
					IP4->Dst.IP[0], IP4->Dst.IP[1], IP4->Dst.IP[2], IP4->Dst.IP[3], swap16(UDP->PortDst),

					SeqNo, state->SeqCurrent, swap16(mold->MsgCnt));

			{
				GapRange_t *gap = state->GapRanges;
				fprintf(stderr, "[err] Gap list:\n");
				while (gap != NULL)
				{
					fprintf(stderr, "\t[err] gap from=%llu to=%llu\n", gap->Start, gap->End);
					if (gap->Start < SeqNo && gap->End > SeqNo)
					{
						break;
					}
					gap = gap->Next;
				}
			}
			*/

			// May happen if:
			// 1. We just reset the gaps and then an OOO packet came in - we
			// won't know for sure if the gap has been detected/output/reset already
			// or
			// 2. Duplicated message comes in out of order (so 1,2,3,2 - we
			// won't have a gap since it's a dupe AND OOO)
			return;
		}

		// Update gap
		if (gap->Start + 1 == SeqNo)
		{
			gap->Start++;
		}
		else if (gap->End - 1 == SeqNo)
		{
			gap->End++;
		}
		// remove gap if it's been filled
		if (gap->Start + 1 == gap->End)
		{
			state->GapRanges = state->GapRanges->Next;
			free(gap);
		}

		if (SeqNo > gap->Start + 1 && SeqNo < gap->End - 1)
		{
			// Confirm that the gap is wide enough for us to split up
			assert(gap->End - gap->Start > 1);

			GapRange_t *new_gap = malloc(sizeof(GapRange_t));
			new_gap->Start = SeqNo;
			new_gap->End = gap->End;
			// new_gap->TS is already the TS the gap->End seq no. had, so leave
			// it that way
			new_gap->Next = gap;

			// Split into 2 gaps
			gap->End = SeqNo;
			gap->TS = timestamp;

			state->GapRanges = new_gap;
		}
	}
	else
	{
		// Gap detected (since seq no. is higher than we expected), so add a
		// GapRange to the list

		GapRange_t *new_gap = malloc(sizeof(GapRange_t));
		new_gap->Start = state->SeqCurrent;
		new_gap->End = SeqNo;
		new_gap->TS = timestamp;

		// Insert gap at head
		GapRange_t *old_head = state->GapRanges;
		new_gap->Next = old_head;
		state->GapRanges = new_gap;

/*
  fprintf(stderr, "[dbg] Gap detected src=%u.%u.%u.%u:%u dst=%u.%u.%u.%u:%u seq=%llu last_seq=%llu\n",
				IP4->Src.IP[0], IP4->Src.IP[1], IP4->Src.IP[2], IP4->Src.IP[3], swap16(UDP->PortSrc),
				IP4->Dst.IP[0], IP4->Dst.IP[1], IP4->Dst.IP[2], IP4->Dst.IP[3], swap16(UDP->PortDst),
				SeqNo, state->SeqCurrent
			);
*/
		u64 gap_count = new_gap->End - new_gap->Start - 1;
		state->SeqGapCount += gap_count;

		// Now that we've added the gap, we expect the next sequence to continue
		// from here
		state->SeqCurrent = SeqNo;
	}
}

void output_and_reset_gaps()
{
	ITCHState_t *state = ITCHStateList;
	ITCHState_t *old_state = state;
	if (state == NULL)
	{
		// fprintf(stderr, "No gaps detected\n");
	}
	while (state != NULL)
	{

/*
		fprintf(stderr, "\n[gap] src=%u.%u.%u.%u:%u dst=%u.%u.%u.%u:%u\n\tooo=%llu gaps=%llu\n",
				state->SrcIP.IP[0], state->SrcIP.IP[1], state->SrcIP.IP[2], state->SrcIP.IP[3], swap16(state->SrcPort),
				state->DstIP.IP[0], state->DstIP.IP[1], state->DstIP.IP[2], state->DstIP.IP[3], swap16(state->DstPort),
				state->SeqOOOCount, state->SeqGapCount
			);
*/

		u64 gap_count = 0;
		GapRange_t *gap = state->GapRanges;
		GapRange_t *old_gap = gap;
		while (gap != NULL)
		{
			// fprintf(stderr, "\t[gap] gap range from %llu to %llu dist=%llu\n", gap->Start, gap->End, gap->End - gap->Start);

			assert(gap->End > gap->Start);
			gap_count = gap->End - gap->Start - 1;

			u8 TStr[128];
			WriteTSFormat(TStr, gap->TS);

			fprintf(stdout, "{ \"_index\": \"gaps\", \"srcIP\": \"%u.%u.%u.%u\", \"dstIP\": \"%u.%u.%u.%u\", \"srcPort\": %u, \"dstPort\": %u, \"session\": \"%c%c%c%c%c%c%c%c%c%c\", \"oooCount\": %llu, \"gapSeqStart\": %llu, \"gapSeqEnd\": %llu, \"gapCount\": %llu, \"timestamp\": \"%lf\", \"TS\": \"%s\"",
					state->SrcIP.IP[0], state->SrcIP.IP[1], state->SrcIP.IP[2], state->SrcIP.IP[3],
					state->DstIP.IP[0], state->DstIP.IP[1], state->DstIP.IP[2], state->DstIP.IP[3],
					swap16(state->SrcPort), swap16(state->DstPort),
					state->Session[0], state->Session[1], state->Session[2], state->Session[3], state->Session[4], state->Session[5], state->Session[6], state->Session[7], state->Session[8], state->Session[9],
					state->SeqOOOCount, gap->Start, gap->End, gap_count,
					gap->TS, TStr
				);
			if (g_VLANFound)
			{
				fprintf(stdout, ", \"vlan_id\": %u", state->VLAN);
			}
			fprintf(stdout, " }\n");
			g_total_gap_count += gap_count;

			old_gap = gap;
			gap = gap->Next;

			free(old_gap);
		}
		// Reset all recorded gaps
		state->GapRanges = NULL;
		state->SeqOOOCount = 0;

		old_state = state;
		state = state->Next;
	}
	g_LastOutputTime = clock_ns();
}

void free_itch_state_list()
{

	ITCHState_t *state = ITCHStateList;
	ITCHState_t *old_state = state;
	while (state != NULL)
	{
		old_state = state;
		state = state->Next;
		free(old_state);
	}
}

u8 process_pcap_payload(u8 *payload, u32 len, double timestamp)
{
	fEther_t *ether = (fEther_t*) payload;
	u16 etherProto = swap16(ether->Proto);
	/*
	  fprintf(stderr, "ether src=%x:%x:%x:%x:%x:%x dst=%x:%x:%x:%x:%x:%x end=%d proto=%x\n",

			ether->Src[0], ether->Src[1], ether->Src[2], ether->Src[3], ether->Src[4], ether->Src[5],
			ether->Dst[0], ether->Dst[1], ether->Dst[2], ether->Dst[3], ether->Dst[4], ether->Dst[5],

			is_reverse_endian, etherProto);
	*/

	if (etherProto != ETHER_PROTO_IP && etherProto != ETHER_PROTO_IPV4 && etherProto != ETHER_PROTO_VLAN)
	{
		return 0;
	}

	u8 *ip_payload = (u8*) (ether + 1);
	u16 vlan_id = 0;
	if (etherProto == ETHER_PROTO_VLAN)
	{
		g_VLANFound = true;
		VLANTag_t* vlan = (VLANTag_t*) (ether + 1);
		vlan_id = VLANTag_ID(vlan);
		// IP header is now after VLAN tag and ether proto (2 bytes)
		ip_payload = (u8*) vlan + sizeof(VLANTag_t) + 2;
	}

	IP4Header_t* IP4 = (IP4Header_t*) (ip_payload);
	u32 IPOffset = (IP4->Version & 0x0f)*4;

	/*
	  fprintf(stderr, "ip len=%u proto=%u src=%u.%u.%u.%u dst=%u.%u.%u.%u\n",
			swap16(IP4->Len), IP4->Proto,
			IP4->Src.IP[0], IP4->Src.IP[1], IP4->Src.IP[2], IP4->Src.IP[3],
			IP4->Dst.IP[0], IP4->Dst.IP[1], IP4->Dst.IP[2], IP4->Dst.IP[3]);
	*/
	if (IP4->Proto != IPv4_PROTO_UDP)
	{
		return 0;
	}

	UDPHeader_t* UDP = (UDPHeader_t*) ((u8*)IP4 + IPOffset);
	/*
	fprintf(stderr, "udp src=%u dst=%u len=%u\n", swap16(UDP->PortSrc), swap16(UDP->PortDst),
			swap16(UDP->Length));
	 */


	MoldUDP64_t *mold_udp = (MoldUDP64_t*) (UDP + 1);
//	fprintf(stderr, "p=%p len=%x ip=%p udp=%p mold=%p end=%p mold_end=%p\n", payload, len, IP4, UDP, mold_udp, payload + len, ((u8*) &mold_udp->MsgCnt) + 2);
	if (swap16(mold_udp->MsgCnt) > 0)
	{
/*
		fprintf(stderr, "mold payload ");

	fprintf(stderr, "session=%x.%x.%x.%x.%x.%x.%x.%x.%x.%x src=%u.%u.%u.%u:%u dst=%u.%u.%u.%u:%u seq=%llu msg_cnt=%u\n",
			mold_udp->Session[0], mold_udp->Session[1], mold_udp->Session[2], mold_udp->Session[3], mold_udp->Session[4], mold_udp->Session[5], mold_udp->Session[6], mold_udp->Session[7], mold_udp->Session[8], mold_udp->Session[9],

			IP4->Src.IP[0], IP4->Src.IP[1], IP4->Src.IP[2], IP4->Src.IP[3], swap16(UDP->PortSrc),
			IP4->Dst.IP[0], IP4->Dst.IP[1], IP4->Dst.IP[2], IP4->Dst.IP[3], swap16(UDP->PortDst),

			swap64(mold_udp->SeqNo), swap16(mold_udp->MsgCnt));
/*
*/
	}

	process_mold_udp(IP4, UDP, mold_udp, timestamp, vlan_id);
	u8 *itch_payload = (u8*) (mold_udp + 1);
	output_itch_events(IP4, UDP, mold_udp, timestamp, itch_payload, vlan_id);

	return 1;
}

void print_help()
{
	fprintf(stderr,
			"Outputs JSON line by line on market data gap detection stats\n"
			"Usage: cat itch.pcap | ./itch-gaps [options] > output.json\n"
			"\t--output-sample-time <time in seconds>\n"
			"\t--stat-sample-time <time in seconds>\n"
			"\t--metamako | use packet timestamp from Metamako footer\n"
			"\n"
		);
}

int main(int argc, char* argv[])
{
	for (int i = 0; i < argc; i++)
	{
		// fprintf(stderr, "[dbg] arg = %s\n", argv[i]);
		if (strcmp(argv[i], "--output-sample-time") == 0)
		{
			output_sample_time = strtod(argv[i+1], NULL) * S_TO_NS;
			fprintf(stderr, "[dbg] Output sample time = %lf seconds\n", output_sample_time/S_TO_NS);
			i++;
		}
		else if (strcmp(argv[i], "--stat-sample-time") == 0)
		{
			stat_sample_time = strtod(argv[i+1], NULL);
			fprintf(stderr, "[dbg] Stat sample time = %lf seconds\n", stat_sample_time);
			i++;
		}
		else if (strcmp(argv[i], "--metamako") == 0)
		{
			g_MetamakoFooter = true;
			fprintf(stderr, "[dbg] Using timestamp from Metamako footer\n");
		}
		else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0)
		{
			print_help();
			return 0;
		}
	}

	FILE *input_file = stdin;

	// read header
	PCAPHeader_t file_header;
	int rlen = fread(&file_header, 1, sizeof(file_header), input_file);
	if (rlen != sizeof(file_header))
	{
		fprintf(stderr, "Failed to read pcap header\n");
		return -1;
	}
	u32 magic = file_header.magic;

	// TODO: Confirm reverse endian detection works
	if (magic == PCAPHEADER_MAGIC_USEC)
	{
		t_scale = 1000;
		is_reverse_endian = 0;
	}
	else if (magic == swap32(PCAPHEADER_MAGIC_USEC))
	{
		t_scale = 1000;
		is_reverse_endian = 1;
	}
	else if (magic == PCAPHEADER_MAGIC_NANO)
	{
		t_scale = 1;
		is_reverse_endian = 0;
	}
	else if (magic == swap32(PCAPHEADER_MAGIC_NANO))
	{
		t_scale = 1;
		is_reverse_endian = 1;
	}
	else
	{
		fprintf(stderr, "Invalid PCAP format %08x\n", file_header.magic);
		return -1;
	}

	if (is_reverse_endian) fprintf(stderr, "Reverse endian PCAP\n");

	// max packet size of 64K
	u8 *payload = malloc(UDP_MAX_PKTLEN);

	// Read every PCAP packet and process MoldUDP seq numbers
	u32 cnt = 0;
	u32 processed_cnt = 0;
	while (!feof(input_file))
	{

		PCAPPacket_t pcap_pkt = { 0 };

		// Read PCAP packet header
		int rlen = fread(&pcap_pkt, 1, sizeof(PCAPPacket_t), input_file);
		if (rlen != sizeof(PCAPPacket_t)) break;

		if (is_reverse_endian)
		{
			pcap_pkt.sec = swap32(pcap_pkt.sec);
			pcap_pkt.nsec = swap32(pcap_pkt.nsec);
			pcap_pkt.length_capture = swap32(pcap_pkt.length_capture);
			pcap_pkt.length_wire = swap32(pcap_pkt.length_wire);
		}

		// validate packet size
		if (pcap_pkt.length_capture == 0 || pcap_pkt.length_capture > UDP_MAX_PKTLEN)
		{
			fprintf(stderr, "Invalid packet length: %i\n", pcap_pkt.length_capture);
			break;
		}

		// Read payload
		rlen = fread(payload, 1, pcap_pkt.length_capture, input_file);
		if (rlen != pcap_pkt.length_capture)
		{
			fprintf(stderr, "payload read fail %i expect %i\n", rlen, pcap_pkt.length_capture);
			break;
		}

		double timestamp = pcap_pkt.sec + ((double) pcap_pkt.nsec / (1e9 / t_scale));
		if (g_MetamakoFooter)
		{
			MetaMakoFooter_t* Footer = (MetaMakoFooter_t*) (payload + pcap_pkt.length_capture - sizeof(MetaMakoFooter_t));
			double mTS = ((u64)swap32(Footer->Sec)*1000000000ULL + (u64)swap32(Footer->NSec)) / 1e9;

			// fprintf(stderr, "[dbg] TS=%lf mTS=%lf dT=%lf\n", timestamp, mTS, mTS-timestamp);

			timestamp = mTS;
		}

		processed_cnt += process_pcap_payload(payload, pcap_pkt.length_capture, timestamp);

		//if (cnt % 1000 == 0) fprintf(stderr, "Processed %u packets\n", cnt);
		if (clock_ns() > g_LastOutputTime + output_sample_time)
		{
			// fprintf(stderr, "Printing gaps %llu\n", g_LastOutputTime);
			output_and_reset_gaps();
		}

		cnt++;
	}

	free(payload);

	output_and_reset_gaps();
	free_itch_state_list();

	fprintf(stderr, "Total gaps=%llu ooo=%llu\n", g_total_gap_count, g_total_ooo_count);
	fprintf(stderr, "Processed %u/%u PCAP packets\n", processed_cnt, cnt);

	return 0;
}
