#ifndef __FMAD_ITCH_H__
#define __FMAD_ITCH_H__


// http://www.nasdaqtrader.com/content/technicalsupport/specifications/dataproducts/moldudp64.pdf
typedef struct
{
    u8		Session[10];
    u64		SeqNo;
    u16		MsgCnt;

} __attribute__((packed)) MoldUDP64_t;

typedef struct
{
    u8		MsgType;
    u32		NS;
    u8		Group[4];
    u8		Event;

} __attribute__((packed)) fITCH_System_t;

#endif
