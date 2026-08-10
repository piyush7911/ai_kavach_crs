#ifndef RTOS_TYPES_H
#define RTOS_TYPES_H

#include <stdint.h>
#include <stdlib.h>

typedef uint32_t rtos_status_t;
typedef uint16_t rtos_channel_id_t;

#define RTOS_MAX_CHANNEL_BUF 128
#define RTOS_HEADER_MAGIC 0x4b415641

#define MACRO_HDR_LEN 16
#define EXPAND_BUF(x) ((uint32_t)((x) * sizeof(uint32_t)))
#define CALC_ALLOC_SZ(x) (MACRO_HDR_LEN + EXPAND_BUF(x))

typedef struct {
    uint32_t flags : 4;
    uint32_t reserved : 4;
    uint32_t payload_len : 24;
} __attribute__((packed)) BitfieldHeader;

typedef struct {
    uint32_t magic;
    BitfieldHeader header_spec;
    uint8_t buffer[RTOS_MAX_CHANNEL_BUF];
} ChannelPacket;

typedef struct {
    ChannelPacket *active_pkt;
    rtos_channel_id_t id;
    int is_active;
} SessionHandle;

#endif
