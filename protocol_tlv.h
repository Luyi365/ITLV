#ifndef __PROTOCOL_TLV_H__
#define __PROTOCOL_TLV_H__

#ifdef __cplusplus
extern "C"
{
#endif

// typedef char           int8_t;
typedef unsigned char  uint8_t;
typedef short          int16_t;
typedef unsigned short uint16_t;
typedef int            int32_t;
typedef unsigned int   uint32_t;

// 协议头
#define PROTOCOL_HEAD	          0x55AA  // 协议头

// 各协议字段长度
#define PROTOCOL_HEAD_LEN         2       // 协议头长度，固定2字节
#define PROTOCOL_ID_LEN           1       // ID长度，固定1字节
#define PROTOCOL_TYPE_LEN         1       // Type长度，固定1字节
#define PROTOCOL_LENGTH_LEN       1       // Length长度，固定1字节
#define PROTOCOL_VALUE_MAX_LEN    256     // Value最大长度，256字节
#define PROTOCOL_CRC_LEN          2       // CRC校验值长度，固定2字节
#define PROTOCOL_MAX_LEN          (2 + 1 + 1 + 1 + 256 + 2)   // 该协议最大数据长度
#define PROTOCOL_MIN_LEN          (2 + 1 + 1 + 1 + 2)         // 该协议最小数据长度

// 协议数组索引
#define PROTOCOL_ID_INDEX         2
#define PROTOCOL_TYPE_INDEX       3
#define PROTOCOL_LENGTH_INDEX     4

// TLV 数据类型type
typedef enum _tlv_type
{
    TLV_TYPE_UINT8,
    TLV_TYPE_INT8,
    TLV_TYPE_UINT16,
    TLV_TYPE_INT16,
    TLV_TYPE_UINT32,
    TLV_TYPE_INT32,
    TLV_TYPE_STRING,
    TLV_TYPE_FLOAT,
    TLV_TYPE_BYTE_ARR,   // 字节数组
}tlv_type_e;

#pragma pack(1) 
// 协议格式
typedef struct _protocol_format
{
    uint16_t head;    
    uint8_t id;
    uint8_t type;
    uint8_t length;
    uint8_t value[];
}protocol_format_t;

// 控制命令
typedef enum _ctrl_cmd
{
    CTRL_CMD_LED_ON,
    CTRL_CMD_LED_OFF
}ctrl_cmd_e;

typedef struct _protocol_data_ctrl_cmd
{
    ctrl_cmd_e cmd;
}protocol_data_ctrl_cmd_t;

// 时间数据
typedef struct _protocol_data_time
{
    int year;
    int mon;
    int mday;
    int hour;
    int min;
    int sec;
}protocol_data_time_t;

// 工作状态
typedef enum _work_status
{
    WORK_STATUS_NORMAL,
    WORK_STATUS_ERROR
}work_status_e;

typedef struct _protocol_data_work_status
{
    work_status_e status;
}protocol_data_work_status_t;

// 数据ID
typedef enum _protocol_id
{
    // A板发往B板
    PROTOCOL_ID_A_TO_B_BASE = 0x00,
    PROTOCOL_ID_A_TO_B_CTRL_CMD,
    PROTOCOL_ID_A_TO_B_DATE_TIME,
    PROTOCOL_ID_A_TO_B_END = 0x7F,

    // B板发往A板
    PROTOCOL_ID_B_TO_A_BASE = 0x80,
    PROTOCOL_ID_B_TO_A_WORK_STATUS,
    PROTOCOL_ID_B_TO_A_END = 0xFF,
}protocol_id_e;

// A板发往B板的数据value值
typedef union _protocol_value_a_to_b
{
    protocol_data_ctrl_cmd_t ctrl_cmd;
    protocol_data_time_t     date_time;
}protocol_value_a_to_b_t;

// B板发往A板的数据value值
typedef union _protocol_value_b_to_a
{
    protocol_data_work_status_t work_status;
}protocol_value_b_to_a_t;

// 所有协议数据value值
typedef union _protocol_value
{
    protocol_value_a_to_b_t a_to_b_value;
    protocol_value_b_to_a_t b_to_a_value;
}protocol_value_t;

// 总的协议数据
typedef struct _protocol_data
{
    protocol_id_e id;
    protocol_value_t value;
}protocol_data_t;
#pragma pack() 

// 组包、解包函数
int protocol_data_packet(uint8_t *buf, uint16_t len, protocol_data_t *protocol_data);
void protocol_data_parse(protocol_data_t *protocol_data, uint8_t *buf, uint16_t len);
void print_hex_data_frame(uint8_t *pbuf, int buf_len);
uint16_t crc16_x25_check(uint8_t* data, uint32_t length);

#ifdef __cplusplus
}
#endif

#endif /*__PROTOCOL_TLV_H__*/
