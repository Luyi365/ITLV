#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "protocol_tlv.h"

static const unsigned short crc16_table[256] = 
{
    0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
    0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
    0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
    0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
    0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
    0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
    0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
    0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
    0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
    0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
    0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
    0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
    0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
    0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
    0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
    0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
    0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
    0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
    0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
    0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
    0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
    0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
    0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
    0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
    0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
    0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
    0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
    0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
    0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
    0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
    0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
    0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78
};

uint16_t crc16_x25_check(uint8_t* data, uint32_t length)
{
	unsigned short crc_reg = 0xFFFF;
	
	while (length--)
	{
		crc_reg = (crc_reg >> 8) ^ crc16_table[(crc_reg ^ *data++) & 0xff];
	}
	
	return (uint16_t)(~crc_reg) & 0xFFFF;
}

int protocol_data_packet(uint8_t *buf, uint16_t len, protocol_data_t *protocol_data)
{
    int ret = -1;
    int value_len = 0;
    int offset = 0;
    protocol_format_t *p_protocol_format = NULL;

    if (!buf || !protocol_data || len < PROTOCOL_MIN_LEN)
    {
        printf("Invalid input argument!\n");
        return ret;
    }

    // 通过ID来获取value的长度
    switch (protocol_data->id)
    {
        case PROTOCOL_ID_A_TO_B_CTRL_CMD:
        {
            printf("PROTOCOL_ID_A_TO_B_CTRL_CMD\n");
            value_len = sizeof(protocol_data->value.a_to_b_value.ctrl_cmd);
            printf("protocol_format.length = %d\n", value_len);
            break;
        }
        case PROTOCOL_ID_A_TO_B_DATE_TIME:
        {
            printf("PROTOCOL_ID_A_TO_B_DATE_TIME\n");
            value_len = sizeof(protocol_data->value.a_to_b_value.date_time);
            printf("value_len = %d\n", value_len);
            break;
        }
        
        default:
            break;
    }

    // 为协议格式数据申请内存
    p_protocol_format = (protocol_format_t *)malloc(sizeof(protocol_format_t) + value_len);
    if (NULL == p_protocol_format)
    {
        printf("malloc error\n");
        return ret;
    }

    // 填充协议数据各字段
    p_protocol_format->head = PROTOCOL_HEAD;
    p_protocol_format->id = protocol_data->id;
    p_protocol_format->type = TLV_TYPE_BYTE_ARR;
    p_protocol_format->length = value_len;
    if (p_protocol_format->length <= PROTOCOL_VALUE_MAX_LEN)
    {
        memcpy(p_protocol_format->value, &protocol_data->value.a_to_b_value, p_protocol_format->length);
    }
    else
    {
        printf("protocol_format.length > PROTOCOL_VALUE_MAX_LEN\n");
    }

    // 计算校验值
    uint32_t crc_data_len = sizeof(protocol_format_t) + value_len;
    uint16_t crc16 = crc16_x25_check((uint8_t*)p_protocol_format, crc_data_len);
    printf("crc16 = %#x\n", crc16);

    // struct -> buf
    memcpy(buf, p_protocol_format, crc_data_len);
    offset += crc_data_len;
    memcpy(buf + offset, &crc16, sizeof(uint16_t));
    offset += sizeof(uint16_t);

    // 释放内存
    free(p_protocol_format);
    p_protocol_format = NULL;

    return offset;
}

// 解包函数
void protocol_data_parse(protocol_data_t *protocol_data, uint8_t *buf, uint16_t len)
{
    protocol_format_t *p_protocol_format = NULL;

    if (!buf || !protocol_data || len < PROTOCOL_MIN_LEN)
    {
        printf("Invalid input argument!\n");
        return;
    }

    // 为协议格式数据申请内存
    int value_len = buf[PROTOCOL_LENGTH_INDEX];
    p_protocol_format = (protocol_format_t *)malloc(sizeof(protocol_format_t) + value_len);
    if (NULL == p_protocol_format)
    {
        printf("malloc p_protocol_format error\n");
        return;
    }

    // buf -> struct
    memcpy(p_protocol_format, buf, sizeof(protocol_format_t) + value_len);
    printf("protocol_data->id = %#x\n", p_protocol_format->id);

    // 通过数据ID来解析各对应的数据
    switch (p_protocol_format->id)
    {
        case PROTOCOL_ID_B_TO_A_WORK_STATUS:
        {
            printf("PROTOCOL_ID_B_TO_A_WORK_STATUS\n");
            uint8_t work_status_len = sizeof(protocol_data->value.b_to_a_value.work_status);
            if (p_protocol_format->length == work_status_len)
            {
                memcpy(&protocol_data->value.b_to_a_value.work_status, p_protocol_format->value, p_protocol_format->length);
            }
            else
            {
                printf("p_protocol_format->length error\n");
            }
            break;
        }
        
        default:
            break;
    }

    // 释放内存
    free(p_protocol_format);
    p_protocol_format = NULL;
}

void print_hex_data_frame(uint8_t *pbuf, int buf_len)
{
	int i;
	int j = 1;

	for (i = 0; i < buf_len; i++) 
	{
		printf("%02x-", *(pbuf + i));

		if (j % 32 == 0)
			printf("\n");
		j++;
	}

	printf("\n");
}
