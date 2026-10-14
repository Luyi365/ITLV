#include <stdio.h>   
#include <strings.h>
#include "protocol_tlv.h"

int main(int arc, char *argv[])
{
    static uint8_t send_buf[PROTOCOL_MAX_LEN] = {0};
    protocol_data_t protocol_data_send = {0};
    int send_len = 0;

    printf("\n==============================test packet===========================================\n");
    // 模拟组包发送控制命令
    bzero(send_buf, sizeof(send_buf));
    bzero(&protocol_data_send, sizeof(protocol_data_t));
    protocol_data_send.id = PROTOCOL_ID_A_TO_B_CTRL_CMD;
    protocol_data_send.value.a_to_b_value.ctrl_cmd.cmd = CTRL_CMD_LED_OFF;
    send_len = protocol_data_packet(send_buf, PROTOCOL_MAX_LEN, &protocol_data_send);
    printf("send ctrl data = ");
    print_hex_data_frame(send_buf, send_len);

    // 模拟组包发送时间数据
    bzero(send_buf, sizeof(send_buf));
    bzero(&protocol_data_send, sizeof(protocol_data_t));
    protocol_data_send.id = PROTOCOL_ID_A_TO_B_DATE_TIME;
    protocol_data_send.value.a_to_b_value.date_time.year = 2022;
    protocol_data_send.value.a_to_b_value.date_time.mon = 8;
    protocol_data_send.value.a_to_b_value.date_time.mday = 20;
    protocol_data_send.value.a_to_b_value.date_time.hour = 8;
    protocol_data_send.value.a_to_b_value.date_time.min = 8;
    protocol_data_send.value.a_to_b_value.date_time.sec = 8;
    send_len = protocol_data_packet(send_buf, PROTOCOL_MAX_LEN, &protocol_data_send);
    printf("send date_time data = ");
    print_hex_data_frame(send_buf, send_len);

    printf("\n==============================test parse===========================================\n");
    // 模拟解析工作状态数据
    uint8_t work_status_buf[11] = {0x55, 0xAA, 0x81, 0x08, 0x04, 0x01, 0x00, 0x00, 0x00, 0xf2, 0x88};
    protocol_data_t protocol_data_recv = {0};

    uint16_t calc_crc16 = crc16_x25_check(work_status_buf, sizeof(work_status_buf) - 2);
    uint16_t recv_crc16 = (uint16_t)(work_status_buf[10] << 8) | work_status_buf[9];

    if (calc_crc16 == recv_crc16)
    {
        protocol_data_parse(&protocol_data_recv, work_status_buf, sizeof(work_status_buf));
        printf("work_status = %d\n", protocol_data_recv.value.b_to_a_value.work_status.status);
    }

	return 0;
}