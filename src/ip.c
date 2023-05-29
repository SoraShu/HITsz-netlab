#include "net.h"
#include "ip.h"
#include "ethernet.h"
#include "arp.h"
#include "icmp.h"

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac) {
    // length check
    if (buf->len < sizeof(ip_hdr_t))
        return;

    // head check
    // ipv4 only
    ip_hdr_t *hdr = (ip_hdr_t *)buf->data;
    int valid = ((hdr->version == 4) && (hdr->hdr_len * 4 <= buf->len));
    if (valid == 0)
        return;

    // checksum check
    uint16_t checksum_tmp = hdr->hdr_checksum16;
    uint8_t protocol = hdr->protocol;
    hdr->hdr_checksum16 = 0;
    uint16_t checksum_calc = checksum16((uint16_t *)hdr, sizeof(ip_hdr_t));
    if (checksum_tmp != checksum_calc) {
        printf("ip_in: checksum not equal, calc=%04x, in=%04x\n", checksum_calc,
               checksum_tmp);
        return;
    }
    // restore checksum
    hdr->hdr_checksum16 = checksum_tmp;

    // dip check
    if (memcmp(hdr->dst_ip, net_if_ip, NET_IP_LEN) != 0)
        return;

    // remove padding if padded
    uint16_t totlen = swap16(hdr->total_len16);
    if (totlen < buf->len)
        buf_remove_padding(buf, buf->len - totlen);

    if (protocol != NET_PROTOCOL_ICMP && protocol != NET_PROTOCOL_UDP) {
        icmp_unreachable(buf, hdr->src_ip, ICMP_CODE_PROTOCOL_UNREACH);
    }

    buf_remove_header(buf, hdr->hdr_len * 4);
    net_in(buf, protocol, hdr->src_ip);
}

/**
 * @brief 处理一个要发送的ip分片
 *
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id,
                     uint16_t offset, int mf) {
    buf_add_header(buf, sizeof(ip_hdr_t));

    ip_hdr_t *hdr = (ip_hdr_t *)buf->data;
    *hdr = (ip_hdr_t){
        .version = 4,
        .hdr_len = sizeof(ip_hdr_t) / 4,
        .tos = 0,
        .total_len16 = swap16(buf->len),
        .id16 = swap16(id),
        .flags_fragment16 = swap16((mf ? IP_MORE_FRAGMENT : 0) | (offset)),
        .ttl = 64,
        .protocol = protocol,
        .hdr_checksum16 = 0,
    };
    memcpy(hdr->src_ip, net_if_ip, NET_IP_LEN);
    memcpy(hdr->dst_ip, ip, NET_IP_LEN);

    uint16_t checksum = checksum16((uint16_t *)hdr, sizeof(ip_hdr_t));
    hdr->hdr_checksum16 = checksum;

    arp_out(buf, ip);
}

/**
 * @brief 处理一个要发送的ip数据包
 *
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol) {
    int default_len = (1500 - sizeof(ip_hdr_t)) / 8 * 8;
    static int id = 0;
    buf_t tmp;
    for (int st = 0; st < buf->len; st += default_len) {
        int len = default_len;
        if (st + len > buf->len) {
            len = buf->len - st;
        }
        buf_init(&tmp, len);
        memcpy(tmp.data, (buf->data) + st, len);
        ip_fragment_out(&tmp, ip, protocol, id, st / 8, st + len != buf->len);
    }

    id++;
}

/**
 * @brief 初始化ip协议
 *
 */
void ip_init() { net_add_protocol(NET_PROTOCOL_IP, ip_in); }