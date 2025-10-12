#ifndef __PCAPKEY_H__
#define __PCAPKEY_H__

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <vector>
#include <string>
#include <cstring>
#include <iostream>

namespace pcapabvparser {



struct PacketOffsets_t
{
    size_t l2_offset = 0;
    size_t l3_offset = 0;
    size_t l4_offset = 0;
    size_t payload_offset = 0;
    uint16_t ethertype = 0;
    uint8_t ip_protocol = 0;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t icmp_type = 0;
    uint8_t tls_record_type = 0;
    uint16_t tls_version = 0;
    uint8_t tls_handshake_type = 0;
    uint16_t vxlan_vni;
    std::string tls_sni;
};

std::vector<uint8_t> parse_packet(const uint8_t * packet, const pcap_pkthdr* header, PacketOffsets_t& offsets);

} //end namespace
#endif // __PCAPKEY_H__
