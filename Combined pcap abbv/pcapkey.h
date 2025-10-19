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
#include <memory>
#include "nonblockingbuffers.h"
#include <utility>
#include <random>

#include <iomanip>

namespace pcapabvparser {

//hash function for packet key
/*struct VectorHash
{
    std::size_t operator()(const std::vector<uint8_t>& vec) const
    {
        // Treat the vector's data as a string_view over raw bytes
        std::string_view view(reinterpret_cast<const char*>(vec.data()), vec.size());
        return std::hash<std::string_view> {}(view);
    }
};*/



struct PacketOffsets_t
{
    size_t l2_offset = 0;
    size_t l3_offset = 0;
    size_t l4_offset = 0;
    size_t payload_offset = 0;
    uint16_t ethertype = 0;  //L3
    uint8_t ip_protocol = 0;  //L4
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t icmp_type = 0;
    uint8_t icmp_code = 0;
    //uint8_t tls_record_type = 0;
    //uint16_t tls_version = 0;
    //uint8_t tls_handshake_type = 0;
    //uint16_t vxlan_vni;
    //std::string tls_sni;
    bool originalAddrPortOrdering=true;
};


std::pair <std::unique_ptr<std::vector<uint8_t>>, std::unique_ptr<PacketOffsets_t>> parse_packet(
    const uint8_t* packet,
    const pcap_pkthdr* header); //,
 //   PacketOffsets_t* offsets);

//void print_key(std::unique_ptr<std::vector<uint8_t>> key);
void print_key(std::vector<uint8_t> key);
} //end namespace
#endif // __PCAPKEY_H__
