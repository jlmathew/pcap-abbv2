#include "pcapkey.h"

namespace pcapabvparser
{

std::unique_ptr<std::vector<uint8_t>> parse_packet(
     std::unique_ptr<uint8_t[]>& uniquePacket,
     std::unique_ptr<pcap_pkthdr>& header,
     std::unique_ptr<PacketOffsets_t>& uniqueOffsets)
{
    auto key = std::make_unique<std::vector<uint8_t>>();

//std::vector<uint8_t> parse_packet(const u_char* packet, const pcap_pkthdr* header, PacketOffsets_t& offsets)
//{
    //std::vector<uint8_t> key;
    size_t offset = 0;
    size_t caplen = header->caplen;
    uint8_t *packet=uniquePacket.get();
    PacketOffsets_t *offsets=uniqueOffsets.get();

    // L2: Ethernet
    if (offset + sizeof(ether_header) > caplen) return key;
    const ether_header* eth = reinterpret_cast<const ether_header*>(packet + offset);
    offsets->ethertype = ntohs(eth->ether_type);
    offsets->l2_offset = offset;
    offset += sizeof(ether_header);

    // Add EtherType to key
    key->push_back((offsets->ethertype >> 8) & 0xFF);
    key->push_back(offsets->ethertype & 0xFF);

    // L3: IP
    if (offset >= caplen) return key;
    const u_char* l3 = packet + offset;
    uint8_t ip_version = (l3[0] >> 4);

    if (offsets->ethertype == ETHERTYPE_IP && ip_version == 4)
    {
        if (offset + sizeof(ip) > caplen) return key;
        const ip* ipv4 = reinterpret_cast<const ip*>(l3);
        offsets->ip_protocol = ipv4->ip_p;
        offsets->l3_offset = offset;
        offset += ipv4->ip_hl * 4;
        if (ntohl(ipv4->ip_src.s_addr) > ntohl(ipv4->ip_dst.s_addr))
        {
            key->insert(key->end(), reinterpret_cast<const uint8_t*>(&ipv4->ip_src), reinterpret_cast<const uint8_t*>(&ipv4->ip_src) + 4);
            key->insert(key->end(), reinterpret_cast<const uint8_t*>(&ipv4->ip_dst), reinterpret_cast<const uint8_t*>(&ipv4->ip_dst) + 4);
        }
        else
        {
            key->insert(key->end(), reinterpret_cast<const uint8_t*>(&ipv4->ip_src), reinterpret_cast<const uint8_t*>(&ipv4->ip_src) + 4);
            key->insert(key->end(), reinterpret_cast<const uint8_t*>(&ipv4->ip_dst), reinterpret_cast<const uint8_t*>(&ipv4->ip_dst) + 4);

        }

    }
    else if (offsets->ethertype == ETHERTYPE_IPV6 && ip_version == 6)
    {
        if (offset + sizeof(ip6_hdr) > caplen) return key;
        const ip6_hdr* ipv6 = reinterpret_cast<const ip6_hdr*>(l3);
        offsets->ip_protocol = ipv6->ip6_nxt;
        offsets->l3_offset = offset;
        offset += sizeof(ip6_hdr);
        using uint128 = std::tuple<uint64_t, uint64_t>;

        const uint8_t* src_bytes = reinterpret_cast<const uint8_t*>(&ipv6->ip6_src);
        uint64_t src_hi = *reinterpret_cast<const uint64_t*>(src_bytes);
        uint64_t src_lo = *reinterpret_cast<const uint64_t*>(src_bytes + 8);
        uint128 src = std::make_tuple(src_hi, src_lo);

        const uint8_t* dst_bytes = reinterpret_cast<const uint8_t*>(&ipv6->ip6_dst);
        uint64_t dst_hi = *reinterpret_cast<const uint64_t*>(dst_bytes);
        uint64_t dst_lo = *reinterpret_cast<const uint64_t*>(dst_bytes + 8);
        uint128 dst = std::make_tuple(dst_hi, dst_lo);
        key->insert(key->end(), reinterpret_cast<const uint8_t*>(&ipv6->ip6_src), reinterpret_cast<const uint8_t*>(&ipv6->ip6_src) + 16);
        key->insert(key->end(), reinterpret_cast<const uint8_t*>(&ipv6->ip6_dst), reinterpret_cast<const uint8_t*>(&ipv6->ip6_dst) + 16);
        if (src>dst)
        {
            key->insert(key->end(), reinterpret_cast<const uint8_t*>(&ipv6->ip6_src), reinterpret_cast<const uint8_t*>(&ipv6->ip6_src) + 16);
            key->insert(key->end(), reinterpret_cast<const uint8_t*>(&ipv6->ip6_dst), reinterpret_cast<const uint8_t*>(&ipv6->ip6_dst) + 16);
        }
        else
        {
            key->insert(key->end(), reinterpret_cast<const uint8_t*>(&ipv6->ip6_dst), reinterpret_cast<const uint8_t*>(&ipv6->ip6_dst) + 16);
            key->insert(key->end(), reinterpret_cast<const uint8_t*>(&ipv6->ip6_src), reinterpret_cast<const uint8_t*>(&ipv6->ip6_src) + 16);

        }
    }
    else
    {
        return key; // unsupported L3
    }

    // L4: TCP, UDP, ICMP
    offsets->l4_offset = offset;
    const u_char* l4 = packet + offset;

    if (offsets->ip_protocol == IPPROTO_TCP && offset + sizeof(tcphdr) <= caplen)
    {
        const tcphdr* tcp = reinterpret_cast<const tcphdr*>(l4);
        offsets->src_port = ntohs(tcp->th_sport);
        offsets->dst_port = ntohs(tcp->th_dport);
        offset += tcp->th_off * 4;
        offsets->payload_offset = offset;

        // TLS detection
        if (offset + 5 <= caplen && l4[0] == 22)
        {
            offsets->tls_record_type = l4[0];
            offsets->tls_version = (l4[1] << 8) | l4[2];
            offsets->tls_handshake_type = l4[5];

            // SNI extraction (simplified)
            for (size_t i = 43; i + 5 < caplen; )
            {
                uint16_t ext_type = (l4[i] << 8) | l4[i + 1];
                uint16_t ext_len = (l4[i + 2] << 8) | l4[i + 3];
                if (ext_type == 0x00 && ext_len > 5)
                {
                    size_t sni_len = l4[i + 5];
                    if (i + 6 + sni_len <= caplen)
                        offsets->tls_sni = std::string(reinterpret_cast<const char*>(&l4[i + 6]), sni_len);
                    break;
                }
                i += 4 + ext_len;
            }
        }

    }
    else if (offsets->ip_protocol == IPPROTO_UDP && offset + sizeof(udphdr) <= caplen)
    {
        const udphdr* udp = reinterpret_cast<const udphdr*>(l4);
        offsets->src_port = ntohs(udp->uh_sport);
        offsets->dst_port = ntohs(udp->uh_dport);
        offset += sizeof(udphdr);
        offsets->payload_offset = offset;
        size_t payload_len = caplen - offset;
        const u_char* payload = packet + offset;

        // VXLAN detection
        if (offsets->dst_port == 4789 && payload_len >= 8)
        {
            offsets->vxlan_vni = (payload[4] << 16) | (payload[5] << 8) | payload[6];
        }
    }
    else if (offsets->ip_protocol == IPPROTO_ICMP && offset + sizeof(icmp) <= caplen)
    {
        const icmp* icmpv4 = reinterpret_cast<const icmp*>(l4);
        offsets->icmp_type = icmpv4->icmp_type;

    }
    else if (offsets->ip_protocol == IPPROTO_ICMPV6 && offset + sizeof(icmp6_hdr) <= caplen)
    {
        const icmp6_hdr* icmpv6 = reinterpret_cast<const icmp6_hdr*>(l4);
        offsets->icmp_type = icmpv6->icmp6_type;
    }

    // Add L4 info to key
    key->push_back(offsets->ip_protocol);
    //ICMP doesnt use ports
    if ((offsets->ip_protocol == IPPROTO_ICMP ) || (offsets->ip_protocol == IPPROTO_ICMPV6))
    {
        key->push_back(offsets->icmp_type);
    }
    else //UDP or TCP
    {
        //parse  largest/smallest port, to allow key to be the same for ingress/egress keys
        if (offsets->src_port > offsets->dst_port)
        {
            key->push_back((offsets->src_port >> 8) & 0xFF);
            key->push_back(offsets->src_port & 0xFF);
            key->push_back((offsets->dst_port >> 8) & 0xFF);
            key->push_back(offsets->dst_port & 0xFF);
        }
        else
        {
            key->push_back((offsets->dst_port >> 8) & 0xFF);
            key->push_back(offsets->dst_port & 0xFF);
            key->push_back((offsets->src_port >> 8) & 0xFF);
            key->push_back(offsets->src_port & 0xFF);
        }

    }



    return key;
}

void print_key(std::unique_ptr<std::vector<uint8_t>> key)  {


}



} //end namespace
