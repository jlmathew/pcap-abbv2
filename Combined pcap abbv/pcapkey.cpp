#include "pcapkey.h"

namespace pcapabvparser
{


//need to add link layer proto
std::pair <std::unique_ptr<std::vector<uint8_t>>, std::unique_ptr<PacketOffsets_t>> parse_packet(
            const uint8_t* packet,
            const pcap_pkthdr* header)

{

    auto key = std::make_unique<std::vector<uint8_t>>();
    auto protoOffsets = std::make_unique<PacketOffsets_t>();


    size_t offset = 0;

    size_t caplen = header->caplen;


    // L2: Ethernet
    //need to have 'sizeof' dependent upon packet capture type
    if (offset + sizeof(ether_header) > caplen)
    {
        key->clear();
        return  std::make_pair( std::move(key),std::move(protoOffsets) );
    }
    const ether_header* eth = reinterpret_cast<const ether_header*>(packet + offset);
    protoOffsets->ethertype = ntohs(eth->ether_type);
    protoOffsets->l2_offset = offset;
    offset += sizeof(ether_header);

    // Add EtherType to key
    key->push_back((protoOffsets->ethertype >> 8) & 0xFF);
    key->push_back(protoOffsets->ethertype & 0xFF);

    //std::cout << "L3proto=" << std::hex << protoOffsets->ethertype << std::endl;

    // L3: IP
    if (offset >= caplen)
    {
        key->clear();
        return  std::make_pair( std::move(key),std::move(protoOffsets) );
    }
    const u_char* l3 = packet + offset;
    uint8_t ip_version = (l3[0] >> 4);

    if (protoOffsets->ethertype == ETHERTYPE_IP && ip_version == 4)
    {
        if (offset + sizeof(ip) > caplen)
        {
            key->clear();
            return  std::make_pair( std::move(key),std::move(protoOffsets) );
        }
        const ip* ipv4 = reinterpret_cast<const ip*>(l3);
        protoOffsets->ip_protocol = ipv4->ip_p;
        protoOffsets->l3_offset = offset;
        offset += ipv4->ip_hl * 4;
        if (ntohl(ipv4->ip_src.s_addr) > ntohl(ipv4->ip_dst.s_addr))
        {
            key->insert(key->end(), reinterpret_cast<const uint8_t*>(&ipv4->ip_src), reinterpret_cast<const uint8_t*>(&ipv4->ip_src) + 4);
            key->insert(key->end(), reinterpret_cast<const uint8_t*>(&ipv4->ip_dst), reinterpret_cast<const uint8_t*>(&ipv4->ip_dst) + 4);
        }
        else
        {
            key->insert(key->end(), reinterpret_cast<const uint8_t*>(&ipv4->ip_dst), reinterpret_cast<const uint8_t*>(&ipv4->ip_dst) + 4);
            key->insert(key->end(), reinterpret_cast<const uint8_t*>(&ipv4->ip_src), reinterpret_cast<const uint8_t*>(&ipv4->ip_src) + 4);
            protoOffsets->originalAddrPortOrdering=false;
        }

        //std::cout << "Src addr:" << protoOffsets->originalAddrPortOrdering << std::endl;
        uint32_t ip=ntohl(ipv4->ip_src.s_addr);
        /* std::cout << "IP src:" << std::dec << ((ip >> 24) & 0xFF) << "."
                  << ((ip >> 16)  & 0xFF) << "."
                  << ((ip >> 8) & 0xFF) << "."
                  << (ip & 0xFF) << std::endl;
        ip=ntohl(ipv4->ip_dst.s_addr);
        std::cout << std::dec << "IP dst:" << ((ip >> 24) & 0xFF) << "."
                  << ((ip >> 16)  & 0xFF) << "."
                  << ((ip >> 8) & 0xFF) << "."
                  << (ip & 0xFF) << std::endl; */
    }
    else if (protoOffsets->ethertype == ETHERTYPE_IPV6 && ip_version == 6)
    {
        if (offset + sizeof(ip6_hdr) > caplen)
        {
            key->clear();
            return  std::make_pair( std::move(key),std::move(protoOffsets) );
        }
        const ip6_hdr* ipv6 = reinterpret_cast<const ip6_hdr*>(l3);
        protoOffsets->ip_protocol = ipv6->ip6_nxt;
        protoOffsets->l3_offset = offset;
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
            protoOffsets->originalAddrPortOrdering=false;
        }
    }
    else
    {
        key->clear();
        return  std::make_pair( std::move(key),std::move(protoOffsets) );// unsupported L3
    }

    // L4: TCP, UDP, ICMP
    protoOffsets->l4_offset = offset;
    const u_char* l4 = packet + offset;

    if (protoOffsets->ip_protocol == IPPROTO_TCP && offset + sizeof(tcphdr) <= caplen)
    {
        const tcphdr* tcp = reinterpret_cast<const tcphdr*>(l4);
        protoOffsets->src_port = ntohs(tcp->th_sport);
        protoOffsets->dst_port = ntohs(tcp->th_dport);
        offset += tcp->th_off * 4;
        protoOffsets->payload_offset = offset;


    }
    else if (protoOffsets->ip_protocol == IPPROTO_UDP && offset + sizeof(udphdr) <= caplen)
    {
        const udphdr* udp = reinterpret_cast<const udphdr*>(l4);
        protoOffsets->src_port = ntohs(udp->uh_sport);
        protoOffsets->dst_port = ntohs(udp->uh_dport);
        offset += sizeof(udphdr);
        protoOffsets->payload_offset = offset;
        size_t payload_len = caplen - offset;
        const u_char* payload = packet + offset;

    }
    else if (protoOffsets->ip_protocol == IPPROTO_ICMP && offset + sizeof(icmp) <= caplen)
    {
        const icmp* icmpv4 = reinterpret_cast<const icmp*>(l4);
        protoOffsets->icmp_type = icmpv4->icmp_type;
        protoOffsets->icmp_code = icmpv4->icmp_code;
    }
    else if (protoOffsets->ip_protocol == IPPROTO_ICMPV6 && offset + sizeof(icmp6_hdr) <= caplen)
    {
        const icmp6_hdr* icmpv6 = reinterpret_cast<const icmp6_hdr*>(l4);
        protoOffsets->icmp_type = icmpv6->icmp6_type;
        protoOffsets->icmp_code = icmpv6->icmp6_code;
    }

    // Add L4 info to key
    key->push_back(protoOffsets->ip_protocol);
    std::cout << "L4 proto:" << std::dec << protoOffsets->ip_protocol << std::endl;
    //ICMP doesnt use ports
    if ((protoOffsets->ip_protocol == IPPROTO_ICMP ) || (protoOffsets->ip_protocol == IPPROTO_ICMPV6))
    {
        key->push_back(protoOffsets->icmp_type);
        key->push_back(protoOffsets->icmp_code);
        //ICMP will have 'port key' set to 0
        key->push_back((uint8_t) 0); //need to add due to no ICMP ports, should not be necessary, but unsure if this would affect hashing for now TODO
        key->push_back((uint8_t) 0);
    }
    else //UDP or TCP
    {
        //parse  largest/smallest port, to allow key to be the same for ingress/egress keys
        if (protoOffsets->originalAddrPortOrdering)
        {
            key->push_back((protoOffsets->src_port >> 8) & 0xFF);
            key->push_back(protoOffsets->src_port & 0xFF);
            key->push_back((protoOffsets->dst_port >> 8) & 0xFF);
            key->push_back(protoOffsets->dst_port & 0xFF);
            //std::cout << "srcport:" << std::dec << protoOffsets->src_port << std::endl;
            //std::cout << "dstport:" << std::dec << protoOffsets->dst_port << std::endl;
        }
        else
        {
            key->push_back((protoOffsets->dst_port >> 8) & 0xFF);
            key->push_back(protoOffsets->dst_port & 0xFF);
            key->push_back((protoOffsets->src_port >> 8) & 0xFF);
            key->push_back(protoOffsets->src_port & 0xFF);
            //std::cout << "srcport:" << std::dec << protoOffsets->dst_port << std::endl;
            //std::cout << "dstport:" << std::dec << protoOffsets->src_port << std::endl;
        }

    }

//only print ip/tcp/udp/icmp
    print_key(*key);
    return  std::make_pair( std::move(key),std::move(protoOffsets) );
}

//void print_key(std::unique_ptr<std::vector<uint8_t>> key)
void print_key(std::vector<uint8_t> key)
{
//std::vector<uint8_t> *val=key.get();
    std::ostringstream oss;  //parameter should be ostringstream, not cout (allow parameter to be passed) to allow strings as well

    std::cout << "PRINTKEY: ########" << std::endl;
    std::cout << "Size:" << key.size() << std::endl;
    for (unsigned int i=0; i<key.size(); i++)
    {
        std::cout <<std::hex << std::uppercase
                  << std::setw(2) << std::setfill('0') << static_cast<int>(key[i]); //key[i];
    }
    std::cout << std::endl;

    std::cout << "L3 Proto:0x" << std::hex << std::uppercase << std::setw(4) << (uint16_t) (key[0]*256+key[1]) << std::endl;
    if (0x800 == (key[0]*256+key[1]))
    {
        std::cout << "IPv4 addr1:" << std::dec << static_cast<int>(key[2])  << "." << static_cast<int>(key[3]) << "." << static_cast<int>(key[4]) << "." << static_cast<int>(key[5]) << std::endl;
        std::cout << "IPv4 addr2:" << std::dec << static_cast<int>(key[6]) << "." <<  static_cast<int>(key[7]) << "."  << static_cast<int>(key[8]) << "." << static_cast<int>(key[9]) << std::endl;
    }
    else if (41 == (key[0]*256+key[1]))
    {
        std::cout << "Ipv6 addr1:";
        for (size_t i = 0; i < 16; i += 2)
        {
            uint16_t segment = (key[i] << 8) | key[i + 1];
            std::cout  << std::hex << std::setw(4) << std::setfill('0') << segment;
            if (i < 14) std::cout << ":";
        }
        std::cout << std::endl;
        for (size_t i = 0; i < 16; i += 2)
        {
            uint16_t segment = (key[i+16] << 8) | key[i + 1];
            std::cout  << std::hex << std::setw(4) << std::setfill('0') << segment;
            if (i < 30) std::cout << ":";
        }
        std::cout << std::endl;
    }
    else
    {
        std::cout << "Invalid L3 protocol" << std::endl;
    }
    std::cout << "L4 proto:" << std::dec << std::uppercase << std::setw(2)<< (int)key[10] << std::endl;;
    if (key[10]==1)   //ICMP
    {
        std::cout << "ICMP type:" << std::dec << (int) key[11] << std::endl;
        std::cout << "ICMP code:" << std::dec << (int) key[12] << std::endl;
    }
    else
    {
        std::cout << "Port1:" << std::dec << (uint16_t) (key[11]*256+key[12]) << std::endl;
        std::cout << "Port2:" << std::dec << (uint16_t) (key[13]*256+key[14]) << std::endl;
    }

    std::cout << "END PRINTKEY #####\n\n" << std::endl;
}
} //end namespace
