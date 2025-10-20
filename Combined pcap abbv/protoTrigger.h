#ifndef __PROTOTRIGGER_H__
#define __PROTOTRIGGER_H__

#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <map>
#include <unordered_map>
#include <functional>
#include <sstream>
#include <cctype>
#include <stdexcept>
#include <string>
#include <deque>
#include <pcap/pcap.h>

//#include "parser.h"
namespace pcapabvparser
{
//only test/placeholder
struct PacketOffsets_t;
using packetLayerHelper_t = int;

using Func = std::function<int(std::vector<int>)>;

struct VectorHash
{
    std::size_t operator()(const std::vector<uint8_t>& vec) const
    {
        // Treat the vector's data as a string_view over raw bytes
        std::string_view view(reinterpret_cast<const char*>(vec.data()), vec.size());
        return std::hash<std::string_view> {}(view);
    }
};

/** Registered functions that can be invoked in expressions */
//std::unordered_map<std::string, Func> functionRegistry;

class protoTrigger
{
protected:
std::string m_myId;
uint16_t m_protocolNumber;
public:
   protoTrigger();
   protoTrigger(packetLayerHelper_t *helper);
   void setRawPacket(packetLayerHelper_t *packetLayerHelper);
   virtual ~protoTrigger();
   protoTrigger(const protoTrigger &other);
   protoTrigger& operator=(const protoTrigger & other);
   Func protoRequest(std::string &functName);

   std::unordered_map<std::string, Func> m_functEval;
   packetLayerHelper_t *m_packetLayerHelper;
   public:
virtual const std::string id() const;
virtual const uint16_t protoNum() const;
};

class protoTcpTrigger: public protoTrigger
{

    public:
        protoTcpTrigger();
           protoTcpTrigger(packetLayerHelper_t *helper);
        virtual ~protoTcpTrigger();
        protoTcpTrigger(const protoTcpTrigger& other);
        protoTcpTrigger& operator=(const protoTcpTrigger& other);
        Func protoRequest(std::string &functName);

    protected:
    void createNameLambda();


};
class protoUdpTrigger: public protoTrigger
{

    public:
        protoUdpTrigger();
           protoUdpTrigger(packetLayerHelper_t *helper);
        virtual ~protoUdpTrigger();
        protoUdpTrigger(const protoUdpTrigger& other);
        protoUdpTrigger& operator=(const protoUdpTrigger& other);
        Func protoRequest(std::string &functName);

    protected:
    void createNameLambda();


};
class protoIcmpTrigger: public protoTrigger
{

    public:
        protoIcmpTrigger();
           protoIcmpTrigger(packetLayerHelper_t *helper);
        virtual ~protoIcmpTrigger();
        protoIcmpTrigger(const protoIcmpTrigger& other);
        protoIcmpTrigger& operator=(const protoIcmpTrigger& other);
        Func protoRequest(std::string &functName);

    protected:
    void createNameLambda();


};
class protoIpv4Trigger: public protoTrigger
{

    public:
        protoIpv4Trigger();
        protoIpv4Trigger(packetLayerHelper_t *helper);
        virtual ~protoIpv4Trigger();
        protoIpv4Trigger(const protoIpv4Trigger& other);
        protoIpv4Trigger& operator=(const protoIpv4Trigger& other);
        Func protoRequest(std::string &functName);

    protected:
    void createNameLambda();


};

class protoIpv6Trigger: public protoTrigger
{

    public:
        protoIpv6Trigger();
        protoIpv6Trigger(packetLayerHelper_t *helper);
        virtual ~protoIpv6Trigger();
        protoIpv6Trigger(const protoIpv6Trigger& other);
        protoIpv6Trigger& operator=(const protoIpv6Trigger& other);
        Func protoRequest(std::string &functName);

    protected:
    void createNameLambda();


};

class TriggerGen
{
   public:
   TriggerGen();
   virtual ~TriggerGen();
   protoTrigger * getProtocol(const std::string &protoName);
};

//this class handles packet stream information at a per protocol issue
class PacketStreamEval {
public:
PacketStreamEval();
virtual ~PacketStreamEval();

void configurationFiles(std::string configFile);
//cache names and get lambda functions
void registerProtoFnNames(std::vector<std::string> protoFnNames);
auto returnProtoFunction(std::string protoFnName);
void setSavePacketTrigger(bool);
void setSaveStreamTrigger(bool);
void flushPacketsToDisk();
void transferPacket(std::unique_ptr<pcap_pkthdr> &&header, std::unique_ptr<uint8_t[]> &&data, PacketOffsets_t * pktOffsets);
private:
//cached mapping of protocol to lambda
std::unordered_multimap<std::string , protoTrigger > m_protoMap;
//save unique protocols based upon filters (tcp, icmp, ipv6, etc)
std::vector<protoTrigger> m_protocolsUsed;
//packet history (for before intested tagged packets), also post packets after tagging
//dequeue to popping off the front unsaved older packets

std::deque<std::pair<std::unique_ptr<pcap_pkthdr>, std::unique_ptr<uint8_t[]>>> m_packetHistory;

//history of packets to save and/or write to disk
uint32_t m_prePacketHistoryMax;
uint32_t m_postPacketHistoryMax;

//0 for not saving packets, otherwise start with postPacketHistoryMax and decrement
//packetHistory should be zero size when doing post tagged packet saving
//should be post tagged packet if flushing
uint32_t m_currentPostPacketHistoryCnt;

//how many packets to save before disk flush
uint32_t m_flushPacketMax;
//how much memory from packets to save before disk flush
uint32_t m_flushPacketMemMax;
//how many bytes in pkt size (data) currently
uint32_t m_currentPacketMem;

//if we see a 2nd tag packet, and not done, we need to flush existing packets, add the difference from post packets (plus one for additional tag packet), after flushing existing buffer
uint32_t totalPacketsToFlush;

//File pointer to write, if open
FILE *m_filePtr;
//unique fileName;
std::string m_fileName;

//save packets in packetHistory then flush, or flush to disk directly when tagged packets found
bool m_cachePackets;

//do we keep the pcap file (in case we capture packets of interest, but not packet streams to save)
bool m_savePcapStream;

//did we already open a file
bool m_fileopen;

//trigger packet seen, so we save max pre-trigger-post packet counts
bool triggerPacketSeen;




//use a thread_local uint64 to write total bytes written per thread, and have it summed in summary
//total packets per thread, total bytes written per thread, total bytes per all thread,

//need to purge expired objects (time out), and remove any saved files if not to be saved
//or flush buffers to file and close before killing object.

};
}
#endif // __PROTOTRIGGER_H__
