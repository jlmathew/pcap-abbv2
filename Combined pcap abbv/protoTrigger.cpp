#include "protoTrigger.h"

namespace pcapabvparser
{
//Base class protoTrigger
protoTrigger::protoTrigger() //illegal to call
{

}

protoTrigger::~protoTrigger()
{
    //dtor
}

protoTrigger::protoTrigger(const protoTrigger& other)
{
    //copy ctor
}

protoTrigger& protoTrigger::operator=(const protoTrigger& rhs)
{
    return *this;
}

Func protoTrigger::protoRequest(std::string &functName)
{
    return 0;
}

void protoTrigger::setRawPacket(packetLayerHelper_t *packetLayerHelper)
{
    m_packetLayerHelper = packetLayerHelper;
}

protoTrigger::protoTrigger(packetLayerHelper_t *packetLayerHelper)
{
    setRawPacket(packetLayerHelper);
}
const std::string protoTrigger::id() const
{
    return m_myId;
}

const uint16_t protoTrigger::protoNum() const
{
    return m_protocolNumber;
}

// TCP protocol trigger
protoTcpTrigger::protoTcpTrigger()
{
    createNameLambda();

}

protoTcpTrigger::~protoTcpTrigger()
{

}

protoTcpTrigger::protoTcpTrigger(const protoTcpTrigger& other)
{

}

protoTcpTrigger& protoTcpTrigger::operator=(const protoTcpTrigger& rhs)
{
    if (this == &rhs) return *this; // handle self assignment
    //assignment operator
    return *this;
}

protoTcpTrigger::protoTcpTrigger(packetLayerHelper_t *packetLayerHelper)
{
    protoTrigger::setRawPacket(packetLayerHelper);
}

Func protoTcpTrigger::protoRequest(std::string &functName)
{

    auto it = m_functEval.find(functName);
    if (it != m_functEval.end())
    {
        return it->second; // Call the associated function
    }
    else
    {
        return [functName](std::vector<int> params)
        {
            std::cout << "Parameter " << functName << "Not registered function in TCP" << std::endl;
            return 0;
        };
    }
}
//auto lambdaFunc = [&g](const std::string& name) {g.greet(name);};

void protoTcpTrigger::createNameLambda()
{

    m_functEval.emplace("SYNONLY_CNT",
                        [helper = this->m_packetLayerHelper](std::vector<int> params) -> int
    {
        // Example logic using captured helper
        int sum = 0;
        for (int val : params)
        {
            sum += val;
        }
        return sum + *helper;
    }
                       );
    m_functEval.emplace("Handshake",
                        [helper = this->m_packetLayerHelper](std::vector<int> params) -> int
    {
        // Example logic using captured helper
        return 0;
    }
                       );
    m_functEval.emplace("RST_CNT",
                        [helper = this->m_packetLayerHelper](std::vector<int> params) -> int
    {
        // Example logic using captured helper
        return 0;
    }
                       );

    m_functEval.emplace("IllegalFlagCnt",
                        [helper = this->m_packetLayerHelper](std::vector<int> params) -> int
    {
        // Example logic using captured helper
        return 0;
    }
                       );
}

TriggerGen::TriggerGen() {}
   TriggerGen::~TriggerGen() {}
   protoTrigger * TriggerGen::getProtocol(const std::string &protoName) { return nullptr;}





PacketStreamEval::PacketStreamEval() {

}

PacketStreamEval::~PacketStreamEval() {}
void PacketStreamEval::configurationFiles(std::string configFile) {}
void PacketStreamEval::registerProtoFnNames(std::vector<std::string> protoFnNames) {
for(auto protoName : protoFnNames )
{

}

}
auto PacketStreamEval::returnProtoFunction(std::string protoFnName) {}
void PacketStreamEval::setSavePacketTrigger(bool) {}
void PacketStreamEval::setSaveStreamTrigger(bool) {}
void PacketStreamEval::flushPacketsToDisk() {}
void PacketStreamEval::transferPacket(std::unique_ptr<pcap_pkthdr> &&header, std::unique_ptr<uint8_t[]> &&data, PacketOffsets_t * pktOffsets) {

//save packet
m_packetHistory.emplace_back(std::move(header), std::move(data));

//check if packet is interesting or to save

//flush prior packets

//calculate how many future packets to save

//flush/erase/drop all packets beyond required size


}

} //end namespace
