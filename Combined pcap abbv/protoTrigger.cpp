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

/*
LambdaHolderType protoTrigger::protoRequest(std::string &functName)
{
    return 0;
}
*/

void protoTrigger::setRawPacket(packetLayerHelper_t *packetLayerHelper)
{
    m_packetLayerHelper = packetLayerHelper;
}


const std::string protoTrigger::id() const
{
    return m_myId;
}

const uint16_t protoTrigger::protoNum() const
{
    return m_protocolNumber;
}

void protoTrigger::protoRegister(lambdaMap &protoMap) {}

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


/*LambdaHolderType protoTcpTrigger::protoRequest(std::string &functName)
//ICallable* protoTcpTrigger::protoRequest(std::string &functName)
//auto protoTcpTrigger::protoRequest(std::string &functName)
{

    auto it = m_functEval.find(functName);
    if (it != m_functEval.end())
    {
        return it->second; // Call the associated function
    }
    else
    {
        return make_lambda_holder([functName](const std::vector<int> &)
        {
            std::cout << "Parameter " << functName << "Not registered function in TCP" << std::endl;
            return 0;
        });
    }
}*/
//auto lambdaFunc = [&g](const std::string& name) {g.greet(name);};

void protoTcpTrigger::createNameLambda() {}
void protoTcpTrigger::protoRegister(lambdaMap &m_functEval)
{
    static int test1=0;

    m_functEval.emplace("TCP.Test",  make_lambda_holder([&](const std::vector<int>& params)
    {

        a--;
        std::cout << "Tcp.Test called. Counter is now: " << test1 << " and " << a << "\n";
        return test1++;
    })
                       );
}

/*
m_functEval.emplace("SYNONLY_CNT",
                  [helper = this->m_packetLayerHelper](std::vector<int> params) -> int
{
  // Example logic using captured helper
  int sum = 0;
  for (int val : params)
  {
      sum += val;
  }
  return sum ;
}
                 );
m_functEval.emplace("Handshake",
                  [helper = this->m_packetLayerHelper](std::vector<int> params) -> int
{
  // Example logic using captured helper
  test1++;
  return 0;
} );


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
protoTrigger * TriggerGen::getProtocol(const std::string &protoName)
{
return nullptr;
}
*/




PacketStreamEval::PacketStreamEval()
{

}

PacketStreamEval::~PacketStreamEval()
{
//temporary default, flush buffers

}
void PacketStreamEval::configurationFiles(std::string configFile) {}

//probably faster to have them register directly, but we need to 'prefill' in all functions to return '0', in case its not supported
void PacketStreamEval::registerProtoFnNames(std::vector<std::string> protoFnNames)
{
    std::string protocol, functName;
    for(auto protoName : protoFnNames )
    {
        size_t pos = protoName.find('.');

        if (pos != std::string::npos)
        {
            protocol = protoName.substr(0, pos);         // Before the dot
            functName = protoName.substr(pos + 1);        // After the dot
        }
        else
        {
            protocol = protoName;                        // No dot found
            functName = "";                           // Empty second part
        }
        auto iter=m_protocolsUsed.find(protocol);

        if (iter == m_protocolsUsed.end())
        {
            if (protocol == "TCP")
            {
                iter =m_protocolsUsed.insert({"TCP", new protoTcpTrigger()});
                iter->second->protoRegister(m_protoLambdaMap);
std::cout << "registered function TCP." << std::endl;
            }
            /* else  if (protocol == "IPv4")
            {
                iter = m_protocolsUsed.insert({"IPv4", new protoIpv4Trigger()});

            }
            //FIXME only support tcp/ipv4 due to time
             else if (protocol == "UDP")
             {
                 iter = m_protocolsUsed.insert({"UDP", new protoUDPTrigger()});

             }

             else if (protocol == "IPv6")
             {
                 iter = m_protocolsUsed.insert({"IPv6", new protoIpv6Trigger()});

             }
             else if (protocol == "ICMP")
             {
                 iter = m_protocolsUsed.insert({"ICMP", new protoIcmpTrigger()});

             }*/
            else   //unsupported
            {
                std::cerr << "Unsuported protocol in packet stream evaluation:" << protocol << std::endl;
                exit(1);

            }

        }

        //auto lambda = iter->second.protoRequest(protocol);
        //m_protoLambdaMap.emplace({protoName, iter->second.protoRequest(protocol)});


        //is lamdba valid?
        //LambdaHolder lamContainer(lambda);
    }

}
//void PacketStreamEval::evaluatePacket(pcap_pkthdr *hdr, uint8_t[] &data, PacketOffsets_t *offsets, ASTPtr &tree) {}
void PacketStreamEval::evaluatePacket(pcap_pkthdr* hdr, uint8_t* data, PacketOffsets_t* offsets, ASTNode * tree) {}
auto PacketStreamEval::returnProtoFunction(std::string protoFnName) {}
void PacketStreamEval::setSavePacketTrigger(bool) {}
void PacketStreamEval::setSaveStreamTrigger(bool) {}
void PacketStreamEval::flushPacketsToDisk() {}
void PacketStreamEval::transferPacket(std::unique_ptr<pcap_pkthdr> &&header, std::unique_ptr<uint8_t[]> &&data, std::unique_ptr<PacketOffsets_t>  &&pktOffsets)
{

//This should evaluate and save

//save packet
    m_packetHistory.emplace_back(std::move(header), std::move(data));

//check if packet is interesting or to save

//flush prior packets

//calculate how many future packets to save

//flush/erase/drop all packets beyond required size


}

} //end namespace
