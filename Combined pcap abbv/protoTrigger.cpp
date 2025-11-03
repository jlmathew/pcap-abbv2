#include "protoTrigger.h"



namespace pcapabvparser
{

extern thread_local std::map<std::string, std::function<int(const std::vector<int>&)>> userFunctions;

//Base class protoTrigger
protoTrigger::protoTrigger() //illegal to call
{

}
/*
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
*/
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

//void protoTrigger::protoRegister(const std::vector<std::string> &fnNames) {}

const std::string protoTrigger::id() const
{
    return m_myId;
}

const uint16_t protoTrigger::protoNum() const
{
    return m_protocolNumber;
}


// TCP protocol trigger
protoTcpTrigger::protoTcpTrigger():b(0)
{
    std::cout << "CREATING lambda" << std::endl;
//createNameLambda();

}
std::shared_ptr<protoTcpTrigger> protoTcpTrigger::create(const std::vector<std::string>& fnNames)
{
    //auto ptr = std::shared_ptr<protoTcpTrigger>(new protoTcpTrigger());
    auto ptr = std::make_shared<protoTcpTrigger>();
std::cout << "make_shared ptr = " << ptr.get() << std::endl;

    ptr->createNameLambda();
    ptr->protoRegister(fnNames);
    return ptr;
}

void protoTcpTrigger::createNameLambda()
{
    std::weak_ptr<protoTcpTrigger> self = shared_from_this(); //
    //test
    try
    {
        auto self = shared_from_this();
        std::cout << "shared_from_this() succeeded" << std::endl;
    }
    catch (const std::bad_weak_ptr& e)
    {
        std::cerr << "shared_from_this() failed: " << e.what() << std::endl;
    }

m_protoMap["TCP.Test"] = [](const std::vector<int>&) { return 42; };

    m_protoMap["TCP.Test2"] = [a = 50, self](const std::vector<int>&) mutable
    {
        if (auto spt = self.lock())
        {
            return --a;
        }
        return -1;
    };
}
protoTcpTrigger::~protoTcpTrigger()
{
    std::cout << "protoTcpTrigger eval deleted" << std::endl;
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
/*
void protoTcpTrigger::createNameLambda()
{
    int a=50; //test
    //static std::atomic<int> test1{0};

    std::cout << "calling creatNameLambda" << std::endl;
    std::weak_ptr<protoTcpTrigger> self = shared_from_this();


    m_protoMap["TCP.Test"] = [a, self](const std::vector<int>& params) mutable -> int
    {
        if (auto spt = self.lock())
        {
            a--;
            // use spt->... if needed
            return a;
        }
        else
        {
            std::cerr << "protoTcpTrigger no longer alive!" << std::endl;
            return 0;
        }
    };
    //m_protoMap["TCP.Test"] = ([a,this](const std::vector<int>& params) mutable
    //m_protoMap["TCP.Test"] = ([&test1](const std::vector<int>& params)
    {

        a--;
        //b = (++b) % 2;
        std::cout << "Tcp.Test called. Counter is now: " << a << "\n"; //<< " and " <<  " and " << b << "\n";
        return a; //test1.fetch_add(1);
    }
      };
//}
*/

void protoTcpTrigger::protoRegister(const std::vector<std::string> &fnNames) //string_view to be quicker
{

    std::cout << "protoTCP Register called " << std::endl;
    for(auto name : fnNames)
    {
        auto itr= m_protoMap.find(name);
        if (itr != m_protoMap.end() && itr->second)
        {
            std::cout << "Registering function: '" << name << "' length=" << name.length() << std::endl;
            std::vector<int> a;
            std::cout << "return vlaue is " << itr->second(a);
            std::cout << "Lambda address: " << reinterpret_cast<void*>(&itr->second) << std::endl;

            pcapabvparser::userFunctions[name] = itr->second;
        } // we skip non matches, may be other protocols
        else
        {
            std::cout << "DANGER, itr second is null" << std::endl;
        }
    }

    /*
        //m_functEval.emplace("TCP.Test",  make_lambda_holder([&](const std::vector<int>& params)
        registerUserFunction("TCP.Test",  ([&](const std::vector<int>& params)
        {

            a--;
            std::cout << "Tcp.Test called. Counter is now: " << test1 << " and " << a << "\n";
            return test1++;
        })
                           ); */
    std::cout << "done new lambda" << std::endl;
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
   static std::atomic<uint64_t> pktCnt{0};

   pktCnt++;
   std::cout << pktCnt << "packet streams" << std::endl;
}

PacketStreamEval::~PacketStreamEval()
{
//temporary default, flush buffers
    std::cout << "Packetstream eval deleted" << std::endl;
}
void PacketStreamEval::configurationFiles(std::string configFile) {}
   void PacketStreamEval::setId(const std::string &id) { m_id=id;
   std::cout << "Packet ID:" << m_id << std::endl;
   }
//probably faster to have them register directly, but we need to 'prefill' in all functions to return '0', in case its not supported
void PacketStreamEval::registerProtoFnNames(const std::vector<std::string> &protoFnNames)
{
    std::string protocol, functName;
    std::cout << "protFnNames size is " << protoFnNames.size() << std::endl;
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
                //iter =m_protocolsUsed.insert({"TCP", new protoTcpTrigger()});
                /*auto trigger = std::make_shared<protoTcpTrigger>();

                m_protocolsUsed["TCP"] = trigger;
                trigger->createNameLambda();
                trigger->protoRegister(protoFnNames);*/

                auto trigger = std::make_shared<protoTcpTrigger>();

// Call createNameLambda BEFORE storing in m_protocolsUsed
//trigger->createNameLambda();

// Then store it as base type
//m_protocolsUsed["TCP"] = std::static_pointer_cast<protoTrigger>(trigger);
                m_protocolsUsed["TCP"] = protoTcpTrigger::create(protoFnNames);

                trigger->protoRegister(protoFnNames);
                //iter->second->protoRegister(protoFnNames); //protoLambdaMap


                /*pcapabvparser::registerUserFunction(protoName, [protoName](const std::vector<int> &args)
                {
                    std::cerr << protoName << " is a reimplemented function" << std::endl;
                    return 1;

                });*/
                //iter->second->protoRegister(protoFnNames); //protoLambdaMap
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

        }
        else   //unsupported, should return 0
        {
            std::cerr << "Unsupported protocol in packet stream evaluation:" << protocol << std::endl;
            //exit(1);

        }

        //auto lambda = iter->second.protoRequest(protocol);
        //m_protoLambdaMap.emplace({protoName, iter->second.protoRequest(protocol)});


        //is lamdba valid?
        //LambdaHolder lamContainer(lambda);
    }


}

//COMMENT:
//We may need to
//remember last key
//if key is new, clear (lamba returning 0) existing functions based upon functNames
//    re-register all functions in all proctols, into PacketStreamEval
//Call tree->eval(), mark packet as tagged for interest or save
//add to queue to save (pop any older pre-packets)
//
// To do, add queue lengths for same or different packets-gress (same-gress or different-gress) (extra option as well), and first SYN direction
//
//
//void PacketStreamEval::evaluatePacket(pcap_pkthdr *hdr, uint8_t[] &data, PacketOffsets_t *offsets, ASTPtr &tree) {}
void PacketStreamEval::evaluatePacket(pcap_pkthdr* hdr, uint8_t* data, PacketOffsets_t* offsets, ASTNode * tree)
{

//only needed if we are not on the same packet stream and new
    //registerProtoFnNames(protoFnNames); -- looks incorrect

//protoRegister(lambdaMap &m_functEval);
    //protoRegister(m_protoLambdaMap &m_functEval);
    int result = tree->eval();
    std::cout << "eval=" << result << std::endl;

}
//auto PacketStreamEval::returnProtoFunction(std::string protoFnName) {}
void PacketStreamEval::setSavePacketTrigger(bool) {}
void PacketStreamEval::setSaveStreamTrigger(bool) {}
void PacketStreamEval::flushPacketsToDisk() {}
void PacketStreamEval::transferPacket(std::unique_ptr<pcap_pkthdr> &&header, std::unique_ptr<uint8_t[]> &&data, std::unique_ptr<PacketOffsets_t>  &&pktOffsets)
{
    std::cout << "packet buffer now size " << m_packetHistory.size() << std::endl;
//This should evaluate and save

//save packet
    m_packetHistory.emplace_back(std::move(header), std::move(data));

//check if packet is interesting or to save

//flush prior packets

//calculate how many future packets to save

//flush/erase/drop all packets beyond required size


}

} //end namespace
