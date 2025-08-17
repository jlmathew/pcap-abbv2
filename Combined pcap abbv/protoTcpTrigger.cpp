#include "protoTcpTrigger.h"

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

protoTcpTrigger::protoTcpTrigger(packetLayerHelper_t *packetLayerHelper) {
   protoTrigger::setRawPacket(packetLayerHelper);
}

Func protoTcpTrigger::protoRequest(std::string &functName)
{

    auto it = m_functEval.find(functName);
    if (it != m_functEval.end()) {
        return it->second; // Call the associated function
    } else {
        return 0;
    }
}
//auto lambdaFunc = [&g](const std::string& name) {g.greet(name);};

void protoTcpTrigger::createNameLambda(){

m_functEval.emplace("SYNONLY_CNT",
            [helper = this->m_packetLayerHelper](std::vector<int> params) -> int {
                // Example logic using captured helper
                int sum = 0;
                for (int val : params) {
                    sum += val;
                }
                return sum + *helper;
            }
        );
m_functEval.emplace("Handshake",
            [helper = this->m_packetLayerHelper](std::vector<int> params) -> int {
                // Example logic using captured helper
return 0;
            }
        );
        m_functEval.emplace("RST_CNT",
            [helper = this->m_packetLayerHelper](std::vector<int> params) -> int {
                // Example logic using captured helper
return 0;
            }
        );
}
