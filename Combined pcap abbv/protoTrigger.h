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

//#include "parser.h"
namespace pcapabvparser
{
//only test/placeholder
using packetLayerHelper_t = int;

using Func = std::function<int(std::vector<int>)>;

/** Registered functions that can be invoked in expressions */
//std::unordered_map<std::string, Func> functionRegistry;

class protoTrigger
{
protected:
std::string m_myId;
uint16_t m_protocolNumber;
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

class TriggerGen
{
   public:
   TriggerGen();
   virtual ~TriggerGen();
   protoTrigger * getProtocol(const std::string &protoName);
};


}
#endif // __PROTOTRIGGER_H__
