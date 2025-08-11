#ifndef __PROTOTCPTRIGGER_H__
#define __PROTOTCPTRIGGER_H__

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

//only test/placeholder
#define packetLayerHelper_t int


using Func = std::function<int(std::vector<int>)>;

/** Registered functions that can be invoked in expressions */
//std::unordered_map<std::string, Func> functionRegistry;

class protoTrigger
{
protected:
   protoTrigger();
   protoTrigger(packetLayerHelper_t *helper);
   void setRawPacket(packetLayerHelper_t *packetLayerHelper);
   virtual ~protoTrigger();
   protoTrigger(const protoTrigger &other);
   protoTrigger& operator=(const protoTrigger & other);
   Func protoRequest(std::string &functName);
   protected:
   std::unordered_map<std::string, Func> m_functEval;
   packetLayerHelper_t *m_packetLayerHelper;
   public:

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

#endif // __PROTOTCPTRIGGER_H__
