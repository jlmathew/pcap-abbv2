#ifndef PCAP_ABBV_CLI_PARSER_H
#define PCAP_ABBV_CLI_PARSER_H

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
#include <tuple>
#include <cstring>

namespace pcapabvparser
{
//using namespace std;

extern std::string version;

 struct globalOptions_t
{
    globalOptions_t() : bufferSizePerTotalFlush(30000000), bufferPacketsBefore(10), bufferPacketsAfter(7), bufferSizePerStreamFlush(30000),
        combinePacketsIntoPcap(false), streamSummary(true), useFileName(false) {} //, printHelp(false) {}
    //deep copy not needed, just shallow copy, so use default
    ~globalOptions_t()=default;
    globalOptions_t(const globalOptions_t &)=default;
    globalOptions_t& operator=(const globalOptions_t &) = default;

    uint64_t bufferSizePerTotalFlush;
    uint32_t bufferPacketsBefore;
    uint32_t bufferPacketsAfter;
    uint32_t bufferSizePerStreamFlush;
    bool combinePacketsIntoPcap;
    bool streamSummary;
    //bool printHelp;
    std::string preName; //pre name for saved pcaps
    std::string pcapPacketOfInterestFilter;
    std::string pcapPacketTriggerToSaveFilter;
    std::string protocolTimeoutConfigFileName;
    std::string inputFileName;
    bool useFileName;
    void printOptions()
    {
        std::cout << "Current Global Options:\n" << "(bufferSizePerTotalFlush):" << bufferSizePerTotalFlush << ", (bufferPacketsBefore):" << bufferPacketsBefore << ",(bufferPacketsAfter):" << bufferPacketsAfter <<
                  ",(bufferSizePerStreamFlush):" << bufferSizePerStreamFlush << ",(combinePacketsIntoPcap):" << (combinePacketsIntoPcap ? "true" : "false") << ",(streamSummary)" << (streamSummary ? "true" : "false") <<
                  ",(preName):" << streamSummary << ",(pcapPacketOfInterestFilter):" << pcapPacketOfInterestFilter << ",(pcapPacketTriggerToSaveFilter):" << pcapPacketTriggerToSaveFilter << ",(protocolTimeoutConfigFileName):" <<
                  protocolTimeoutConfigFileName << std::endl;
    }
} ;

extern globalOptions_t globalOptions;

 void printHelp();



 void printHelp();

    class cli_parser
    {
    public:
        cli_parser();
        cli_parser(int argc, char * options[]);
        virtual ~cli_parser();
        void inputRawOptions(int argc, char*options[]);

        //regular pcap filter for packet filtering
        const std::string  & getPcapFilter() const;
        //pcap abbv filter for tagging packets of interest
        const std::string  & getTagFilter() const ;
        //pcap abbv filter for saving packet streams of interest
        const std::string  & getSaveFilter() const;
        //protocol timeout configuration file
        const std::string & getProtoTimeoutConfigFile() const;
        //print out help
        void printHelp() const;



    protected:
        void setProtoTimeoutConfigFile() const;
    private:
        std::unordered_map<std::string, std::function<void(const char*)> > m_clioptions;
//   std::string m_pcapFilter;
//    std::string m_tagFilter;
//   std::string m_saveFilter;



    };
}
#endif // PCAP_ABBV_CLI_PARSER_H
