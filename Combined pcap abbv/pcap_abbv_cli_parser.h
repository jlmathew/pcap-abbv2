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

namespace pcapabvparser
{
//using namespace std;

struct globalOptions {
    uint64_t bufferSizePerTotalFlush;
    uint32_t bufferPacketsBefore;
    uint32_t bufferPacketsAfter;
    uint32_t bufferSizePerStreamFlush;
    bool combinePacketsIntoPcap;
    std::string preName; //pre name for saved pcaps
    std::string protocolTimeoutConfigFileName;
    std::string pcapPacketOfInterestFilter;
    std::string pcapPacketTriggerToSaveFilter;
};


class cli_parser
{
    public:
        cli_parser();
        cli_parser(int argc, char * options[]);
        virtual ~cli_parser();
        void inputRawOptions(int argc, char*options[]);
        globalOptions & getGlobalOptions();
        //regular pcap filter for packet filtering
        std::string & getPcapFilter();
        //pcap abbv filter for tagging packets of interest
        std::string & getPcapAbvTagFilter();
        //pcap abbv filter for saving packet streams of interest
        std::string & getPcapAbvSaveFilter();
    protected:

    private:
};
}
#endif // PCAP_ABBV_CLI_PARSER_H
