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

static std::string version="0.5 alpha";

static struct globalOptions_t
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
} globalOptions;

static void printHelp();

static const std::vector<std::tuple<std::string,std::string,std::string,std::function<void(const char*)> > > helpStrings  =
{
    {
        "--bufferflushsize", "-f","maximum total storage bytes for all streams before flushing", [](const char* arg)
        {
            globalOptions.bufferSizePerTotalFlush = std::stoull(arg);
        }
    },
    {
        "--bufferpacketsizebefore", "-b","number of packets to save before a packet of interest", [](const char* arg)
        {
            globalOptions.bufferPacketsBefore = std::stoul(arg);
        }
    },
    {
        "--bufferpacketsizeafter","-a","number of packets to save, after a packet of interest", [](const char* arg)
        {
            globalOptions.bufferPacketsAfter = std::stoul(arg);
        }
    },
    {
        "--bufferstreamflushsize","-l","maximum total storage bytes per stream before flushing", [](const char* arg)
        {
            globalOptions.bufferSizePerStreamFlush = std::stoul(arg);
        }
    },
    {
        "--singlepcap","-g","boolean value to combine all individual parsed streams into a single pcap", [](const char* arg)
        {
            globalOptions.combinePacketsIntoPcap = (strncmp(arg,"true",4) ? false: true);
        }
    },
    {
        "--streamsummary","-s","boolean ", [](const char* arg)
        {
            globalOptions.streamSummary = (strncmp(arg,"true",4) ? false: true);
        }
    },
    {
        "--prename","-n","packet prepend name", [](const char* arg)
        {
            globalOptions.preName = arg;
        }
    },
    {
        "--tagPacketFilter","-t","pcap abbv filter to match/tag packets of interest", [](const char* arg)
        {
            globalOptions.pcapPacketOfInterestFilter = arg;
        }
    },
    {
        "--protoTimeoutConfig","-c","file name for protocol timeout config file", [](const char* arg)
        {
            globalOptions.protocolTimeoutConfigFileName = arg;
        }
    }, //Need to call parsing fuction
    {
        "--savePacketFilter","-p","pcap abbv filter to match for saving packet streams", [](const char* arg)
        {
            globalOptions.pcapPacketTriggerToSaveFilter = arg;
        }
    },
    {
        "--help","-h","print out help ", [](const char* )
        {
            printHelp();
            globalOptions.printOptions();
            exit (0);
        }
    },
    {
        "--version","-v","version",[](const char *)
        {
            std::cout << "Version:"<< version << std::endl;
            exit (0);
        }
    },
    {
        "--filename","-n","filename to parse",[](const char*arg)
        {
            globalOptions.inputFileName=arg;
            globalOptions.useFileName=true;
        }
    },
    };

    static void printHelp()
    {
        for(auto line : helpStrings)
        {
            std::cout << std::get<0>(line) << "\t" << std::get<1> (line) << " : " << std::get<2>(line) << std::endl;
        }
    };

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
