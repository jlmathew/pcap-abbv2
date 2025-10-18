#include "pcap_abbv_cli_parser.h"

namespace pcapabvparser
{

 std::string version="0.5 alpha";
struct globalOptions_t globalOptions;

const std::vector<std::tuple<std::string,std::string,std::string,std::function<void(const char*)> > > helpStrings  =
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


cli_parser::cli_parser()
{
    //ctor
}
cli_parser::cli_parser(int argc, char * options[])
{
    inputRawOptions(argc,options);
}

cli_parser::~cli_parser()
{
    //dtor
}

void cli_parser::inputRawOptions(int argc, char*argv[])
{
//parse static options into a map
    for(auto line : helpStrings)
    {
        m_clioptions[std::get<0>(line) ]= std::get<3>(line);
        m_clioptions[std::get<1>(line)] =std::get<3>(line);
    }
//parse actual CLI using map
    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];

        // Check if it's an option (starts with -- or -)
        if (arg.rfind("--", 0) == 0 || arg.rfind("-", 0) == 0)
        {
            std::string value;

            // Check if next argument exists and is not another option
            if (i + 1 < argc && argv[i + 1][0] != '-')
            {
                value = argv[++i];
            }
            else
            {
                value = "true"; // flag-style option
            }
            //use map to parse global options
            auto it = m_clioptions.find(arg);
            if (it != m_clioptions.end() )
            {
                it->second(value.c_str());

            }
            else
            {
                std::cerr << "Unknown parameter: " << arg << std::endl;
            }

        }


    }

}

    void printHelp()
    {
        for(auto line : helpStrings)
        {
            std::cout << std::get<0>(line) << "\t" << std::get<1> (line) << " : " << std::get<2>(line) << std::endl;
        }
    };

//regular pcap filter for packet filtering
const std::string & cli_parser::getPcapFilter() const
{
    return globalOptions.pcapPacketTriggerToSaveFilter;
}

//pcap abbv filter for tagging packets of interest
const std::string & cli_parser::getTagFilter() const
{
    return globalOptions.pcapPacketOfInterestFilter;
}

//pcap abbv filter for saving packet streams of interest
const std::string & cli_parser::getSaveFilter() const
{
  return "";
}


void cli_parser::setProtoTimeoutConfigFile() const
{
//globalOptions.protocolTimeoutConfigFileName
}

//print help
/*void cli_parser::printHelp()
{
    std::cout << "Pcap Abbreviation CLI options:" <<  std::endl;
    for (const auto cliLine : helpStrings)
    {
        std::cout << "  "  << std::get<0>(cliLine) << " " << std::get<1>(cliLine) << " " << std::get<2>(cliLine) << std::endl;
    }
    exit(0);
} */
}  //end of namespace
