#include "pcap_abbv_cli_parser.h"

namespace pcapabvparser
{

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

//        std::cout << "\noption:" << arg;

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
                std::cout << "(debug) " << arg << "=" << value <<std::endl;
                //help?

            }
            else
            {
                std::cerr << "Unknown parameter: " << arg << std::endl;
            }
//            std::cout << " [" << value << "],";
            //m_clioptions[arg] = value;
        }
        if (globalOptions.printHelp)
        {
            printHelp();
        }

    }
    //parse into actual options


}



//regular pcap filter for packet filtering
std::string  cli_parser::getPcapFilter()
{
    return globalOptions.pcapPacketTriggerToSaveFilter;
}

//pcap abbv filter for tagging packets of interest
std::string  cli_parser::getTagFilter()
{
    return globalOptions.pcapPacketOfInterestFilter;
}

//pcap abbv filter for saving packet streams of interest
std::string  cli_parser::getSaveFilter()
{

}


void cli_parser::setProtoTimeoutConfigFile()
{
//globalOptions.protocolTimeoutConfigFileName
}

//print help
void cli_parser::printHelp()
{
    std::cout << "Pcap Abbreviation CLI options:" <<  std::endl;
    for (const auto cliLine : helpStrings)
    {
        std::cout << "  "  << std::get<0>(cliLine) << " " << std::get<1>(cliLine) << " " << std::get<2>(cliLine) << std::endl;
    }
}
}  //end of namespace
