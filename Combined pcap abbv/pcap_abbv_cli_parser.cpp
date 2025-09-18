#include "pcap_abbv_cli_parser.h"

namespace pcapabvparser
{
cli_parser::cli_parser()
{
    //ctor
}
cli_parser::cli_parser(int argc, char * options[]) {
   inputRawOptions(argc,options);
}

cli_parser::~cli_parser()
{
    //dtor
}

void cli_parser::inputRawOptions(int argc, char*options[])
{

}

//parse global options
globalOptions & cli_parser::getGlobalOptions() {
}

//regular pcap filter for packet filtering
std::string & cli_parser::getPcapFilter() {
}

//pcap abbv filter for tagging packets of interest
std::string & cli_parser::getPcapAbvTagFilter() {
}

//pcap abbv filter for saving packet streams of interest
std::string & cli_parser::getPcapAbvSaveFilter() {
}

}  //end of namespace
