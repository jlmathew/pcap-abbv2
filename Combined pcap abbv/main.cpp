#include <iostream>
#include "pcapparser.h"
#include "pcap_abbv_cli_parser.h"
#include <chrono>
#include <pcap/pcap.h>
#include "nonblockingbuffers.h"
#include "pcapkey.h"
#include <random>


    #include <unistd.h>
#include <limits.h>
#include <dirent.h>


//using namespace std;
using namespace pcapabvparser;

// ===== Main Function =====


/*
int test1()
{
    std::vector<std::string> testInputs =
    {
        "isEven(4)",                             // true
        "isEven(5)",                             // false
        "!isPositive(-3)",                       // true
        "isPositive(5)",                         // true
        "alwaysTrue() AND alwaysFalse()",        // false
        "alwaysTrue() OR alwaysFalse()",         // true
        "(fn1(5) == 5) AND (fn2(3) < 10)",        // true
        "fn3() > 7 AND !isEven(3)",              // true
        "fn3() >= 9 AND (isPositive(1) OR isEven(1))",  // true
        "(fn3() >= 9) AND (isPositive(1) OR isEven(1))",  // true
        "((fn1(1) == 1) AND ((fn2(2) < 10) OR (!(fn3() < 5))))", //true
        "((fn1(1) == 1) AND (fn2(2) < 10) OR (!(fn3() < 5)))", //true
        "(fn3() == 9)", //true
        "(fn3() == -9)", //true
        "fn3(0) > 8", // true
        "fn3() == 9", //true
        "!(fn3() == 9)", //false
        "!(fn3() == 8)", //true
        "fn3() != fn1(9) OR fn2(3) == fn1(3)",
        "(!fn3()) == 8",  //false,
        "fn4.fn(3,4)",
        "(((fn3())) == 8)" //false
    };


    using namespace pcapabvparser;

    for (const auto& input : testInputs)
    {
        //cout << "Input: " << input << endl;
        try
        {
            pcapabvparser::FnParser parser(input);
            pcapabvparser::ASTPtr tree = parser.parse();

            //example on adding function registerys (should be via object funct call
            pcapabvparser::registerUserFunction("fn1", [](std::vector<int> args)
            {
                return args.empty() ? 0 : args[0];
            });

            pcapabvparser::registerUserFunction("fn2", [](std::vector<int> args)
            {
                return args.empty() ? 0 : args[0];
            });

            pcapabvparser::registerUserFunction("fn3", [](std::vector<int>)
            {
                return 9;
            });
            pcapabvparser::registerUserFunction("fn4.fn", [](std::vector<int> args)
            {
                return args.empty() ? 0 : args [0] < args[1];
            });

            pcapabvparser::registerUserFunction("isEven", [](std::vector<int> args)
            {
                return args[0] % 2 == 0;
            });

            pcapabvparser::registerUserFunction("isPositive", [](std::vector<int> args)
            {

                return args[0] > 0;
            });


            pcapabvparser::registerUserFunction("alwaysTrue", [](std::vector<int>)
            {
                return 1;
            });


            pcapabvparser::registerUserFunction("alwaysFalse",  [](std::vector<int>)
            {
                return 0;
            });


            std::cout << "-----------------------------" << std::endl;

            std::cout << "Result (" << input << "): " << tree->eval() << std::endl; //true

        }
        catch (const std::exception& e)
        {
            std::cerr << "Tokenize Error: " << e.what() << std::endl;
        }

    }
    return 0;
}


*/
//hash function for packet key
struct VectorHash
{
    std::size_t operator()(const std::vector<uint8_t>& vec) const
    {
        // Treat the vector's data as a string_view over raw bytes
        std::string_view view(reinterpret_cast<const char*>(vec.data()), vec.size());
        return std::hash<std::string_view> {}(view);
    }
};




namespace Errors
{
// Define an enum within the namespace
enum PcapErrorType
{
    NOERROR,
    BAD_FILEDESCRIPTOR_OPEN,
    BAD_FILE_OPEN,
    INVALID_PCAP_INPUT_OPTION,
    FAILURE

};

}

//nned to capture signals (cntrl c, kill ...) and flush all pcap evaluators

int main(int argc, char *argv[])
{
    //test1();

//sudo apt install libpcap-dev

    //string parse options

    pcapabvparser::cli_parser parseCliOptions(argc, argv);


    //parse protocol options
    std::cout << "tag filter:" << parseCliOptions.getTagFilter() << std::endl;

    //same data filtering, but the actual functions are thread specified.
    pcapabvparser::FnParser parser(parseCliOptions.getTagFilter());
    auto tree = parser.parse();

    std::vector<std::string> functionNames;
    pcapabvparser::getFnNames(tree.get(), functionNames );

    int cnt=0;
    for(const auto &name : functionNames)
    {
        cnt++;
        std::cout << "function:" << name << std::endl;
        //quick registeration to avoid crash on eval(), the value should be replaced
        pcapabvparser::registerUserFunction(name, [name](std::vector<int> args)
        {
            std::cerr << name << " is NOT defined" << std::endl;
            return 0;

        });
    }

    //std::cout << "Result: " << tree->eval() << std::endl; //false

    //get 'packet of interest' and 'packet stream to save' filters

    //variables being used
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcapInputStream = nullptr;
    int layer2Proto=0;
    const u_char *packetData;
    struct pcap_pkthdr *pktHeader;
    int resultTimeout=0;





    if (!pcapabvparser::globalOptions.useFileName)   //default is input via stdin
    {
        pcapInputStream = pcap_fopen_offline(stdin, errbuf); //reversed?

        if (nullptr == pcapInputStream)
        {
            std::cerr << "Error: Unable to open input stream" << errbuf << std::endl;
            return Errors::BAD_FILEDESCRIPTOR_OPEN;
        }


    }
    else      // Open the file for reading, get file descriptor
    {
        //pcapInputStream = pcap_open_offline(pcapabvparser::globalOptions.inputFileName.c_str(), errbuf);
        pcapInputStream = pcap_open_offline("test.pcap", errbuf);
        if (nullptr == pcapInputStream)
        {
            std::cerr << "Error: Unable to open file " << pcapabvparser::globalOptions.inputFileName << std::endl;
            return Errors::BAD_FILE_OPEN;
        }

    }
    layer2Proto = pcap_datalink(pcapInputStream);


    //setup non block buffers and threaded child packet processing application
        const size_t BUFFER_SIZE = 256;
    const size_t numConsumers=4;


    std::vector< std::shared_ptr< NonBlockingCircularBuffer<std::unique_ptr<pktBufferData_t>, BUFFER_SIZE > > > nb_buffers;
    nb_buffers.reserve(numConsumers);
    for (size_t i = 0; i < numConsumers; ++i)
    {
        nb_buffers.emplace_back(std::make_shared<NonBlockingCircularBuffer<std::unique_ptr<pktBufferData_t>, BUFFER_SIZE>>());
    }


    std::atomic<bool> consumersReady{false}; //ensure all consumer threads are ready before processing
    std::vector<std::thread> packetDataProccesors;
    for (size_t i = 0; i < numConsumers; ++i)
    {
        packetDataProccesors.emplace_back([i, &nb_buffers, &consumersReady]()
        {
            while (!consumersReady.load(std::memory_order_acquire))
            {
                std::this_thread::yield();
            }
            consumer_pcap_process_thread(i, nb_buffers[i]);
        });
    }

//test
    consumersReady.store(true, std::memory_order_release);

    //find the current location

/*
    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd)) != nullptr) {
        std::cout << "Current working directory: " << cwd << std::endl;
    } else {
        perror("getcwd() error");
    }
     DIR* dir = opendir(".");
    if (dir == nullptr) {
        perror("opendir");
        return 1;
    }

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        std::cout << entry->d_name << std::endl;
    }

    closedir(dir);
*/

//loop over all packets


    //this function blocks
    uint64_t counter=0;
    while((resultTimeout = pcap_next_ex( pcapInputStream, &pktHeader, &packetData)) >= 0)
    {
    counter++;
        if(resultTimeout == 0)
            // Timeout elapsed
            continue;

        //get copies for smart pointers
        // Copy header and packet data into unique_ptrs
        auto headerCopy = std::make_unique<pcap_pkthdr>(*pktHeader);

        auto packetCopy = std::unique_ptr<uint8_t[]>(new uint8_t[pktHeader->caplen]);
        std::memcpy(packetCopy.get(), packetData, pktHeader->caplen);



        //auto offsets = std::make_unique<pktBufferData_t>();

        //auto key = parse_packet(packetCopy, headerCopy, offsets);
        auto [key,offsets] = parse_packet( packetData,  pktHeader);

        //dont process invalid packets
        if (key->size()==0) { continue;}
        //create new 'packetstream',otherwise hash key into a thread
        //queue packet into fifo per thread
        VectorHash hasher;
        size_t target = hasher(*key) % numConsumers;
print_key(*key);
        //push informationation onto correct queue
        auto queueData = std::make_unique<pktBufferData_t>(std::move(headerCopy),std::move(packetCopy),std::move(offsets), std::move(key),target);
        //while (!nb_buffers[i]->push(testData)) {
        std::cout << "[COUNTER COUNT]=" << counter << std::endl;
        nb_buffers[target]->push(std::move(queueData));

    }


    for (auto& t : packetDataProccesors) t.detach();
    return 0;
}

