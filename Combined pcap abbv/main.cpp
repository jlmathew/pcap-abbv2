#include <iostream>
#include "pcapparser.h"
#include "pcap_abbv_cli_parser.h"
#include <chrono>
#include <pcap/pcap.h>
#include "nonblockingbuffers.h"
#include "pcapkey.h"

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

void timer(const pcapabvparser::ASTPtr ast)
{
    // Start timer
    auto start = std::chrono::high_resolution_clock::now();

    // Call the function
    for(int i=0; i<1000000; i++)
    {
//ASTPtr
    }

    // Stop timer
    auto end = std::chrono::high_resolution_clock::now();

    // Calculate duration
    std::chrono::duration<double, std::milli> duration = end - start;

    std::cout << "doWork() took " << duration.count() << " ms" << std::endl;
}

*/



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


int main(int argc, char *argv[])
{
    //test1();


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
    //using packetProcessingData_t = std::tuple<const u_char *, struct pcap_pkthdr *, std::vector<char>  >;
    //struct pcap_pkthdr* header;
    //const u_char* packet;

    //create threads (based upon global options) to handle packets
    //create signal capture in each thread, if killed or cntrl-c, each thread flushes
    //pass to thread, pcap_pkthdr, packetdata, pcap proto layer help, pcap key


    // constexpr uint32_t bufferSize=sizeof(pktBufferData_t);
//constexpr size_t BUFFER_SIZE = 256;
//constexpr size_t numConsumers=4;
    const size_t BUFFER_SIZE = 256;
    const size_t numConsumers=4;
    //NonBlockingCircularBuffer<pktBufferData_t, BUFFER_SIZE> nb_buffers[numConsumers];
    //auto nb_buffers = new NonBlockingCircularBuffer<pktBufferData_t, BUFFER_SIZE> nb_buffers[numConsumers];
    std::shared_ptr<NonBlockingCircularBuffer<pktBufferData_t, BUFFER_SIZE>[]> nb_buffers(new NonBlockingCircularBuffer<pktBufferData_t, BUFFER_SIZE>[numConsumers]);



    std::vector<std::thread> packetDataProccesors;
    for (size_t i = 0; i < NUM_CONSUMERS; ++i)
    {
        /*packetDataProccesors.emplace_back([i, &nb_buffers]()
        {
            consumer_pcap_process_thread(i, &nb_buffers[i]);
        });*/
    }



    //  while (messages_processed.load(std::memory_order_relaxed) < NUM_MESSAGES)
//   {
    //std::this_thread::sleep_for(std::chrono::milliseconds(10));
//   }


    //loop for packet captures


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
        pcapInputStream = pcap_open_offline(pcapabvparser::globalOptions.inputFileName.c_str(), errbuf);
        if (nullptr == pcapInputStream)
        {
            std::cerr << "Error: Unable to open file " << pcapabvparser::globalOptions.inputFileName << std::endl;
            return Errors::BAD_FILE_OPEN;
        }
        ;
    }
    layer2Proto = pcap_datalink(pcapInputStream);


//loop over all packets

    //std::map<std::string, PacketInspector_t *> packetsOfInterest;
    //PacketInspector_t * packetFollower;


    //this function blocks
    while((resultTimeout = pcap_next_ex( pcapInputStream, &pktHeader, &packetData)) >= 0)
    {
        if(resultTimeout == 0)
            // Timeout elapsed
            continue;

            //get copies for smart pointers
            // Copy header and packet data into unique_ptrs
        auto headerCopy = std::make_unique<pcap_pkthdr>(*pktHeader);

        auto packetCopy = std::unique_ptr<uint8_t[]>(new uint8_t[pktHeader->caplen]);
        std::memcpy(packetCopy.get(), packetData, pktHeader->caplen);



         auto offsets = std::make_unique<PacketOffsets_t>();
        auto key = parse_packet(packetCopy, headerCopy, offsets);

        //create new 'packetstream',otherwise hash key into a thread
        //queue packet into fifo per thread
        //size_t target = hasher(key) % NUM_CONSUMERS;
    }

   // for (auto& t : consumer_pcap_process_thread) t.detach();
    return 0;
}

