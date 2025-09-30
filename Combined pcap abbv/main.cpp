#include <iostream>
#include "pcapparser.h"
#include "pcap_abbv_cli_parser.h"
#include <chrono>

//using namespace std;
//using namespace pcapabvparser;

// ===== Main Function =====



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
        "fn3(0) > 8", // true
        "fn3() == 9", //true
        "!(fn3() == 9)", //false
        "!(fn3() == 8)", //true
        "fn3() != fn1(9) OR fn2(3) == fn1(3)",
        "(!fn3()) == 8",  //false,
        "fn4(3,4)",
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
            pcapabvparser::registerUserFunction("fn4", [](std::vector<int> args)
            {
                return args.empty() ? 0 : args [0] < args[1];
            });

            pcapabvparser::registerUserFunction("isEven", [](std::vector<int> args)
            {
                return args[0] % 2 == 0;
            });

            pcapabvparser::registerUserFunction("isPositive", [](std::vector<int> args)
            {

                std::cout << args[0] << " should be positive\n";
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



int main(int argc, char *argv[])
{
    test1();


    //string parse options
    //pcapabvparser::
    //FnParser parser("TCP.HS()");
    //STPtr tree = parser.parse();
    //pcapabvparser::parseCliOptions(argc, argv);


    //parse protocol options
    //std::cout << "tag filter:" << parseCliOptions.getTagFilter() << std::endl;
    //auto tokens = tokenize(parseCliOptions.getTagFilter());



    //get 'packet of interest' and 'packet stream to save' filters

    //create threads (based upon global options) to handle packets
    //create signal capture in each thread, if killed or cntrl-c, each thread flushes

    //loop for packet captures

    //create key for packet
    //optimize for int, not string (too long)

    //create new 'packetstream',otherwise hash packetstream into a thread
    //queue packet into fifo per thread


    return 0;
}
