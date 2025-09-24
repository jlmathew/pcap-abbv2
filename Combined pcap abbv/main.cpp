#include <iostream>
#include "pcapparser.h"
#include "pcap_abbv_cli_parser.h"


//using namespace std;
using namespace pcapabvparser;

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




    for (const auto& input : testInputs)
    {
        //cout << "Input: " << input << endl;
        try
        {
            auto tokens = tokenize(input);
            /*for (const auto& name : tokens )
            {
                if (name.type==TOKEN_FUNC) {
                std::cout << "TOkens(" << int(name.type) << "): " << name.value << std::endl; }
            }*/

            Parser parser(tokens);
            auto fnNameList2 = parser.getFunctionNames();
            //loop for each new packet sources
            /*for (auto cit=fnNameList2.begin(); cit!=fnNameList2.end(); cit++ )
            {
                std::cout << "parser functions: " << *cit << std::endl;
            }*/

            //example on adding function registerys (should be via object funct call
            parser.addFunct("fn1", [](std::vector<int> args)
            {
                return args.empty() ? 0 : args[0];
            });

            parser.addFunct("fn2", [](std::vector<int> args)
            {
                return args.empty() ? 0 : args[0];
            });

            parser.addFunct("fn3", [](std::vector<int>)
            {
                return 9;
            });
            parser.addFunct("fn4", [](std::vector<int> args)
            {
                return args.empty() ? 0 : args [0] < args[1];
            });

            parser.addFunct("isEven", [](std::vector<int> args)
            {
                return args[0] % 2 == 0;
            });

            parser.addFunct("isPositive", [](std::vector<int> args)
            {
                return args[0] > 0;
            });


            parser.addFunct("alwaysTrue", [](std::vector<int>)
            {
                return 1;
            });


            parser.addFunct("alwaysFalse",  [](std::vector<int>)
            {
                return 0;
            });

            AST ast = parser.parse();
            AST ast2 = ast->clone(); // make a copy
            ast2->addFunct("isPositive", [](std::vector<int> args)
            {
                return args[0] < 1;
            });

            bool result = ast->evaluate();
            std::cout << "Result " << input << ": " << std::boolalpha << result << std::endl;
            std::cout << "Result2: " << input << ": " << std::boolalpha << ast2->evaluate() << std::endl;
        }
        catch (const std::exception& e)
        {
            std::cerr << "Tokenize Error: " << e.what() << std::endl;
        }
        std::cout << "-----------------------------" << std::endl;
    }

    return 0;
}

void timer(const AST ast)
{
    // Start timer
    auto start = std::chrono::high_resolution_clock::now();

    // Call the function
    for(int i=0; i<1000000; i++)
    {
        AST ast2 = ast->clone();
    }

    // Stop timer
    auto end = std::chrono::high_resolution_clock::now();

    // Calculate duration
    std::chrono::duration<double, std::milli> duration = end - start;

    std::cout << "doWork() took " << duration.count() << " ms" << std::endl;
}

void test2()
{
    std::vector<std::string> testInputs =
    {
        //"(!TCP.SYNONLY_CNT() ==2 AND TCP.Handshake()) OR TCP.RST_CNT() > 0 OR IPv4.WindowSizeCnt()==0 OR TCP.IllegalFlagCnt() > 0",                             // true
        "TCP.SYNONLY_CNT() == 2" ,
    };
    //test 3 packets
    for (const auto& input : testInputs)
    {
        try
        {
            auto tokens = tokenize(input);
            /*for (const auto& name : tokens )
            {
                if (TOKEN_FUNC==name.type ) {
                std::cout << "TOkens(" << int(name.type) << "): " << name.value << std::endl;
                }
            }*/

            Parser parser(tokens);
            auto fnNameList2 = parser.getFunctionNames();
            //loop for each new packet sources
            /*for ( auto& name : fnNameList2 )
            {
                std::cout << "functions2: " << name << std::endl;
            }*/
            //now link to to packet evaluator for each stream


            /*for (const auto& name : fnNameList4 )
            {
                std::cout << "functions3: " << name << std::endl;
            }*/



            //timer(ast);


            parser.addFunct("TCP.SYNONLY_CNT", [](std::vector<int>)
            {
                std::cout << "parser original synonly" << std::endl; return 2;
            });
 /*           parser.addFunct("TCP.Handshake", [](std::vector<int>)
            {
                return 1;
            });
            parser.addFunct("TCP.RST_CNT", [](std::vector<int>)
            {
                return 1;
            });
            parser.addFunct("IPv4.WindowSizeCnt", [](std::vector<int>)
            {
                return 0;
            });
            parser.addFunct("TCP.IllegalFlagCnt", [](std::vector<int>)
            {
                return 1;
            });
*/

std::cout << "pre-parser" << std::endl;
            //parse with packet links
            AST ast = parser.parse();
            //auto fnNameList = parser.getFunctionNames();
            //auto fnNameList3 = ast->getFunctionMap();
            //auto fnNameList4 = parser.getFunctionNames();

            //evaluate different packets
std::cout << "pre-evaluate" << std::endl;
            bool result = ast->evaluate();
            std::cout << "post-evaluate" << std::endl;
            //test functions
//AST ast2 = ast->clone();

            //std::cout << "ast addr " << ast << ", ast2 addr " << ast2 << std::endl;

//test if ast only changes
            /*parser.addFunct("TCP.SYNONLY_CNT", [](std::vector<int>)
            {
                std::cout << "parser update synonly" << std::endl;return 0;
            });*/

            parser.addFunct("TCP.SYNONLY_CNT", [](std::vector<int>)
            {
                std::cout << "mod  synonly" << std::endl; return 1;
            });
            ast->addFunct("TCP.SYNONLY_CNT", [](std::vector<int>)
            {
                std::cout << "ast update synonly" << std::endl;return 0;
            });

            /*ast2->addFunct("TCP.SYNONLY_CNT", [](std::vector<int>)
            {
                std::cout << "ast2 update synonly" << std::endl;return 0;
            });*/

            //bool result2 = ast2->evaluate();

            std::cout << "Result1 " << input << ": " << std::boolalpha << result << " address: " << ast <<std::endl;
            //std::cout << "Result2 " << input << ": " << std::boolalpha << result2 << std::endl;
            bool result3 = ast->evaluate();
            std::cout << "Result3 " << input << ": " << std::boolalpha << result3 << " address: " << ast << std::endl;

            AST ast2 = parser.parse();
            bool result2 = ast2->evaluate();
            std::cout << "Result2 " << input << ": " << std::boolalpha << result2 << " address: " << ast2 << std::endl;

        }
        catch (const std::exception& e)
        {
            std::cerr << "Tokenize Error: " << e.what() << std::endl;
        }
        std::cout << "-----------------------------" << std::endl;

    }
}



int main(int argc, char *argv[])
{
 //   test1();
    test2();

    //string parse options
    pcapabvparser::cli_parser parseCliOptions(argc, argv);


    //parse protocol options
    std::cout << "tag filter:" << parseCliOptions.getTagFilter() << std::endl;
    auto tokens = tokenize(parseCliOptions.getTagFilter());
    /*for (const auto& name : tokens )
    { if (TOKEN_FUNC==name.type) {
        std::cout << "TOkens(" << int(name.type) << "): " << name.value << std::endl; }
    }*/

    Parser parser(tokens);
    auto fnNameList2 = parser.getFunctionNames();
    //loop for each new packet sources
    for (const auto &name : fnNameList2 )
    {
        std::cout << "functions2: " << name << std::endl;
    }


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
