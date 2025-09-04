#include <iostream>
#include "parser.h"

using namespace std;
using namespace pcapabvparser;

// ===== Main Function =====



int test1()
{
    vector<string> testInputs =
    {
        "isEven(4)",                             // true
        "isEven(5)",                             // false
        "!isPositive(-3)",                       // true
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
            Parser parser(tokens);


            //example on adding function registerys (should be via object funct call
            parser.addFunct("fn1", [](vector<int> args)
            {
                return args.empty() ? 0 : args[0];
            });

            parser.addFunct("fn2", [](vector<int> args)
            {
                return args.empty() ? 0 : args[0];
            });

            parser.addFunct("fn3", [](vector<int>)
            {
                return 9;
            });
            parser.addFunct("fn4", [](vector<int> args)
            {
                return args.empty() ? 0 : args [0] < args[1];
            });

            parser.addFunct("isEven", [](vector<int> args)
            {
                return args[0] % 2 == 0;
            });

            parser.addFunct("isPositive", [](vector<int> args)
            {
                return args[0] > 0;
            });


            parser.addFunct("alwaysTrue", [](vector<int>)
            {
                return 1;
            });


            parser.addFunct("alwaysFalse",  [](vector<int>)
            {
                return 0;
            });

            AST ast = parser.parse();
            AST ast2 = ast; // make a copy
            bool result = ast->evaluate();
            cout << "Result " << input << ": " << boolalpha << result << endl;
            //cout << "Result2: " << std::boolalpha << ast2->evaluate() << endl;
        }
        catch (const exception& e)
        {
            cerr << "Tokenize Error: " << e.what() << endl;
        }
        cout << "-----------------------------" << endl;
    }

    return 0;
}

int timer(const AST ast) {
    // Start timer
    auto start = std::chrono::high_resolution_clock::now();

    // Call the function
    for(int i=0; i<1000000; i++)
    {  AST ast2 = ast->clone();
    }

    // Stop timer
    auto end = std::chrono::high_resolution_clock::now();

    // Calculate duration
    std::chrono::duration<double, std::milli> duration = end - start;

    std::cout << "doWork() took " << duration.count() << " ms" << std::endl;
}

void test2()
{
    vector<string> testInputs =
    {
        "(!TCP.SYNONLY_CNT() ==2 AND TCP.Handshake()) OR TCP.RST_CNT() > 0 OR IPv4.WindowSizeCnt()==0 OR TCP.IllegalFlagCnt() > 0"                             // true

    };
    //test 3 packets
    for (const auto& input : testInputs)
    {
        //cout << "Input: " << input << endl;
        try
        {
            auto tokens = tokenize(input);
            Parser parser(tokens);
            //loop for each new packet sources
            //for (const auto& name : parser.m_functionNameCache ) {
//std::cout << "functions: " << name << std::endl;
//}
            //now link to to packet evaluator for each stream

            //parse with packet links
            AST ast = parser.parse();
//
            for (const auto& name : parser.m_functionNameCache )
            {
                //for (const auto& name : parser.m_functionRegistry ) {
                std::cout << "show functions: " << name << std::endl;
            }

//            timer(ast);

            AST ast2 = ast->clone();

            std::cout << "ast addr " << ast << ", ast2 addr " << ast2 << std::endl;

//test if ast only changes
            ast2->addFunct("TCP.SYNONLY_CNT", [](vector<int>)
            {
                return 2;
            });
            ast2->addFunct("TCP.Handshake", [](vector<int>)
            {
                return 0;
            });
            //evaluate different packets
            bool result = ast->evaluate();

            //test functions


            //test
            bool result2 = ast2->evaluate();
            cout << "Result " << input << ": " << boolalpha << result << endl;
            cout << "Result " << input << ": " << boolalpha << result2 << endl;
        }
        catch (const exception& e)
        {
            cerr << "Tokenize Error: " << e.what() << endl;
        }
        cout << "-----------------------------" << endl;

    }
}



int main()
{
    test1();
    test2();
    return 0;
}
