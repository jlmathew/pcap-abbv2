#ifndef __pcap_abbv_parser_h__
#define __pcap_abbv_parser_h__




//#include <sstream>
#include <string>
#include <unordered_map>
#include <functional>
#include <vector>
#include <memory>
#include <thread>
#include <cctype>

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <functional>
#include <memory>
#include <thread>
#include <stdexcept>
#include <cctype>

namespace pcapabvparser {
// Token types
enum class TokenType { IDENT, NUMBER, OP, LPAREN, RPAREN, COMMA, END };

// Token structure
struct Token
{
    TokenType type;
    std::string value;
};

// Tokenizer
class Tokenizer
{
    std::string input;
    size_t pos = 0;

public:
    Tokenizer(const std::string& str) : input(str) {}

    Token next()
    {
        while (pos < input.size() && isspace(input[pos])) ++pos;
        if (pos >= input.size()) return {TokenType::END, ""};

        char ch = input[pos];
        if (isdigit(ch))
        {
            size_t start = pos;
            while (pos < input.size() && isdigit(input[pos])) ++pos;
            return {TokenType::NUMBER, input.substr(start, pos - start)};
        }

        if (isalpha(ch))
        {
            size_t start = pos;
            while (pos < input.size() && (isalnum(input[pos]) || input[pos] == '.')) ++pos;
            std::string word = input.substr(start, pos - start);
            if (word == "AND" || word == "OR") return {TokenType::OP, word};
            return {TokenType::IDENT, word};
        }

        if (ch == '(') return ++pos, Token{TokenType::LPAREN, "("};
        if (ch == ')') return ++pos, Token{TokenType::RPAREN, ")"};
        if (ch == ',') return ++pos, Token{TokenType::COMMA, ","};

        if (ch == '=' || ch == '!' || ch == '<' || ch == '>')
        {
            std::string op(1, ch);
            ++pos;
            if (pos < input.size() && input[pos] == '=')
            {
                op += input[pos++];
            }
            return {TokenType::OP, op};
        }

        throw std::runtime_error("Unknown character: " + std::string(1, ch));
    }
};

// AST Node
struct ASTNode
{
    virtual int eval() const = 0;
    virtual ~ASTNode() = default;
};

using ASTPtr = std::unique_ptr<ASTNode>;

// Thread-local user function registry
thread_local std::map<std::string, std::function<int(const std::vector<int>&)>> userFunctions;

// Function call node
struct FuncCallNode : ASTNode
{
    std::string name;
    std::vector<ASTPtr> args;

    FuncCallNode(std::string n, std::vector<ASTPtr> a) : name(std::move(n)), args(std::move(a)) {}

    int eval() const override
    {
        std::vector<int> evaluatedArgs;
        for (const auto& arg : args) evaluatedArgs.push_back(arg->eval());
        auto it = userFunctions.find(name);
        if (it == userFunctions.end()) throw std::runtime_error("Unknown function: " + name);
        return it->second(evaluatedArgs);
    }
};

// Constant node
struct ConstNode : ASTNode
{
    int value;
    ConstNode(int v) : value(v) {}
    int eval() const override
    {
        return value;
    }
};

// Unary node
struct UnaryNode : ASTNode
{
    std::string op;
    ASTPtr operand;
    UnaryNode(std::string o, ASTPtr e) : op(std::move(o)), operand(std::move(e)) {}

    int eval() const override
    {
        if (op == "!") return !operand->eval();
        throw std::runtime_error("Unknown unary operator: " + op);
    }
};

// Binary node
struct BinaryNode : ASTNode
{
    ASTPtr left;
    std::string op;
    ASTPtr right;
    BinaryNode(ASTPtr l, std::string o, ASTPtr r) : left(std::move(l)), op(std::move(o)), right(std::move(r)) {}

    int eval() const override
    {
        int l = left->eval(), r = right->eval();
        if (op == "AND") return l && r;
        if (op == "OR") return l || r;
        if (op == ">") return l > r;
        if (op == "<") return l < r;
        if (op == ">=") return l >= r;
        if (op == "<=") return l <= r;
        if (op == "==") return l == r;
        if (op == "!=") return l != r;
        throw std::runtime_error("Unknown binary operator: " + op);
    }
};

// Parser with precedence
class FnParser
{
    Tokenizer tokenizer;
    Token current;

    void advance()
    {
        current = tokenizer.next();
    }

    ASTPtr parsePrimary()
    {
        if (current.type == TokenType::NUMBER)
        {
            int val = std::stoi(current.value);
            advance();
            return std::make_unique<ConstNode>(val);
        }
        if (current.type == TokenType::IDENT)
        {
            std::string name = current.value;
            advance();
            if (current.type == TokenType::LPAREN)
            {
                advance();
                std::vector<ASTPtr> args;
                if (current.type != TokenType::RPAREN)
                {
                    do
                    {
                        args.push_back(parseExpression());
                        if (current.type == TokenType::COMMA) advance();
                    }
                    while (current.type != TokenType::RPAREN);
                }
                advance();
                return std::make_unique<FuncCallNode>(name, std::move(args));
            }
            throw std::runtime_error("Unexpected identifier without function call");
        }
        if (current.type == TokenType::OP && current.value == "!")
        {
            std::string op = current.value;
            advance();
            return std::make_unique<UnaryNode>(op, parsePrimary());
        }
        if (current.type == TokenType::LPAREN)
        {
            advance();
            ASTPtr expr = parseExpression();
            if (current.type != TokenType::RPAREN) throw std::runtime_error("Expected ')'");
            advance();
            return expr;
        }
        throw std::runtime_error("Unexpected token: " + current.value);
    }

    ASTPtr parseComparison()
    {
        ASTPtr left = parsePrimary();
        while (current.type == TokenType::OP &&
                (current.value == "==" || current.value == "!=" ||
                 current.value == "<" || current.value == ">" ||
                 current.value == "<=" || current.value == ">="))
        {
            std::string op = current.value;
            advance();
            ASTPtr right = parsePrimary();
            left = std::make_unique<BinaryNode>(std::move(left), op, std::move(right));
        }
        return left;
    }

    ASTPtr parseAnd()
    {
        ASTPtr left = parseComparison();
        while (current.type == TokenType::OP && current.value == "AND")
        {
            std::string op = current.value;
            advance();
            ASTPtr right = parseComparison();
            left = std::make_unique<BinaryNode>(std::move(left), op, std::move(right));
        }
        return left;
    }

    ASTPtr parseOr()
    {
        ASTPtr left = parseAnd();
        while (current.type == TokenType::OP && current.value == "OR")
        {
            std::string op = current.value;
            advance();
            ASTPtr right = parseAnd();
            left = std::make_unique<BinaryNode>(std::move(left), op, std::move(right));
        }
        return left;
    }

    ASTPtr parseExpression()
    {
        return parseOr();
    }

public:
    FnParser(const std::string& input) : tokenizer(input)
    {
        advance();
    }

    ASTPtr parse()
    {
        return parseOr();
    }
};

// Register user function
void registerUserFunction(const std::string& name, std::function<int(const std::vector<int>&)> func)
{
    userFunctions[name] = std::move(func);
}

} //end namespace
#endif // __pcap_abbv_parser_h__
