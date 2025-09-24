#ifndef __pcap_abbv_parser_h__
#define __pcap_abbv_parser_h__

#include <chrono>
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

namespace pcapabvparser
{

/** Type definition for callable functions in expressions */
using Func = std::function<int(std::vector<int>)>;
using FuncMap = std::unordered_map<std::string, Func>;

class Parser;

/** Registered functions that can be invoked in expressions */

/**  base class for all AST nodes */
class ASTNode
{
public:
    /** Evaluate the node and return boolean result */
    virtual bool evaluate() = 0;
    ASTNode() { std::cout << "creating ast at address " << this << std::endl; }
    ASTNode(const ASTNode& other) : m_functionMap(other.m_functionMap)  {}
    ASTNode(FuncMap functionUsed) : m_functionMap(functionUsed) {}
    //ASTNode(const ASTNode &node) { insertParser(node.getFunctionMap())}
    virtual ~ASTNode() = default;
    // Pure virtual clone methodm_functionMap
    virtual std::shared_ptr<ASTNode> clone() const = 0;
//protected:
    FuncMap m_functionMap;

public:
    void addFunct(std::string fnName, Func lambda)
    {
    std::cout << "adding function " << fnName << " at address " << this << std::endl;
        m_functionMap[fnName]=lambda;

    }
    auto getFunctionMap() const
    {
        return m_functionMap;
    }

    void insertParser(FuncMap functlist)
    {
        m_functionMap=functlist;
    }

};

using AST = std::shared_ptr<ASTNode>;

/** Represents a numeric constant value */
class ValueNode : public ASTNode
{
    int m_value;
    ValueNode() {};

public:
    explicit ValueNode(int v) : m_value(v) {}
    ValueNode(const ValueNode& other) : ASTNode(other), m_value(other.m_value)  {}
    AST clone() const override
    {
        return std::make_shared<ValueNode>(*this);
    }

    bool evaluate() override
    {
        return m_value != 0;
    }
    int getValue() const
    {
        return m_value;
    }
};

/** Represents a function call */
class FuncNode : public ASTNode
{
    std::string m_name;
    std::vector<int> m_args;

public:
    FuncNode(std::string n, std::vector<int> a) : m_name(move(n)), m_args(move(a))
    {

    }
    FuncNode(std::string n, std::vector<int> a, FuncMap functions) : ASTNode(functions), m_name((n)), m_args((a))
    {
std::cout << "FuncNode FuncMap:";
for(auto name : functions)
{
   std::cout << name.first << " ";
}
std::cout << std::endl;
    }
    // FuncNode(string n, vector<int> a, FuncMap functions) : ASTNode(functions), m_name(move(n)), m_args(move(a)) { }
    FuncNode(const FuncNode& other) : ASTNode(other),m_name(other.m_name),m_args(other.m_args)  {}
    AST clone() const override
    {
        return std::make_shared<FuncNode>(*this);
    }
    bool evaluate() override
    {
        auto iter = ASTNode::m_functionMap.find(m_name);
        std::cout << "eval function(" << m_name << ")=" << iter->second(m_args) << std::endl;
        if (iter != m_functionMap.end())
        {
            return iter->second(m_args) != 0;
        }
        else
        {
            std::cerr << "Function " << m_name << " does not exist." << std::endl;
            return 0;
        }
    }
    int getValue() const
    {
        auto iter = m_functionMap.find(m_name);
        std::cout << "getval function(" << m_name << ")=" << iter->second(m_args) << std::endl;
        if (iter != m_functionMap.end())
        {
            return iter->second(m_args);
        }
        else
        {
            std::cerr << "Function " << m_name << " does not exist." << std::endl;
            return 0;
        }
    }
};

/** Logical NOT */
class NotNode : public ASTNode
{
    AST m_child;
public:
    explicit NotNode(AST c) : m_child((c)) {}
    NotNode(const NotNode& other) : ASTNode(other), m_child(other.m_child)  {}
    AST clone() const override
    {
        return std::make_shared<NotNode>(*this);
    }
    bool evaluate() override
    {
        return !m_child->evaluate();
    }
};

/** Logical AND */
class AndNode : public ASTNode
{
    AST m_left, m_right;
public:
    AndNode(AST l, AST r) : m_left((l)), m_right((r)) {}
    AndNode(const AndNode& other) : ASTNode(other), m_left(other.m_left), m_right(other.m_right)  {}
    AST clone() const override
    {
        return std::make_shared<AndNode>(*this);
    }
    bool evaluate() override
    {
        return m_left->evaluate() && m_right->evaluate();
    }
};

/** Logical OR */
class OrNode : public ASTNode
{
    AST m_left, m_right;
public:
    OrNode(AST l, AST r) : m_left((l)), m_right((r)) {}
    OrNode(const OrNode& other) : ASTNode(other), m_left(other.m_left), m_right(other.m_right)  {}

    AST clone() const override
    {
        return std::make_shared<OrNode>(*this);
    }
    bool evaluate() override
    {
        return m_left->evaluate() || m_right->evaluate();
    }
};

/** Comparison operations */
class ComparisonNode : public ASTNode
{
public:
    enum class Operator { EQ, NEQ, GT, LT, GTE, LTE };

private:
    AST m_left;
    Operator m_op;
    AST m_right;

public:

    ComparisonNode(AST l, Operator o, AST r)
        : m_left((l)), m_op(o), m_right((r)) {}
    ComparisonNode(const ComparisonNode& other) : ASTNode(other), m_left(other.m_left), m_op(other.m_op), m_right(other.m_right)  {}

    AST clone() const override
    {
        return std::make_shared<ComparisonNode>(*this);
    }
    bool evaluate() override
    {
        auto getVal = [](const AST& node) -> int
        {
            if (auto val = std::dynamic_pointer_cast<ValueNode>(node)) return val->getValue();
            if (auto fn = std::dynamic_pointer_cast<FuncNode>(node)) return fn->getValue();
            // NEW: also allow wrapped logical expressions to resolve to bool -> int
            return node->evaluate() ? 1 : 0;
            //throw runtime_error("Invalid comparison operand"); Unsure if we wish to compare boolean (true/false) to ints (true=1, false=0)
        };
        int lhs = getVal(m_left);
        int rhs = getVal(m_right);
        switch (m_op)
        {
        case Operator::EQ:
            return lhs == rhs;
        case Operator::NEQ:
            return lhs != rhs;
        case Operator::GT:
            return lhs > rhs;
        case Operator::LT:
            return lhs < rhs;
        case Operator::GTE:
            return lhs >= rhs;
        case Operator::LTE:
            return lhs <= rhs;
        }
        return false;
    }
};

// === Tokenizer definitions ===

/** Token types used by the parser */
enum TokenType
{
    TOKEN_AND, TOKEN_OR, TOKEN_NOT,
    TOKEN_LPAREN, TOKEN_RPAREN, TOKEN_FUNC,
    TOKEN_EQ, TOKEN_NEQ, TOKEN_GT, TOKEN_LT, TOKEN_GTE, TOKEN_LTE,
    TOKEN_NUM, TOKEN_END
};

/** Represents a lexical token */
struct Token
{
    TokenType type;
    std::string value;
};

/**
 * @brief Tokenize an input expression into a vector of Tokens
 * @param input The string expression
 * @return Vector of tokens
 */
std::vector<Token> tokenize(const std::string& input)
{
    std::vector<Token> m_tokens;
    size_t i = 0;

    while (i < input.size())
    {
        if (isspace(input[i]))
        {
            ++i;
            continue;
        }

        if (input[i] == '(')
        {
            m_tokens.push_back({TOKEN_LPAREN, "("});
            ++i;
        }
        else if (input[i] == ')')
        {
            m_tokens.push_back({TOKEN_RPAREN, ")"});
            ++i;
        }
        else if (input[i] == '!')
        {
            if (i + 1 < input.size() && input[i + 1] == '=')
            {
                m_tokens.push_back({TOKEN_NEQ, "!="});
                i += 2;
            }
            else
            {
                m_tokens.push_back({TOKEN_NOT, "!"});
                ++i;
            }
        }
        else if (input[i] == '=' && i + 1 < input.size() && input[i + 1] == '=')
        {
            m_tokens.push_back({TOKEN_EQ, "=="});
            i += 2;
        }
        else if (input[i] == '>' && i + 1 < input.size() && input[i + 1] == '=')
        {
            m_tokens.push_back({TOKEN_GTE, ">="});
            i += 2;
        }
        else if (input[i] == '<' && i + 1 < input.size() && input[i + 1] == '=')
        {
            m_tokens.push_back({TOKEN_LTE, "<="});
            i += 2;
        }
        else if (input[i] == '>')
        {
            m_tokens.push_back({TOKEN_GT, ">"});
            ++i;
        }
        else if (input[i] == '<')
        {
            m_tokens.push_back({TOKEN_LT, "<"});
            ++i;
        }
        else if (isdigit(input[i]))
        {
            size_t j = i;
            while (j < input.size() && isdigit(input[j])) ++j;
            m_tokens.push_back({TOKEN_NUM, input.substr(i, j - i)});
            i = j;
        }
        else if (isalpha(input[i]) || input[i] == '_' || input[i] == '.')
        {
            // Read identifier
            size_t j = i;
            while (j < input.size() && (isalnum(input[j]) || input[j] == '_' || input[j] == '.')) ++j;
            std::string name = input.substr(i, j - i);

            // Check for function call
            size_t k = j;
            if (k < input.size() && input[k] == '(')
            {
                int depth = 1;
                ++k;
                while (k < input.size() && depth > 0)
                {
                    if (input[k] == '(') ++depth;
                    else if (input[k] == ')') --depth;
                    ++k;
                }
                if (depth == 0)
                {
                    m_tokens.push_back({TOKEN_FUNC, input.substr(i, k - i)});
                    i = k;
                    continue;
                }
                else
                {
                    throw std::runtime_error("Unclosed function call parentheses at position " + std::to_string(i));
                }
            }

            // Not a function call, treat as keyword
            if (name == "AND") m_tokens.push_back({TOKEN_AND, name});
            else if (name == "OR") m_tokens.push_back({TOKEN_OR, name});
            else throw std::runtime_error("Unexpected identifier: " + name);

            i = j;
        }
        else
        {
            throw std::runtime_error("Unknown character: " + std::string(1, input[i]));
        }
    }

    m_tokens.push_back({TOKEN_END, ""});
    return m_tokens;
}


// ===== Parser =====
class Parser
{

private:

    const std::vector<Token>& m_tokens;
    size_t m_pos = 0;
    std::unordered_map<std::string, Func> m_functionRegistry;

public:

    void addFunct(std::string fnName, Func lambda)
    {
        m_functionRegistry[fnName]=lambda;
    }
    auto getFunctionRegistry() const
    {
        return &m_functionRegistry;
    }

    auto getFunctionNames() const
    {

        std::vector<std::string> functionNameCache;
        for(const auto &functionToken : m_tokens) {
           if (functionToken.type==TOKEN_FUNC) { functionNameCache.push_back(functionToken.value);}
        }
        return functionNameCache;
    }
    Token peek() const
    {
        return m_tokens[m_pos];
    }
    Token advance()
    {
        return m_tokens[m_pos++];
    }

    AST parseExpr()
    {
        AST node = parseFactor();
        while (peek().type == TOKEN_OR)
        {
            advance();
            node = std::make_shared<OrNode>(node, parseFactor());
        }
        return node;
    }


    AST parseFunc(const std::string& ftext)
    {
        size_t lparen = ftext.find('(');
        std::string name = ftext.substr(0, lparen);
        std::string argsText = ftext.substr(lparen + 1, ftext.size() - lparen - 2);

        std::vector<int> args;
        std::stringstream ss(argsText);
        std::string val;
        while (getline(ss, val, ','))
        {
            if (!val.empty() )
            {
                if (val != ")") // handle case where fn() is used
                {
                    args.push_back(stoi(val));
                }
            }
        }

        return std::make_shared<FuncNode>(name, args, m_functionRegistry);

    }

    /**
    * @class Parser
    * @brief Parses tokens into an Abstract Syntax Tree (AST)
    */
    AST parseFactor()
    {
        AST node = parseComparison();
        while (peek().type == TOKEN_AND)
        {
            advance();
            node = std::make_shared<AndNode>(node, parseComparison());
        }
        return node;
    }



    AST parseComparison()
    {
        AST left = parsePrimary();
        TokenType ttype = peek().type;
        if (ttype >= TOKEN_EQ && ttype <= TOKEN_LTE)
        {
            Token t = advance();
            AST right = parsePrimary();
            using Op = ComparisonNode::Operator;
            Op op = Op::EQ;
            if (t.type == TOKEN_EQ) op = Op::EQ;
            else if (t.type == TOKEN_NEQ) op = Op::NEQ;
            else if (t.type == TOKEN_GT) op = Op::GT;
            else if (t.type == TOKEN_LT) op = Op::LT;
            else if (t.type == TOKEN_GTE) op = Op::GTE;
            else if (t.type == TOKEN_LTE) op = Op::LTE;
            return std::make_shared<ComparisonNode>(left, op, right);
        }
        return left;
    }
    AST parsePrimary()
    {
        Token t = advance();
        if (t.type == TOKEN_NOT)
        {
            return std::make_shared<NotNode>(parsePrimary());
        }
        else if (t.type == TOKEN_LPAREN)
        {
            AST expr = parseExpr();
            if (peek().type != TOKEN_RPAREN) throw std::runtime_error("Expected ')'");
            advance(); // consume ')'
            return expr;
        }
        else if (t.type == TOKEN_FUNC)
        {
            return parseFunc(t.value);
        }
        else if (t.type == TOKEN_NUM)
        {
            return std::make_shared<ValueNode>(stoi(t.value));
        }
        throw std::runtime_error("Unexpected token: " + t.value);
    }

public:
    explicit Parser(const std::vector<Token>& t) : m_tokens(t) {}
    /*    Parser(Parser &lhs_parser) {
            m_tokens = lhs_parser.m_tokens;
        m_pos = lhs_parser.m_pos;
        m_functionRegistry = lhs_parser.m_functionRegistry;

    } */
    AST parse()
    {
        AST result = parseExpr();
        if (peek().type != TOKEN_END)
        {
            throw std::runtime_error("Unexpected token after end of expression");
        }
        return result;
    }
};
} //end of namespace
#endif // __pcap_abbv_parser_h__


