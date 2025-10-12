#include "pcapparser.h"
#include <stdexcept>
#include <cctype>
#include <utility>
#include <thread>
#include <iostream>


namespace pcapabvparser
{

// Thread-local user function registry
thread_local std::map<std::string, std::function<int(const std::vector<int>&)>> userFunctions;

//get function Names during Parsing


void getFnNames(const ASTNode* node, std::vector<std::string>& names) {
    if (const auto* func = dynamic_cast<const FuncCallNode*>(node)) {
        names.push_back(func->name);
        for (const auto& arg : func->args) {
            getFnNames(arg.get(), names);
        }
    } else if (const auto* unary = dynamic_cast<const UnaryNode*>(node)) {
        getFnNames(unary->operand.get(), names);
    } else if (const auto* binary = dynamic_cast<const BinaryNode*>(node)) {
        getFnNames(binary->left.get(), names);
        getFnNames(binary->right.get(), names);
    }
}

// Tokenizer
Tokenizer::Tokenizer(const std::string& str) : input(str) {}

Token Tokenizer::next()
{

    while (pos < input.size() && isspace(input[pos])) ++pos;
    if (pos >= input.size()) return {TokenType::END, ""};

    char ch = input[pos];
    if (isdigit(ch) || (ch == '-' && pos + 1 < input.size() && isdigit(input[pos + 1])))
    {
        size_t start = pos;
        if (input[pos] == '-') ++pos;
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

// AST Nodes
FuncCallNode::FuncCallNode(std::string n, std::vector<ASTPtr> a) : name(std::move(n)), args(std::move(a)) {}

int FuncCallNode::eval() const
{
    std::vector<int> evaluatedArgs;
    for (const auto& arg : args) evaluatedArgs.push_back(arg->eval());
    auto it = userFunctions.find(name);
    if (it == userFunctions.end()) throw std::runtime_error("Unknown function: " + name);
    return it->second(evaluatedArgs);
}

ConstNode::ConstNode(int v) : value(v) {}

int ConstNode::eval() const
{
    return value;
}

UnaryNode::UnaryNode(std::string o, ASTPtr e) : op(std::move(o)), operand(std::move(e)) {}

int UnaryNode::eval() const
{
    if (op == "!") return !operand->eval();
    throw std::runtime_error("Unknown unary operator: " + op);
}

BinaryNode::BinaryNode(ASTPtr l, std::string o, ASTPtr r)
    : left(std::move(l)), op(std::move(o)), right(std::move(r)) {}

int BinaryNode::eval() const
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

// Parser
FnParser::FnParser(const std::string& input) : tokenizer(input)
{
    advance();
}

void FnParser::advance()
{
    current = tokenizer.next();
}

ASTPtr FnParser::parsePrimary()
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

ASTPtr FnParser::parseComparison()
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

ASTPtr FnParser::parseAnd()
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

ASTPtr FnParser::parseOr()
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

ASTPtr FnParser::parseExpression()
{
    return parseOr();
}

ASTPtr FnParser::parse()
{
    return parseOr();
}

// Register function
void registerUserFunction(const std::string& name, std::function<int(const std::vector<int>&)> func)
{
    userFunctions[name] = std::move(func);
}

} // namespace pcapabvparser
