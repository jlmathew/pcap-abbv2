#ifndef __pcap_abbv_parser_h__
#define __pcap_abbv_parser_h__

#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <map>

namespace pcapabvparser {


// Token types
enum class TokenType { IDENT, NUMBER, OP, LPAREN, RPAREN, COMMA, END };

// Token structure
struct Token {
    TokenType type;
    std::string value;
};

// Tokenizer
class Tokenizer {
public:
    Tokenizer(const std::string& str);
    Token next();

private:
    std::string input;
    size_t pos = 0;
};

// AST Node
struct ASTNode {
    virtual int eval() const = 0;
    virtual ~ASTNode() = default;
};



using ASTPtr = std::unique_ptr<ASTNode>;

void getFnNames(const ASTNode* node, std::vector<std::string>& names);

// Function call node
struct FuncCallNode : ASTNode {
    std::string name;
    std::vector<ASTPtr> args;
    FuncCallNode(std::string n, std::vector<ASTPtr> a);
    int eval() const override;
};

// Constant node
struct ConstNode : ASTNode {
    int value;
    ConstNode(int v);
    int eval() const override;
};

// Unary node
struct UnaryNode : ASTNode {
    std::string op;
    ASTPtr operand;
    UnaryNode(std::string o, ASTPtr e);
    int eval() const override;
};

// Binary node
struct BinaryNode : ASTNode {
    ASTPtr left;
    std::string op;
    ASTPtr right;
    BinaryNode(ASTPtr l, std::string o, ASTPtr r);
    int eval() const override;
};

// Parser
class FnParser {
public:
    FnParser(const std::string& input);
    ASTPtr parse();

private:
    Tokenizer tokenizer;
    Token current;

    void advance();
    ASTPtr parsePrimary();
    ASTPtr parseComparison();
    ASTPtr parseAnd();
    ASTPtr parseOr();
    ASTPtr parseExpression();
};

// Register user function
void registerUserFunction(const std::string& name, std::function<int(const std::vector<int>&)> func);

} // namespace pcapabvparser

#endif // __pcap_abbv_parser_h__
