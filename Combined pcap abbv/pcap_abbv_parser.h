#ifndef PCAP_ABBV_PARSER_H
#define PCAP_ABBV_PARSER_H


class pcap_abbv_parser
{
public:
    pcap_abbv_parser();
    virtual ~pcap_abbv_parser();

    void parse_each_options(int argc, char *argv[])
    {


//std::vector<std::vector<std::string>> parse_argument_blocks(int argc, char* argv[]) {

        std::vector<std::string> current_block;

        for (int i = 1; i < argc; ++i)
        {
            std::string arg = argv[i];

            if (arg.rfind("--", 0) == 0)    // Starts with "--"
            {
                if (!current_block.empty())
                {
                    blocks.push_back(current_block);
                    current_block.clear();
                }
            }
            current_block.push_back(arg);
        }

        if (!current_block.empty())
        {
            option_blocks.push_back(current_block);
        }

        return option_blocks;
    }

protected:

private:
    std::vector<std::vector<std::string>> m_option_block;
};

#endif // PCAP_ABBV_PARSER_H
