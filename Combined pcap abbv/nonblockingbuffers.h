#ifndef _nonblockingbuffers_h__
#define _nonblockingbuffers_h__

#include <iostream>
#include <thread>
#include <vector>
#include <atomic>
#include <optional>
#include <string>
#include <functional>
#include <chrono>
#include <mutex>
#include <condition_variable>
#include <fstream>
#include <sstream>
#include <unistd.h>
#include <sys/resource.h>
#include <tuple>
#include <pcap/pcap.h>
#include <unordered_map>
#include <cstdint>

#include "pcapkey.h"
#include "pcapparser.h"
#include "pcap_abbv_cli_parser.h"
#include "protoTrigger.h"


namespace pcapabvparser
{
extern struct globalOptions_t globalOptions;
//thread_local uint64_t messages_read_per_thread;
struct PacketOffsets_t; // forward declaration

    //std::vector<std::string> functionNames;

struct pktBufferData_t {
    std::unique_ptr<pcap_pkthdr> pktHeader;
    std::unique_ptr<uint8_t[]> pkt;
    std::unique_ptr<PacketOffsets_t> protoOffset;
    std::unique_ptr<std::vector<uint8_t>> key;
    uint32_t index = 0; // optional debug index
    pktBufferData_t(std::unique_ptr<pcap_pkthdr> header,
                    std::unique_ptr<uint8_t[]> data,
                    std::unique_ptr<PacketOffsets_t> offset,
                    std::unique_ptr<std::vector<uint8_t>> keyData,
                    uint32_t idx = 0)
        : pktHeader(std::move(header)),
          pkt(std::move(data)),
          protoOffset(std::move(offset)),
          key(std::move(keyData)),
          index(idx) {}
};


template<typename T, size_t Size>
class NonBlockingCircularBuffer
{
private:
    std::vector<std::optional<T>> buffer;
    std::atomic<size_t> head{0};
    std::atomic<size_t> tail{0};

public:
    NonBlockingCircularBuffer() : buffer(Size) {}

    //bool push(std::unique_ptr< T>&& item)
        bool push( T && item)
    {
        size_t current_head = head.load(std::memory_order_relaxed);
        size_t next_head = (current_head + 1) % Size;

        if (next_head == tail.load(std::memory_order_acquire))
        {
            return false;
        }

        buffer[current_head] = std::move(item);
        head.store(next_head, std::memory_order_release);
        return true;
    }

    std::optional<T> pop()
    {
        size_t current_tail = tail.load(std::memory_order_relaxed);
        if (current_tail == head.load(std::memory_order_acquire))
        {
            return std::nullopt;
        }

        std::optional<T> item = std::move(buffer[current_tail]);
        buffer[current_tail].reset();
        tail.store((current_tail + 1) % Size, std::memory_order_release);
        return item;
    }
};


extern std::atomic<uint64_t> messages_processed;

template<size_t Size>
void consumer_pcap_process_thread(
    size_t id,
    std::shared_ptr<NonBlockingCircularBuffer<std::unique_ptr<pktBufferData_t>, Size> > buffer)

{
//std::cout << "calling thread " << id << " and buffer pointer:" << std::hex << buffer<< std::endl;
//auto queueData = std::make_unique<pktBufferData_t>(std::move(headerCopy),std::move(packetCopy),std::move(offsets), std::move(key),target);

//create local thread evaluator, only doing packets of interest for now
  pcapabvparser::FnParser parser(globalOptions.pcapPacketOfInterestFilter);
    auto tree = parser.parse();
size_t threadId=id;
  std::vector<std::string> functionNames;
   pcapabvparser::getFnNames(tree.get(), functionNames );


   std::unordered_multimap<std::vector<uint8_t>, protoTrigger *, VectorHash > packetStreamMap;


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


while (true)
    {
        auto opt = buffer->pop();
        if (!opt)
        {
            std::this_thread::yield();
            continue;
        }
        messages_processed.fetch_add(1, std::memory_order_relaxed);
        //additional processing here
        std::cout << "thread " << threadId << " received packet #"  << messages_processed << " size " << opt.value()->key->size() << std::endl;

        //hash lookup new thread or existing?
        auto find_iter=packetStreamMap.find(*(opt.value()->key));

        //create new object if new
        if (find_iter== packetStreamMap.end()) {
           //create new Object
        } else {
           //get packet steram object

        }
        //transfer raw packet to network stream object (to queue for saves)
       //register functions to local thread evaluator
       //set flags (save packet, save stream) as necessary
    }

}





} //end namespace

#endif // __nonblockingbuffers_h__
