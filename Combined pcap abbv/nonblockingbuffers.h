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


namespace pcapabvparser
{



constexpr size_t NUM_CONSUMERS = 4;
constexpr size_t BUFFER_SIZE = 256;
constexpr size_t NUM_MESSAGES = 100000000;

struct pktBufferData_t
{
    char *pktHeader=nullptr;
    char *pkt=nullptr;
    std::vector<char> *key=nullptr;
    //help vector/struct?
    uint32_t index=0; //index for threads, should be only used in debug statements
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

    bool push(const T& item)
    {
        size_t current_head = head.load(std::memory_order_relaxed);
        size_t next_head = (current_head + 1) % Size;

        if (next_head == tail.load(std::memory_order_acquire))
        {
            return false;
        }

        buffer[current_head] = item;
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

        auto item = buffer[current_tail];
        buffer[current_tail].reset();
        tail.store((current_tail + 1) % Size, std::memory_order_release);
        return item;
    }
};


std::atomic<uint64_t> messages_processed{0};

void consumer_pcap_process_thread(size_t id, NonBlockingCircularBuffer<pktBufferData_t, BUFFER_SIZE>* buffers)
{
    while (true)
    {
        auto opt = buffers[id].pop();
        if (!opt)
        {
            std::this_thread::yield();
            continue;
        }
        messages_processed.fetch_add(1, std::memory_order_relaxed);
        //additional processing here
    }

}



// Producer for non-blocking
void producer_thread(NonBlockingCircularBuffer<pktBufferData_t, BUFFER_SIZE>* buffers)
{
    std::hash<std::string> hasher;
    for (size_t i = 0; i < NUM_MESSAGES; ++i)
    {
        std::string key = "key" + std::to_string(i);
        std::string value = "value" + std::to_string(i);
        size_t target = hasher(key) % NUM_CONSUMERS;
        //     struct pktBufferData_t msg{struct pcap_pkthdr *, char *, std::vector<char> *key }; //fix
        //while (!buffers[target].push(msg)) {
        //     std::this_thread::yield();
        //}
    }
}

} //end namespace

#endif // __nonblockingbuffers_h__
