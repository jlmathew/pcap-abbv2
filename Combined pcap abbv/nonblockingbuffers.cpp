
#include "nonblockingbuffers.h"

/*struct Message_t {
    std::string key;
    std::string value;
};*/

/*
double get_cpu_time_rusage() {
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    double user_time = usage.ru_utime.tv_sec + usage.ru_utime.tv_usec / 1e6;
    double sys_time  = usage.ru_stime.tv_sec + usage.ru_stime.tv_usec / 1e6;
    return user_time + sys_time;
}
*/

// Non-blocking circular buffer
template<typename T, size_t Size>
class NonBlockingCircularBuffer {
private:
    std::vector<std::optional<T>> buffer;
    std::atomic<size_t> head{0};
    std::atomic<size_t> tail{0};

public:
    NonBlockingCircularBuffer() : buffer(Size) {}

    bool push(const T& item) {
        size_t current_head = head.load(std::memory_order_relaxed);
        size_t next_head = (current_head + 1) % Size;

        if (next_head == tail.load(std::memory_order_acquire)) {
            return false;
        }

        buffer[current_head] = item;
        head.store(next_head, std::memory_order_release);
        return true;
    }

    std::optional<T> pop() {
        size_t current_tail = tail.load(std::memory_order_relaxed);
        if (current_tail == head.load(std::memory_order_acquire)) {
            return std::nullopt;
        }

        auto item = buffer[current_tail];
        buffer[current_tail].reset();
        tail.store((current_tail + 1) % Size, std::memory_order_release);
        return item;
    }
};


std::atomic<uint64_t> messages_processed{0};

/*
// CPU time from /proc/self/stat
long get_cpu_ticks() {
    std::ifstream stat("/proc/self/stat");
    std::string line;
    std::getline(stat, line);
    std::istringstream iss(line);
    std::string token;
    for (int i = 0; i < 13; ++i) iss >> token; // skip to utime
    long utime, stime;
    iss >> utime >> stime;
    return utime + stime;
}
*/

// Non-blocking consumer
void consumer_thread(size_t id, NonBlockingCircularBuffer<pktBufferData_t, BUFFER_SIZE>* buffers) {
    while (true) {
        auto opt = buffers[id].pop();
        if (!opt) {
            std::this_thread::yield();
            continue;
        }
        messages_processed.fetch_add(1, std::memory_order_relaxed);
    }
}



// Producer for non-blocking
void producer_thread(NonBlockingCircularBuffer<pktBufferData_t, BUFFER_SIZE>* buffers) {
    std::hash<std::string> hasher;
    for (size_t i = 0; i < NUM_MESSAGES; ++i) {
        std::string key = "key" + std::to_string(i);
        std::string value = "value" + std::to_string(i);
        size_t target = hasher(key) % NUM_CONSUMERS;
       //     struct pktBufferData_t msg{struct pcap_pkthdr *, char *, std::vector<char> *key }; //fix
        //while (!buffers[target].push(msg)) {
       //     std::this_thread::yield();
        //}
    }
}



// Benchmark runner
/*template<typename BufferType>
void run_test(const std::string& label, BufferType* buffers) {
    messages_processed.store(0);
long cpu_start_ticks = get_cpu_ticks();
double cpu_start_rusage = get_cpu_time_rusage();
auto wall_start = std::chrono::high_resolution_clock::now();


    std::vector<std::thread> consumers;
    for (size_t i = 0; i < NUM_CONSUMERS; ++i) {
        consumers.emplace_back([i, buffers]() {
            consumer_thread(i, buffers);
        });
    }

    std::thread producer([buffers]() {
        producer_thread(buffers);
    });

    producer.join();

    while (messages_processed.load(std::memory_order_relaxed) < NUM_MESSAGES) {
        //std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }


auto wall_end = std::chrono::high_resolution_clock::now();
long cpu_end_ticks = get_cpu_ticks();
double cpu_end_rusage = get_cpu_time_rusage();


 std::chrono::duration<double> wall_elapsed = wall_end - wall_start;
long ticks_per_sec = sysconf(_SC_CLK_TCK);
double cpu_seconds_ticks = static_cast<double>(cpu_end_ticks - cpu_start_ticks) / ticks_per_sec;
double cpu_seconds_rusage = cpu_end_rusage - cpu_start_rusage;




std::cout << label << " processed " << NUM_MESSAGES << " messages\n";
std::cout << "Wall time: " << wall_elapsed.count() << " seconds\n";
std::cout << "CPU time (/proc/stat): " << cpu_seconds_ticks << " seconds\n";
std::cout << "CPU time (getrusage):  " << cpu_seconds_rusage << " seconds\n\n";

    for (auto& t : consumers) t.detach();
}*/
