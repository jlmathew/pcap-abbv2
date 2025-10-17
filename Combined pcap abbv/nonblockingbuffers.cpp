
#include "nonblockingbuffers.h"

namespace pcapabvparser
{


std::atomic<uint64_t> messages_processed{0};

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
}
