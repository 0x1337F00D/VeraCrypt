#include <iostream>
#include <vector>
#include <chrono>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <random>
#include "Platform/PlatformBase.h"
#include "Platform/Buffer.h"
#include "Platform/File.h"
#include "Platform/Memory.h"
#include "Platform/SystemException.h"

using namespace std;
using namespace VeraCrypt;

// Helper function to measure execution time
template <typename Func>
double measure_time(Func f) {
    auto start = chrono::high_resolution_clock::now();
    f();
    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> diff = end - start;
    return diff.count();
}

// Test configuration
const size_t SEQ_FILE_SIZE = 100 * 1024 * 1024; // 100 MB
const size_t SEQ_BUFFER_SIZE = 1 * 1024 * 1024; // 1 MB chunks for sequential
const size_t RND_FILE_SIZE = 100 * 1024 * 1024; // 100 MB
const size_t RND_BLOCK_SIZE = 4 * 1024;         // 4 KB blocks for random
const size_t RND_ITERATIONS = 5000;             // Number of random IOs
const string TEST_FILE = "test_volume.dat";

void run_test(const string& name, bool use_direct_io, bool random_io = false, bool misalign_memory = false, bool misalign_size = false, bool misalign_offset = false) {
    cout << "Testing: " << name << " (Direct IO: " << (use_direct_io ? "ON" : "OFF") << ")" << endl;

    File::FileOpenFlags flags = File::FlagsNone;
    if (use_direct_io) {
        flags = (File::FileOpenFlags)(flags | File::OpenDirect);
    }

    try {
        File file;
        // Create/Open file
        file.Open(TEST_FILE, File::CreateReadWrite, File::ShareNone, flags);

        size_t alignment = 4096;
        size_t effective_buffer_size = random_io ? RND_BLOCK_SIZE : SEQ_BUFFER_SIZE;
        size_t file_limit = random_io ? RND_FILE_SIZE : SEQ_FILE_SIZE;
        size_t offset_shift = 0;

        if (misalign_size) effective_buffer_size -= 123;
        if (misalign_offset) offset_shift = 123;

        // Allocate aligned memory
        void* raw_mem = Memory::AllocateAligned(effective_buffer_size + 4096, alignment);
        uint8* buf_ptr = (uint8*)raw_mem;

        if (misalign_memory) {
            buf_ptr += 123;
        }

        // Initialize file for random test (needs existing data)
        if (random_io) {
             void* big_buf = Memory::AllocateAligned(file_limit, alignment);
             memset(big_buf, 0, file_limit);
             BufferPtr init_buf((uint8*)big_buf, file_limit);
             // Use buffered IO to init file quickly if possible, but here we reuse 'file' obj
             // To avoid changing modes, just write zeros.
             // (For accurate random read test, we need data)
             // Let's just assume file is big enough or extend it.
             // Actually, simplest is to extend file first.
             // Since we reuse the file from previous tests, it might be 100MB already.
             // Let's ensure size.
             if (file.Length() < file_limit) {
                  // Write zeros to extend
                  // Fallback to small writes if needed or just one big write
                  // Since 'big_buf' is aligned, it should work even in Direct IO
                  file.WriteAt(init_buf, 0);
             }
             Memory::FreeAligned(big_buf);
        }

        // Fill buffer pattern
        for (size_t i = 0; i < effective_buffer_size; ++i) {
            buf_ptr[i] = (uint8)(i % 256);
        }

        BufferPtr io_buf(buf_ptr, effective_buffer_size);

        // --- Write Test ---
        double write_time = 0;
        size_t total_written = 0;

        if (random_io) {
            std::mt19937 rng(42);
            std::uniform_int_distribution<size_t> dist(0, (file_limit / alignment) - 1);

            write_time = measure_time([&]() {
                for (size_t i = 0; i < RND_ITERATIONS; ++i) {
                    size_t block_idx = dist(rng);
                    uint64 offset = block_idx * alignment + offset_shift;
                    // Check bounds
                    if (offset + effective_buffer_size > file_limit) offset = 0;

                    file.WriteAt(io_buf, offset);
                    total_written += effective_buffer_size;
                }
            });
        } else {
            write_time = measure_time([&]() {
                for (size_t offset = 0; offset < file_limit; offset += effective_buffer_size) {
                    size_t write_sz = min(effective_buffer_size, file_limit - offset);
                    BufferPtr chunk_buf(buf_ptr, write_sz);
                    file.WriteAt(chunk_buf, offset + offset_shift);
                    total_written += write_sz;
                }
            });
        }

        double mb_s_write = (double)total_written / (1024.0 * 1024.0) / write_time;
        double iops_write = (double)(random_io ? RND_ITERATIONS : (total_written / effective_buffer_size)) / write_time;

        cout << "  Write: " << mb_s_write << " MB/s | " << iops_write << " IOPS" << endl;


        // --- Read Test ---
        double read_time = 0;
        size_t total_read = 0;

        // Clear buffer to verify (optional, mostly for correctness, skipping stringent verify for bench speed)
        memset(buf_ptr, 0, effective_buffer_size);

        if (random_io) {
            std::mt19937 rng(42); // Same seed
            std::uniform_int_distribution<size_t> dist(0, (file_limit / alignment) - 1);

            read_time = measure_time([&]() {
                for (size_t i = 0; i < RND_ITERATIONS; ++i) {
                    size_t block_idx = dist(rng);
                    uint64 offset = block_idx * alignment + offset_shift;
                    if (offset + effective_buffer_size > file_limit) offset = 0;

                    file.ReadAt(io_buf, offset);
                    total_read += effective_buffer_size;
                }
            });
        } else {
            read_time = measure_time([&]() {
                 for (size_t offset = 0; offset < file_limit; offset += effective_buffer_size) {
                    size_t read_sz = min(effective_buffer_size, file_limit - offset);
                    BufferPtr chunk_buf(buf_ptr, read_sz);
                    file.ReadAt(chunk_buf, offset + offset_shift);
                    total_read += read_sz;
                 }
            });
        }

        double mb_s_read = (double)total_read / (1024.0 * 1024.0) / read_time;
        double iops_read = (double)(random_io ? RND_ITERATIONS : (total_read / effective_buffer_size)) / read_time;

        cout << "  Read:  " << mb_s_read << " MB/s | " << iops_read << " IOPS" << endl;

        file.Close();
        Memory::FreeAligned(raw_mem);

    } catch (std::exception& e) {
        cout << "  [ERROR] Exception: " << e.what() << endl;
    } catch (...) {
        cout << "  [ERROR] Unknown Exception" << endl;
    }
    cout << "------------------------------------------------" << endl;
}

int main() {
    cout << "=== VeraCrypt Disk I/O Simulation Suite ===" << endl;
    cout << "Sequential: 1MB Blocks, " << SEQ_FILE_SIZE / (1024*1024) << " MB Total" << endl;
    cout << "Random:     4KB Blocks, " << RND_ITERATIONS << " Iterations" << endl;
    cout << "------------------------------------------------" << endl;

    // 1. Buffered I/O (Reference)
    run_test("Buffered - Sequential", false);
    run_test("Buffered - Random 4K", false, true);

    // 2. Direct I/O (Aligned)
    run_test("Direct - Sequential (Aligned)", true);
    run_test("Direct - Random 4K (Aligned)", true, true);

    // 3. Direct I/O (Unaligned - Stress Test)
    run_test("Direct - Sequential (Unaligned Mem)", true, false, true, false, false);
    // run_test("Direct - Random 4K (Unaligned Mem)", true, true, true, false, false);

    // Cleanup
    unlink(TEST_FILE.c_str());

    return 0;
}
