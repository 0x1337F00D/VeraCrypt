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

const size_t SEQ_FILE_SIZE = 100 * 1024 * 1024;
const size_t SEQ_BUFFER_SIZE = 1 * 1024 * 1024;
const string TEST_FILE = "test_volume.dat";

// Raw Syscall Benchmark (No VeraCrypt File Wrapper)
void run_raw_syscall_test(const string& name, bool use_direct_io) {
    cout << "| " << name << " | ";

    int flags = O_RDWR | O_CREAT | O_TRUNC;
    if (use_direct_io) flags |= O_DIRECT;

    int fd = open(TEST_FILE.c_str(), flags, 0666);
    if (fd < 0) {
        cout << "FAILED (open)" << endl;
        return;
    }

    size_t alignment = 4096;
    void* raw_mem = nullptr;
    posix_memalign(&raw_mem, alignment, SEQ_BUFFER_SIZE);
    uint8_t* buf = (uint8_t*)raw_mem;
    memset(buf, 0xAA, SEQ_BUFFER_SIZE);

    // Write
    double write_time = measure_time([&]() {
        for (size_t offset = 0; offset < SEQ_FILE_SIZE; offset += SEQ_BUFFER_SIZE) {
            size_t sz = min(SEQ_BUFFER_SIZE, SEQ_FILE_SIZE - offset);
            pwrite(fd, buf, sz, offset);
        }
    });

    // Read
    double read_time = measure_time([&]() {
        for (size_t offset = 0; offset < SEQ_FILE_SIZE; offset += SEQ_BUFFER_SIZE) {
            size_t sz = min(SEQ_BUFFER_SIZE, SEQ_FILE_SIZE - offset);
            pread(fd, buf, sz, offset);
        }
    });

    double mb_s_write = (double)SEQ_FILE_SIZE / (1024.0 * 1024.0) / write_time;
    double mb_s_read = (double)SEQ_FILE_SIZE / (1024.0 * 1024.0) / read_time;

    cout << mb_s_write << " MB/s | " << mb_s_read << " MB/s |" << endl;

    free(raw_mem);
    close(fd);
}

// VeraCrypt File Wrapper Benchmark
void run_vc_test(const string& name, bool use_direct_io, bool simulate_crypto_overhead = false) {
    cout << "| " << name << " | ";

    File::FileOpenFlags flags = File::FlagsNone;
    if (use_direct_io) {
        flags = (File::FileOpenFlags)(flags | File::OpenDirect);
    }

    try {
        File file;
        file.Open(TEST_FILE, File::CreateReadWrite, File::ShareNone, flags);

        size_t alignment = 4096;
        void* raw_mem = Memory::AllocateAligned(SEQ_BUFFER_SIZE, alignment);
        memset(raw_mem, 0xBB, SEQ_BUFFER_SIZE);
        BufferPtr io_buf((uint8*)raw_mem, SEQ_BUFFER_SIZE);

        // Write
        double write_time = measure_time([&]() {
            for (size_t offset = 0; offset < SEQ_FILE_SIZE; offset += SEQ_BUFFER_SIZE) {
                size_t sz = min(SEQ_BUFFER_SIZE, SEQ_FILE_SIZE - offset);
                // Simulate XTS Encryption overhead (AES-256) ~ roughly memory copy cost
                if (simulate_crypto_overhead) {
                     for(volatile int i=0; i<1000; i++); // Minimal delay
                }
                BufferPtr chunk((uint8*)raw_mem, sz);
                file.WriteAt(chunk, offset);
            }
        });

        // Read
        double read_time = measure_time([&]() {
             for (size_t offset = 0; offset < SEQ_FILE_SIZE; offset += SEQ_BUFFER_SIZE) {
                size_t sz = min(SEQ_BUFFER_SIZE, SEQ_FILE_SIZE - offset);
                if (simulate_crypto_overhead) {
                     for(volatile int i=0; i<1000; i++);
                }
                BufferPtr chunk((uint8*)raw_mem, sz);
                file.ReadAt(chunk, offset);
             }
        });

        double mb_s_write = (double)SEQ_FILE_SIZE / (1024.0 * 1024.0) / write_time;
        double mb_s_read = (double)SEQ_FILE_SIZE / (1024.0 * 1024.0) / read_time;

        cout << mb_s_write << " MB/s | " << mb_s_read << " MB/s |" << endl;

        file.Close();
        Memory::FreeAligned(raw_mem);

    } catch (...) {
        cout << "ERROR | ERROR |" << endl;
    }
}

int main() {
    cout << "### Performance Comparison (Sequential 1MB Blocks)" << endl;
    cout << "| Scenario | Write Speed | Read Speed |" << endl;
    cout << "| :--- | :--- | :--- |" << endl;

    // 1. Raw Reference
    run_raw_syscall_test("Reference (Raw Syscall Buffered)", false);
    run_raw_syscall_test("Reference (Raw Syscall Direct)", true);

    // 2. VeraCrypt Wrapper
    run_vc_test("VC Wrapper (Buffered / Before)", false);
    run_vc_test("VC Wrapper (Direct / After)", true);

    // 3. Crypto Simulation (Approximation)
    // run_vc_test("VC Wrapper + Crypto Sim (Buffered)", false, true);
    // run_vc_test("VC Wrapper + Crypto Sim (Direct)", true, true);

    unlink(TEST_FILE.c_str());
    return 0;
}
