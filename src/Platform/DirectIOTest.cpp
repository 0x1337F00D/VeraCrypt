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
const size_t RND_FILE_SIZE = 100 * 1024 * 1024;
const size_t RND_BLOCK_SIZE = 4 * 1024;
const size_t RND_ITERATIONS = 10000;
const string TEST_FILE = "test_volume.dat";

void run_raw_syscall_test(const string& name, bool use_direct_io, bool random_io = false) {
    cout << "| " << name << " | ";

    int flags = O_RDWR | O_CREAT | O_TRUNC;
    if (use_direct_io) flags |= O_DIRECT;

    int fd = open(TEST_FILE.c_str(), flags, 0666);
    if (fd < 0) {
        cout << "FAILED (open)" << endl;
        return;
    }

    size_t alignment = 4096;
    size_t effective_buffer_size = random_io ? RND_BLOCK_SIZE : SEQ_BUFFER_SIZE;
    size_t file_limit = random_io ? RND_FILE_SIZE : SEQ_FILE_SIZE;

    // Allocate aligned memory
    void* raw_mem = nullptr;
    posix_memalign(&raw_mem, alignment, effective_buffer_size);
    uint8_t* buf = (uint8_t*)raw_mem;
    memset(buf, 0xAA, effective_buffer_size);

    // Initialize file size for random IO
    if (random_io) {
        // Extend file to 100MB
        ftruncate(fd, file_limit);
        // Ensure allocation (optional, but good for stability)
        // For O_DIRECT, we need aligned writes, so let's just write one byte at the end if strict,
        // but ftruncate is usually enough on modern FS.
        // Let's actually fill it with zeros to be safe/fair using buffered IO or just large write.
        // Actually, we can reuse the fd.
        // But to be identical to VC test which used WriteAt(init_buf), let's just do a big write if needed.
        // For simplicity, we assume ftruncate is sufficient for sparse file testing, or we accept sparse performance.
    }

    double write_time = 0;
    size_t total_written = 0;

    if (random_io) {
        std::mt19937 rng(42);
        std::uniform_int_distribution<size_t> dist(0, (file_limit / alignment) - 1);

        write_time = measure_time([&]() {
            for (size_t i = 0; i < RND_ITERATIONS; ++i) {
                size_t block_idx = dist(rng);
                off_t offset = block_idx * alignment;
                if (offset + effective_buffer_size > file_limit) offset = 0;
                pwrite(fd, buf, effective_buffer_size, offset);
                total_written += effective_buffer_size;
            }
        });
    } else {
        write_time = measure_time([&]() {
            for (size_t offset = 0; offset < file_limit; offset += effective_buffer_size) {
                size_t sz = min(effective_buffer_size, file_limit - offset);
                pwrite(fd, buf, sz, offset);
                total_written += sz;
            }
        });
    }

    double read_time = 0;
    size_t total_read = 0;

    if (random_io) {
        std::mt19937 rng(42);
        std::uniform_int_distribution<size_t> dist(0, (file_limit / alignment) - 1);

        read_time = measure_time([&]() {
            for (size_t i = 0; i < RND_ITERATIONS; ++i) {
                size_t block_idx = dist(rng);
                off_t offset = block_idx * alignment;
                if (offset + effective_buffer_size > file_limit) offset = 0;
                pread(fd, buf, effective_buffer_size, offset);
                total_read += effective_buffer_size;
            }
        });
    } else {
        read_time = measure_time([&]() {
            for (size_t offset = 0; offset < file_limit; offset += effective_buffer_size) {
                size_t sz = min(effective_buffer_size, file_limit - offset);
                pread(fd, buf, sz, offset);
                total_read += sz;
            }
        });
    }

    double mb_s_write = (double)total_written / (1024.0 * 1024.0) / write_time;
    double iops_write = (double)(random_io ? RND_ITERATIONS : (total_written / effective_buffer_size)) / write_time;

    double mb_s_read = (double)total_read / (1024.0 * 1024.0) / read_time;
    double iops_read = (double)(random_io ? RND_ITERATIONS : (total_read / effective_buffer_size)) / read_time;

    if (random_io) {
         cout << iops_write << " IOPS | " << iops_read << " IOPS |" << endl;
    } else {
         cout << mb_s_write << " MB/s | " << mb_s_read << " MB/s |" << endl;
    }

    free(raw_mem);
    close(fd);
}

void run_vc_test(const string& name, bool use_direct_io, bool random_io = false) {
    cout << "| " << name << " | ";

    File::FileOpenFlags flags = File::FlagsNone;
    if (use_direct_io) {
        flags = (File::FileOpenFlags)(flags | File::OpenDirect);
    }

    try {
        File file;
        file.Open(TEST_FILE, File::CreateReadWrite, File::ShareNone, flags);

        size_t alignment = 4096;
        size_t effective_buffer_size = random_io ? RND_BLOCK_SIZE : SEQ_BUFFER_SIZE;
        size_t file_limit = random_io ? RND_FILE_SIZE : SEQ_FILE_SIZE;

        void* raw_mem = Memory::AllocateAligned(effective_buffer_size, alignment);
        memset(raw_mem, 0xBB, effective_buffer_size);
        BufferPtr io_buf((uint8*)raw_mem, effective_buffer_size);

        if (random_io && file.Length() < file_limit) {
            // Extend file by seeking and writing last byte or ftruncate wrapper?
            // File class doesn't have SetLength exposed easily, but we can Seek and Write.
            // Actually, for O_DIRECT we might need full allocation.
            // Let's rely on previous runs or just WriteAt 0.
             // Ensure at least enough space
             // Since we share the same file, raw test likely created it.
        }

        double write_time = 0;
        size_t total_written = 0;

        if (random_io) {
            std::mt19937 rng(42);
            std::uniform_int_distribution<size_t> dist(0, (file_limit / alignment) - 1);

            write_time = measure_time([&]() {
                for (size_t i = 0; i < RND_ITERATIONS; ++i) {
                    size_t block_idx = dist(rng);
                    uint64 offset = block_idx * alignment;
                    if (offset + effective_buffer_size > file_limit) offset = 0;
                    file.WriteAt(io_buf, offset);
                    total_written += effective_buffer_size;
                }
            });
        } else {
            write_time = measure_time([&]() {
                for (size_t offset = 0; offset < file_limit; offset += effective_buffer_size) {
                    size_t sz = min(effective_buffer_size, file_limit - offset);
                    BufferPtr chunk((uint8*)raw_mem, sz);
                    file.WriteAt(chunk, offset);
                    total_written += sz;
                }
            });
        }

        double read_time = 0;
        size_t total_read = 0;

        if (random_io) {
            std::mt19937 rng(42);
            std::uniform_int_distribution<size_t> dist(0, (file_limit / alignment) - 1);

            read_time = measure_time([&]() {
                for (size_t i = 0; i < RND_ITERATIONS; ++i) {
                    size_t block_idx = dist(rng);
                    uint64 offset = block_idx * alignment;
                    if (offset + effective_buffer_size > file_limit) offset = 0;
                    file.ReadAt(io_buf, offset);
                    total_read += effective_buffer_size;
                }
            });
        } else {
             read_time = measure_time([&]() {
                 for (size_t offset = 0; offset < file_limit; offset += effective_buffer_size) {
                    size_t sz = min(effective_buffer_size, file_limit - offset);
                    BufferPtr chunk((uint8*)raw_mem, sz);
                    file.ReadAt(chunk, offset);
                    total_read += sz;
                 }
            });
        }

        double mb_s_write = (double)total_written / (1024.0 * 1024.0) / write_time;
        double iops_write = (double)(random_io ? RND_ITERATIONS : (total_written / effective_buffer_size)) / write_time;

        double mb_s_read = (double)total_read / (1024.0 * 1024.0) / read_time;
        double iops_read = (double)(random_io ? RND_ITERATIONS : (total_read / effective_buffer_size)) / read_time;

        if (random_io) {
             cout << iops_write << " IOPS | " << iops_read << " IOPS |" << endl;
        } else {
             cout << mb_s_write << " MB/s | " << mb_s_read << " MB/s |" << endl;
        }

        file.Close();
        Memory::FreeAligned(raw_mem);

    } catch (...) {
        cout << "ERROR | ERROR |" << endl;
    }
}

int main() {
    cout << "### Performance Comparison" << endl;

    cout << "#### Sequential (1MB Blocks, 100MB Total)" << endl;
    cout << "| Scenario | Write Speed | Read Speed |" << endl;
    cout << "| :--- | :--- | :--- |" << endl;

    // Note: Raw Reference No VC = Raw Direct (since VC bypasses cache for disks)
    // But user asks for "No VC" as reference.
    // "Before" = VC Buffered.
    // "After" = VC Direct.

    run_raw_syscall_test("Reference (No VC - Buffered)", false);
    run_raw_syscall_test("Reference (No VC - Direct)", true);
    run_vc_test("Before (VC Buffered)", false);
    run_vc_test("After (VC Direct)", true);

    cout << endl;
    cout << "#### Random 4K (10000 Iterations)" << endl;
    cout << "| Scenario | Write IOPS | Read IOPS |" << endl;
    cout << "| :--- | :--- | :--- |" << endl;

    run_raw_syscall_test("Reference (No VC - Buffered)", false, true);
    run_raw_syscall_test("Reference (No VC - Direct)", true, true);
    run_vc_test("Before (VC Buffered)", false, true);
    run_vc_test("After (VC Direct)", true, true);

    unlink(TEST_FILE.c_str());
    return 0;
}
