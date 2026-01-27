#include <iostream>
#include <vector>
#include <chrono>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
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
const size_t FILE_SIZE = 100 * 1024 * 1024; // 100 MB
const size_t BUFFER_SIZE = 64 * 1024;       // 64 KB chunks
const string TEST_FILE = "test_volume.dat";

void run_test(const string& name, bool use_direct_io, bool misalign_memory = false, bool misalign_size = false, bool misalign_offset = false) {
    cout << "Testing: " << name << " (Direct IO: " << (use_direct_io ? "ON" : "OFF") << ")" << endl;

    File::FileOpenFlags flags = File::FlagsNone;
    if (use_direct_io) {
        flags = (File::FileOpenFlags)(flags | File::OpenDirect);
    }

    try {
        File file;
        // Create/Open file
        file.Open(TEST_FILE, File::CreateReadWrite, File::ShareNone, flags);

        size_t alignment = 4096; // Assume 4K sector size for O_DIRECT
        size_t effective_buffer_size = BUFFER_SIZE;
        size_t offset_shift = 0;

        if (misalign_size) effective_buffer_size -= 123; // Make size unaligned
        if (misalign_offset) offset_shift = 123;         // Make offset unaligned

        // Prepare buffer
        // Allocate aligned memory first, then potentially offset pointer
        void* raw_mem = Memory::AllocateAligned(BUFFER_SIZE + 4096, alignment);
        uint8* buf_ptr = (uint8*)raw_mem;

        if (misalign_memory) {
            buf_ptr += 123; // Misalign memory address
        }

        // Fill buffer with pattern
        for (size_t i = 0; i < effective_buffer_size; ++i) {
            buf_ptr[i] = (uint8)(i % 256);
        }

        BufferPtr write_buf(buf_ptr, effective_buffer_size);

        // Write Test
        double write_time = measure_time([&]() {
            for (size_t offset = 0; offset < FILE_SIZE; offset += effective_buffer_size) {
                // Determine write size (handle last block)
                size_t write_sz = min(effective_buffer_size, FILE_SIZE - offset);
                BufferPtr chunk_buf(buf_ptr, write_sz);

                // Write at specific offset (potentially misaligned)
                file.WriteAt(chunk_buf, offset + offset_shift);
            }
        });

        double mb_s_write = (double)FILE_SIZE / (1024.0 * 1024.0) / write_time;
        cout << "  Write Speed: " << mb_s_write << " MB/s (" << FILE_SIZE << " bytes in " << write_time << " s)" << endl;

        // Verify Data (Read back)
        // Clear buffer
        memset(buf_ptr, 0, effective_buffer_size);
        BufferPtr read_buf(buf_ptr, effective_buffer_size);

        // Read Test
        double read_time = measure_time([&]() {
             for (size_t offset = 0; offset < FILE_SIZE; offset += effective_buffer_size) {
                size_t read_sz = min(effective_buffer_size, FILE_SIZE - offset);
                BufferPtr chunk_buf(buf_ptr, read_sz);

                file.ReadAt(chunk_buf, offset + offset_shift);
             }
        });

        double mb_s_read = (double)FILE_SIZE / (1024.0 * 1024.0) / read_time;
        cout << "  Read Speed:  " << mb_s_read << " MB/s (" << FILE_SIZE << " bytes in " << read_time << " s)" << endl;

        // Validation
        bool success = true;
        for (size_t i = 0; i < effective_buffer_size; ++i) { // Check last chunk or representative chunk
             if (buf_ptr[i] != (uint8)(i % 256)) {
                 success = false;
                 cout << "  [FAIL] Data Mismatch at byte " << i << ": Expected " << (int)(i%256) << ", Got " << (int)buf_ptr[i] << endl;
                 break;
             }
        }

        if (success) cout << "  [PASS] Data Integrity Verified." << endl;

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

    // 1. Buffered I/O (Simulating File Container) - Reference
    run_test("Buffered I/O (Container)", false);

    // 2. Direct I/O (Simulating Disk Device) - Aligned (Ideal Case)
    run_test("Direct I/O (Disk) - Aligned", true);

    // 3. Direct I/O (Simulating Disk Device) - Unaligned Memory
    run_test("Direct I/O (Disk) - Unaligned Memory", true, true, false, false);

    // 4. Direct I/O (Simulating Disk Device) - Unaligned Size (Wait, O_DIRECT usually requires size multiple of block size, but File.cpp should handle it via RMW or padding)
    run_test("Direct I/O (Disk) - Unaligned Size", true, false, true, false);

    // 5. Direct I/O (Simulating Disk Device) - Unaligned Offset (Wait, O_DIRECT usually requires offset multiple of block size, but File.cpp should handle it via RMW)
    run_test("Direct I/O (Disk) - Unaligned Offset", true, false, false, true);

    // Cleanup
    unlink(TEST_FILE.c_str());

    return 0;
}
