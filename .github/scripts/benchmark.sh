#!/bin/bash
set -e

# Benchmark script for VeraCrypt CI

VC_BIN="veracrypt"
TEST_VOL="/tmp/bench.vc"
MOUNT_POINT="/mnt/vc_benchmark"
PASS="benchmark"
PIM="0"
SIZE="50M"

echo "### VeraCrypt Benchmark"
echo "Starting benchmark..."

# Create volume
echo "Creating volume..."
$VC_BIN --text --create "$TEST_VOL" --password "$PASS" --pim "$PIM" --hash sha512 --encryption aes --filesystem FAT --size "$SIZE" --volume-type normal --non-interactive

# Mount
echo "Mounting volume..."
mkdir -p "$MOUNT_POINT"
$VC_BIN --text --mount "$TEST_VOL" "$MOUNT_POINT" --password "$PASS" --pim "$PIM" --non-interactive

# Benchmark Write
echo "Benchmarking Write (dd)..."
DD_WRITE_OUT=$(dd if=/dev/zero of="$MOUNT_POINT/testfile" bs=1M count=40 oflag=direct 2>&1)
WRITE_SPEED=$(echo "$DD_WRITE_OUT" | grep -o '[0-9.]* [kKMG]B/s' | tail -n 1)
echo "Write Speed: $WRITE_SPEED"

# Benchmark Read
echo "Benchmarking Read (dd)..."
DD_READ_OUT=$(dd if="$MOUNT_POINT/testfile" of=/dev/null bs=1M count=40 iflag=direct 2>&1)
READ_SPEED=$(echo "$DD_READ_OUT" | grep -o '[0-9.]* [kKMG]B/s' | tail -n 1)
echo "Read Speed: $READ_SPEED"

# Unmount
echo "Unmounting..."
$VC_BIN --text --dismount "$TEST_VOL" --non-interactive

# Cleanup
rm -f "$TEST_VOL"

# Output to GITHUB_STEP_SUMMARY
if [ -n "$GITHUB_STEP_SUMMARY" ]; then
  echo "### VeraCrypt Benchmark Results" >> $GITHUB_STEP_SUMMARY
  echo "| Operation | Speed |" >> $GITHUB_STEP_SUMMARY
  echo "|-----------|-------|" >> $GITHUB_STEP_SUMMARY
  echo "| Write     | $WRITE_SPEED |" >> $GITHUB_STEP_SUMMARY
  echo "| Read      | $READ_SPEED |" >> $GITHUB_STEP_SUMMARY
fi
