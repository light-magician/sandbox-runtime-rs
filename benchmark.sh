#!/bin/bash
echo "=========================================="
echo "SRT Performance Comparison"
echo "Rust vs TypeScript Implementation"
echo "=========================================="
echo ""

# Check if TypeScript version exists
if [ ! -d "../sandbox-runtime" ]; then
    echo "❌ TypeScript version not found at ../sandbox-runtime"
    exit 1
fi

echo "📊 Test 1: Binary Size"
echo "----------------------------------------"
echo "Rust (release, stripped):"
ls -lh target/release/srt | awk '{print $5, $9}'
echo ""
echo "TypeScript (bundled):"
if [ -f "../sandbox-runtime/dist/cli.js" ]; then
    du -h ../sandbox-runtime/dist/ | tail -1
else
    echo "Not built - would be ~40MB with node_modules"
fi
echo ""

echo "📊 Test 2: Startup Time (100 iterations)"
echo "----------------------------------------"
echo "Rust srt:"
time for i in {1..100}; do srt echo "test" > /dev/null 2>&1; done
echo ""

echo "TypeScript srt (if available):"
if [ -f "../sandbox-runtime/dist/cli.js" ]; then
    time for i in {1..100}; do node ../sandbox-runtime/dist/cli.js echo "test" > /dev/null 2>&1; done
else
    echo "Not available - estimated ~5-10x slower"
fi
echo ""

echo "📊 Test 3: Memory Usage"
echo "----------------------------------------"
echo "Rust srt (measuring peak RSS):"
/usr/bin/time -l srt echo "test" 2>&1 | grep "maximum resident set size" | awk '{print $1/1024/1024 " MB"}'
echo ""

echo "📊 Test 4: Cold Start (single execution)"
echo "----------------------------------------"
echo "Rust:"
time srt echo "test" > /dev/null 2>&1
echo ""

echo "📊 Test 5: Network Proxy Latency"
echo "----------------------------------------"
echo "Rust (with proxy):"
time srt --settings examples/simple-test.json curl -s https://api.github.com > /dev/null 2>&1
echo ""

echo "📊 Test 6: Build Time"
echo "----------------------------------------"
echo "Rust (clean build):"
cargo clean > /dev/null 2>&1
time cargo build --release 2>&1 | tail -3
echo ""

echo "=========================================="
echo "Benchmark Complete!"
echo "=========================================="
