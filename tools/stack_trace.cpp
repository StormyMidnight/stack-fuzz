// stack_trace.cpp
//
// Decodes a raw byte file (an AFL++ testcase -- a queue entry, a crash,
// a seed, anything) via the same StackOpFactory the fuzzing harnesses
// use, then replays the resulting operations against either FixedStack
// or StlStackWrapper, printing each operation and the stack's contents
// as it goes. This is the piece analysis/visualize_stacks.py shells out
// to, but it's also just directly useful on its own to answer "what did
// this specific input actually do?"
//
// For the mystack target this is a completely faithful replay: every
// operation FixedStack executes here is exactly what the real AFL
// harness would have executed, including the exceptions it throws.
//
// For the stlstack target, this tool is DELIBERATELY less faithful in
// one respect: it does not actually call pop()/top() on an empty
// std::stack, because that's undefined behavior and this is meant to be
// a safe viewer you can run over an entire queue directory without it
// segfaulting partway through. Where the real AFL harness would hit
// that UB, this tool prints a note instead and continues. That
// divergence is called out explicitly in the output so it's never
// mistaken for a faithful replay.
//
// Usage:
//   stack_trace --target mystack|stlstack [--file PATH]
//   (reads stdin if --file is omitted or is "-")
//
// Output ends with a single "-- summary: ..." line of key=value pairs
// that analysis/visualize_stacks.py parses to compute aggregate stats
// across many testcases; keep that line's format stable if you edit
// this file.

#include <algorithm>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
#include <string>
#include <vector>

#include "../include/mystack.hpp"
#include "stack_op_factory.hpp"
#include "../include/stl_stack_wrapper.hpp"

namespace {

std::vector<unsigned char> read_all(std::istream& in) {
    return std::vector<unsigned char>((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

std::string format_vec(const std::vector<int>& v) {
    std::ostringstream oss;
    oss << "[";
    for (std::size_t i = 0; i < v.size(); ++i) {
        if (i) oss << ", ";
        oss << v[i];
    }
    oss << "]";
    return oss.str();
}

void trace_mystack(const std::vector<StackOp>& ops) {
    constexpr std::size_t kCapacity = 16;
    FixedStack<int, kCapacity> s;
    std::vector<int> mirror;  // shadows s's contents, purely for display
 
    std::size_t pushes = 0, pops = 0, tops = 0;
    std::size_t rejected_full = 0, rejected_empty_pop = 0, rejected_empty_top = 0;
    std::size_t max_size = 0;
    bool reached_full = false;
 
    for (std::size_t i = 0; i < ops.size(); ++i) {
        const auto& op = ops[i];
        std::cout << "op " << (i + 1) << ": ";
        if (op.type == OpType::Push) {
            ++pushes;
            try {
                s.push(op.value);
                mirror.push_back(op.value);
                max_size = std::max(max_size, mirror.size());
                if (s.full()) reached_full = true;
                std::cout << "PUSH " << op.value << " -> " << format_vec(mirror)
                          << " (size " << mirror.size() << "/" << kCapacity << ")\n";
            } catch (const StackFullException& e) {
                ++rejected_full;
                std::cout << "PUSH " << op.value << " -> REJECTED: " << e.what() << "\n";
            }
        } else if (op.type == OpType::Pop) {
            ++pops;
            try {
                s.pop();
                mirror.pop_back();
                std::cout << "POP  -> " << format_vec(mirror) << " (size " << mirror.size()
                          << "/" << kCapacity << ")\n";
            } catch (const StackEmptyException& e) {
                ++rejected_empty_pop;
                std::cout << "POP  -> REJECTED: " << e.what() << "\n";
            }
        } else {  // Top
            ++tops;
            try {
                int v = s.top();
                std::cout << "TOP  -> " << v << ", stack=" << format_vec(mirror) << "\n";
            } catch (const StackEmptyException& e) {
                ++rejected_empty_top;
                std::cout << "TOP  -> REJECTED: " << e.what() << "\n";
            }
        }
    }
 
    std::cout << "-- summary: pushes=" << pushes << " pops=" << pops << " tops=" << tops
              << " rejected_full=" << rejected_full
              << " rejected_empty_pop=" << rejected_empty_pop
              << " rejected_empty_top=" << rejected_empty_top << " max_size=" << max_size
              << " reached_full=" << (reached_full ? "yes" : "no")
              << " final_size=" << mirror.size() << "\n";
}

void trace_stlstack(const std::vector<StackOp>& ops) {
    StlStackWrapper s;
    std::vector<int> mirror;
 
    std::size_t pushes = 0, pops = 0, tops = 0;
    std::size_t ub_would_pop = 0, ub_would_top = 0;
    std::size_t max_size = 0;
 
    for (std::size_t i = 0; i < ops.size(); ++i) {
        const auto& op = ops[i];
        std::cout << "op " << (i + 1) << ": ";
        if (op.type == OpType::Push) {
            ++pushes;
            s.push(op.value);
            mirror.push_back(op.value);
            max_size = std::max(max_size, mirror.size());
            std::cout << "PUSH " << op.value << " -> " << format_vec(mirror) << " (size "
                      << mirror.size() << ")\n";
        } else if (op.type == OpType::Pop) {
            ++pops;
            if (mirror.empty()) {
                ++ub_would_pop;
                std::cout << "POP  -> UB: pop() on an empty std::stack (NOT executed by this "
                             "viewer -- the real AFL harness calls it unguarded and relies on "
                             "ASan/UBSan to catch it)\n";
            } else {
                s.pop();
                mirror.pop_back();
                std::cout << "POP  -> " << format_vec(mirror) << " (size " << mirror.size()
                          << ")\n";
            }
        } else {  // Top
            ++tops;
            if (mirror.empty()) {
                ++ub_would_top;
                std::cout << "TOP  -> UB: top() on an empty std::stack (NOT executed by this "
                             "viewer)\n";
            } else {
                int v = s.top();
                std::cout << "TOP  -> " << v << ", stack=" << format_vec(mirror) << "\n";
            }
        }
    }
 
    std::cout << "-- summary: pushes=" << pushes << " pops=" << pops << " tops=" << tops
              << " ub_would_pop=" << ub_would_pop << " ub_would_top=" << ub_would_top
              << " max_size=" << max_size << " final_size=" << mirror.size() << "\n";
}

} // namespace

int main(int argc, char** argv) {
    std::string target;
    std::string path;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--target" && i + 1 < argc) {
            target = argv[++i];
        } else if (a == "--file" && i + 1 < argc) {
            path = argv[++i];
        } else {
            std::cerr << "Unknown argument: " << a << "\n";
            return 2;
        }
    }
    if (target != "mystack" && target != "stlstack") {
        std::cerr << "Usage: stack_trace --target mystack|stlstack [--file PATH]\n"
                      "(reads stdin if --file is omitted or is \"-\")\n";
        return 2;
    }
 
    std::vector<unsigned char> bytes;
    if (path.empty() || path == "-") {
        bytes = read_all(std::cin);
    } else {
        std::ifstream f(path, std::ios::binary);
        if (!f) {
            std::cerr << "Cannot open " << path << "\n";
            return 1;
        }
        bytes = read_all(f);
    }
 
    auto ops = StackOpFactory::decode(bytes);
    std::cout << bytes.size() << " byte(s) decoded into " << ops.size() << " operation(s)\n";
 
    if (target == "mystack") {
        trace_mystack(ops);
    } else {
        trace_stlstack(ops);
    }
    return 0;
}