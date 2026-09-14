#pragma once
// stack_op_factory.hpp
//
// StackOpFactory::decode() turns a raw byte buffer into a sequence of
// StackOp values (Push/Pop/Top), using the exact encoding the AFL++
// harnesses use to interpret their stdin:
//   byte % 4 == 0       -> Pop
//   byte % 4 == 1       -> Top
//   byte % 4 == 2 or 3  -> Push(byte)
//
// This exists as its own header/factory -- rather than being inlined
// separately into each harness -- for one reason: both
// harness/mystack_fuzz.cpp and harness/stlstack_fuzz.cpp, AND
// tools/stack_trace.cpp (the visualizer used by
// analysis/visualize_stacks.py), all include this same header and call
// the same decode() function. That guarantees the human-readable trace
// you get from the visualizer is decoding a given AFL testcase exactly
// the same way the real fuzzing harness did -- there's no second,
// hand-copied interpretation of the byte format that could quietly
// drift out of sync with the harness and mislead the analysis.

#include <cstddef>
#include <vector>

enum class OpType { Push, Pop, Top };

struct StackOp {
    OpType type;
    int value;  // only meaningful when type == OpType::Push
};

class StackOpFactory {
public:
    static std::vector<StackOp> decode(const std::vector<unsigned char>& bytes) {
        std::vector<StackOp> ops;
        ops.reserve(bytes.size());
        for (unsigned char b : bytes) {
            int sel = b % 4;
            if (sel == 0) {
                ops.push_back(StackOp{OpType::Pop, 0});
            } else if (sel == 1) {
                ops.push_back(StackOp{OpType::Top, 0});
            } else {
                ops.push_back(StackOp{OpType::Push, static_cast<int>(b)});
            }
        }
        return ops;
    }
};