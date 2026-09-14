// mystack_fuzz.cpp
//
// AFL++ target for FixedStack. Reads all of stdin, decodes it into a
// sequence of stack operations via StackOpFactory (the same factory the
// stack_trace visualizer uses -- see include/stack_op_factory.hpp for
// why that's shared rather than duplicated), then replays those
// operations against the stack.
//
// StackFullException and StackEmptyException are EXPECTED outcomes and
// are caught here -- they represent the exception-throwing contract
// working correctly, not a bug. Anything else (a crash, an unexpected
// exception type, an ASan/UBSan report) is a genuine finding.
//
// Build normally:
//   g++ -std=c++17 -I../include -o mystack_fuzz mystack_fuzz.cpp
// Build for AFL++ (see Makefile):
//   afl-clang-fast++ -std=c++17 -I../include -o mystack_fuzz mystack_fuzz.cpp
// Build with the planted bug enabled (for validating your setup):
//   afl-clang-fast++ -std=c++17 -DINJECT_BUG -I../include -o mystack_fuzz_buggy mystack_fuzz.cpp

#include <iostream>
#include <iterator>
#include <vector>
#include "mystack.hpp"
#include "stack_op_factory.hpp"

// Small capacity on purpose: with a tiny stack, "full" and "empty" edge
// cases are only a handful of operations away, which gives AFL++ a
// realistic chance of reaching them via random mutation instead of
// needing to get lucky with a long, precise byte sequence.
constexpr std::size_t kCapacity = 16;

int main() {
    std::vector<unsigned char> bytes(
        (std::istreambuf_iterator<char>(std::cin)),
        std::istreambuf_iterator<char>());
    auto ops = StackOpFactory::decode(bytes);

    FixedStack<int, kCapacity> s;
    for (const auto& op : ops) {
        try {
            if (op.type == OpType::Pop) {
                s.pop();
            } else if (op.type == OpType::Top) {
                (void)s.top();
            } else {
                s.push(op.value);
            }
        } catch (const StackFullException&) {
            // Expected: not a bug.
        } catch (const StackEmptyException&) {
            // Expected: not a bug.
        }
        // Deliberately NOT catching (...) here. If FixedStack ever
        // throws something other than the two exception types above,
        // or corrupts memory instead of throwing, we want that to
        // propagate and register as a crash/abort so AFL++ flags it.
    }
    return 0;
}