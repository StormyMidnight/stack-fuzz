// stlstack_fuzz.cpp
//
// AFL++ target for StlStackWrapper. Reads all of stdin, decodes it into
// a sequence of stack operations via StackOpFactory -- the SAME factory
// mystack_fuzz.cpp and the stack_trace visualizer use -- so the two
// fuzzing campaigns are directly comparable and any AFL testcase can be
// decoded identically regardless of which tool is reading it:
//   byte % 4 == 0  -> pop()
//   byte % 4 == 1  -> top()
//   byte % 4 == 2,3 -> push(b)
//
// There is no try/catch here. pop()/top() on an empty std::stack is
// undefined behavior, not an exception, so there is nothing well-defined
// to catch. Whether AFL++ reports a crash for this depends heavily on
// whether the binary is built with ASan/UBSan (see Makefile) -- a plain
// optimized build may quietly read/write invalid memory without ever
// segfaulting, which is itself a result worth writing up.
//
// Build normally:
//   g++ -std=c++17 -I../include -o stlstack_fuzz stlstack_fuzz.cpp
// Build for AFL++ with ASan (recommended, see Makefile):
//   AFL_USE_ASAN=1 afl-clang-fast++ -std=c++17 -I../include -o stlstack_fuzz stlstack_fuzz.cpp

#include <iostream>
#include <iterator>
#include <vector>
#include "stl_stack_wrapper.hpp"
#include "stack_op_factory.hpp"

int main() {
    std::vector<unsigned char> bytes(
        (std::istreambuf_iterator<char>(std::cin)),
        std::istreambuf_iterator<char>());
    auto ops = StackOpFactory::decode(bytes);

    StlStackWrapper s;
    for (const auto& op : ops) {
        if (op.type == OpType::Pop) {
            s.pop();
        } else if (op.type == OpType::Top) {
            (void)s.top();
        } else {
            s.push(op.value);
        }
    }
    return 0;
}