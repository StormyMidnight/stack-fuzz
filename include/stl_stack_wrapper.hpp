#pragma once
// stl_stack_wrapper.hpp
//
// This wraps std::stack<int> the way an unguarded/naive implementation
// would use it: push() always succeeds (std::stack is backed by
// std::deque by default and grows without a fixed limit), and pop()/top()
// are called with NO check for emptiness. Per the C++ standard, calling
// pop() or top() on an empty std::stack is undefined behavior -- it does
// NOT throw. That asymmetry with FixedStack is the point of the
// comparison: one subject fails via a caught exception, the otheer fails
// via UB that only a sanitizer (or bad luck) will turn into an observable
// crash.
//
// Note there is no "full" failure mode here at all: std::stack has no
// fixed capacity, so it can't be fuzzed for a full-stack condition the
// way FixedStack can.

#include <stack>

class StlStackWrapper {
public:
    void push(int value) { s_.push(value); }

    // No emptiness check on purpose -- mirrors code that assumes the
    // caller "knows" the stack isn't empty. UB if s_ is empty.
    void pop() { s_.pop(); }

    // Same: UB on empty stack.
    int top() const { return s_.top(); }

    bool empty() const { return s_.empty(); }
    std::size_t size() const { return s_.size(); }

private:
    std::stack<int> s_;
};