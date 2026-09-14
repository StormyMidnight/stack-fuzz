// mystack.hpp
//
// A fixed-capacity stack that throws exceptions for every failure mode
// instead of invoking undefined behavior. This is the "well-behaved"
// subject of the experiment: a correctky-guarded implementation should
// produce ZERO AFL++ crashes, no matter what byte stream it is fed,
// because every illegal operation is turned into a caught C++ exception
// rather than a memory fault.
//
// Compile with -DINJECT_BUG to plant a deliberate off-by-one bug in
// push(), which AFL++ (built with ASan/UBSan) should be able to find.
// This gives us a way to sanity-check that our fuzzing setup actually
// works before trusting a "no crashes found" result.

#include <cstddef>
#include <memory>
#include <stdexcept>
#include <string>

class StackFullException : public std::runtime_error {
public:
    explicit StackFullException(std::size_t capacity)
        : std::runtime_error("StackFullException: cannot push, capacity " +
                              std::to_string(capacity) + " reached") {}
};

class StackEmptyException : public std::runtime_error {
public:
    explicit StackEmptyException(const std::string& op)
        : std::runtime_error("StackEmptyException: cannot " + op + " an empty stack") {}
};

template <typename T, std::size_t Capacity>
class FixedStack {
public:
    // buf_ is heap-allocated (rather than a std::array member) on purpose:
    // ASan gives heap allocations a precise redzone matching their exact
    // requested size, so an off-by-one write at buf_[Capacity] is reliably
    // caught. A same-size array embedded directly in this object would
    // just silently corrupt whatever member follows it in memory instead
    // of tripping a sanitizer -- itself a lesson about what ASan can and
    // can't see.
    FixedStack() : buf_(std::make_unique<T[]>(Capacity)), top_(0) {}

    void push(const T& value) {
#ifdef INJECT_BUG
        // Deliberately planned bug: off-by-one allows one extra element
        // to be written past the end of buf_. Only enabled with
        // -DINJECT_BUG, used to validate the fuzzing harness itself.
        if (top_ > Capacity) {
            throw StackFullException(Capacity);
        }
#else
        if (top_ >= Capacity) {
            throw StackFullException(Capacity);
        }
#endif
        buf_[top_] = value;
        ++top_;
    }

    void pop() {
        if (top_ == 0) {
            throw StackEmptyException("pop");
        }
        --top_;
    }

    const T& top() const {
        if (top_ == 0) {
            throw StackEmptyException("top");
        }
        return buf_[top_ - 1];
    }

    bool empty() const { return top_ == 0; }
    bool full() const { return top_ == Capacity; }
    std::size_t size() const { return top_; }
    static constexpr std::size_t capacity() { return Capacity; }

private:
    std::unique_ptr<T[]> buf_;
    std::size_t top_;
};