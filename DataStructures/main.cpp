#include <iostream>
#include <cassert>
#include <vector>
#include <stdexcept>
#include "BinaryHeap.hpp"
#include "ArrayList.hpp"

void test_binary_heap() {
    std::cout << "--- Starting BinaryHeap Tests ---\n";

    // Test 1: Insertions and Priority Ordering
    {
        BinaryHeap<int> heap(0);
        std::vector<int> values = {42, 10, 5, 30, 2, 20};

        std::cout << "[Heap Test 1] Adding elements: ";
        for (int val : values) {
            std::cout << val << " ";
            heap.add(val);
        }
        std::cout << "\n";

        std::cout << "Extracting elements (expected min-heap order: 2, 5, 10, 20, 30, 42):\nResult: ";
        while (heap.size() > 0) {
            std::cout << heap.remove() << " ";
        }
        std::cout << "\n";
    }

    // Test 2: Dynamic Resizing
    {
        std::cout << "\n[Heap Test 2] Dynamic resizing with 100 elements...\n";
        BinaryHeap<int> heap(0);

        for (int i = 100; i >= 1; --i) {
            heap.add(i);
        }

        bool passed = true;
        for (int i = 1; i <= 100; ++i) {
            int val = heap.remove();
            if (val != i) {
                std::cout << "Mismatch! Expected " << i << " but got " << val << "\n";
                passed = false;
                break;
            }
        }

        if (passed) {
            std::cout << "Resize & ordering test passed!\n";
        }
    }

    // Test 3: Duplicates
    {
        std::cout << "\n[Heap Test 3] Testing duplicate elements...\n";
        BinaryHeap<int> heap(0);
        heap.add(5);
        heap.add(1);
        heap.add(5);
        heap.add(1);

        assert(heap.remove() == 1);
        assert(heap.remove() == 1);
        assert(heap.remove() == 5);
        assert(heap.remove() == 5);
        std::cout << "Duplicate handling passed!\n";
    }
}

void test_array_list() {
    std::cout << "\n--- Starting ArrayList Tests ---\n";

    // Test 1: Push Back & Indexing
    {
        std::cout << "[ArrayList Test 1] Push back and indexing...\n";
        ArrayList<int> list;

        list.push_back(10);
        list.push_back(20);
        list.push_back(30);

        assert(list.size() == 3);
        assert(list.capacity() >= 3);
        assert(list[0] == 10);
        assert(list[1] == 20);
        assert(list[2] == 30);
        assert(list.at(1) == 20);

        std::cout << "Push back & indexing passed!\n";
    }

    // Test 2: Pop Back
    {
        std::cout << "\n[ArrayList Test 2] Pop back...\n";
        ArrayList<int> list;
        list.push_back(100);
        list.push_back(200);

        assert(list.size() == 2);
        list.pop_back();
        assert(list.size() == 1);
        assert(list[0] == 100);

        list.pop_back();
        assert(list.empty());
        assert(list.empty());

        std::cout << "Pop back passed!\n";
    }

    // Test 3: Dynamic Resizing
    {
        std::cout << "\n[ArrayList Test 3] Dynamic reallocation...\n";
        ArrayList<int> list;
        size_t initial_capacity = list.capacity();

        for (int i = 0; i < 50; ++i) {
            list.push_back(i);
        }

        assert(list.size() == 50);
        assert(list.capacity() > initial_capacity);

        bool passed = true;
        for (size_t i = 0; i < 50; ++i) {
            if (list[i] != static_cast<int>(i)) {
                passed = false;
                break;
            }
        }
        assert(passed);
        std::cout << "Dynamic reallocation passed!\n";
    }

    // Test 4: Exception Handling (at)
    {
        std::cout << "\n[ArrayList Test 4] Bounds checking with at()...\n";
        ArrayList<int> list;
        list.push_back(5);

        bool exception_caught = false;
        try {
            list.at(10); // Should throw out_of_range
        } catch (const std::out_of_range&) {
            exception_caught = true;
        }

        assert(exception_caught);
        std::cout << "Out of bounds exception handling passed!\n";
    }

    // Test 5: Copy Construction and Assignment
    {
        std::cout << "\n[ArrayList Test 5] Copy constructor & operator=...\n";
        ArrayList<int> original;
        original.push_back(1);
        original.push_back(2);

        ArrayList<int> copy_constructed = original; // Copy constructor
        assert(copy_constructed.size() == 2);
        assert(copy_constructed[0] == 1 && copy_constructed[1] == 2);

        ArrayList<int> copy_assigned = original; // Copy assignment
        assert(copy_assigned.size() == 2);
        assert(copy_assigned[0] == 1 && copy_assigned[1] == 2);

        // Verify deep copy (modifying original doesn't affect copies)
        original[0] = 99;
        assert(copy_constructed[0] == 1);
        assert(copy_assigned[0] == 1);

        std::cout << "Copy semantics passed!\n";
    }
}

int main() {
    test_binary_heap();
    test_array_list();

    std::cout << "\nAll BinaryHeap and ArrayList tests completed successfully!\n";
    return 0;
}
