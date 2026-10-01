#ifndef DATASTRUCTURES_BINARYHEAP_HPP
#define DATASTRUCTURES_BINARYHEAP_HPP

#include "Array.hpp"

template <typename T>
class BinaryHeap {
public:
	BinaryHeap(int capacity = 1);

	static int compare(const T& x, const T& y);
	static int left(int idx);
	static int right(int idx);
	static int parent(int idx);

	int size() const;
	bool add(T x);
	void bubbleUp(int idx);
	T remove();
	void trickleDown(int idx);
	void resize();

private:
	array<T> a;
	int n; // Changed from static int n to member variable
};

#include "BinaryHeap.cpp"

#endif //DATASTRUCTURES_BINARYHEAP_HPP
