#include "BinaryHeap.hpp"
#include <algorithm>

template <typename T>
int BinaryHeap<T>::compare(const T& x, const T& y) {
	if (x < y) return -1;
	if (x > y) return 1;
	return 0;
}

template <typename T>
BinaryHeap<T>::BinaryHeap(int capacity) : a(std::max(capacity, 1)), n(0) {}

template <typename T>
int BinaryHeap<T>::left(int idx) {
	return 2 * idx + 1;
}

template <typename T>
int BinaryHeap<T>::right(int idx) {
	return 2 * idx + 2;
}

template <typename T>
int BinaryHeap<T>::parent(int idx) {
	return (idx - 1) / 2;
}

template <typename T>
int BinaryHeap<T>::size() const {
	return n;
}

template <typename T>
bool BinaryHeap<T>::add(T x) {
	if (n + 1 > a.length_()) resize();
	a[n++] = x;
	bubbleUp(n - 1);
	return true;
}

template <typename T>
void BinaryHeap<T>::bubbleUp(int idx) {
	int p = parent(idx);
	while (idx > 0 && compare(a[idx], a[p]) < 0) {
		a.swap(idx, p);
		idx = p;
		p = parent(idx);
	}
}

template <typename T>
T BinaryHeap<T>::remove() {
	T x = a[0];
	a[0] = a[--n];
	trickleDown(0);
	if (3 * n < a.length_()) resize();
	return x;
}

template <typename T>
void BinaryHeap<T>::trickleDown(int idx) {
	do {
		int j = -1;
		int l = left(idx);
		int r = right(idx);

		// Find smallest element among current node and its children
		if (l < n && compare(a[l], a[idx]) < 0) {
			j = l;
		}
		if (r < n && compare(a[r], (j >= 0 ? a[j] : a[idx])) < 0) {
			j = r;
		}

		if (j >= 0) {
			a.swap(idx, j);
		}
		idx = j;
	} while (idx >= 0);
}

template <typename T>
void BinaryHeap<T>::resize() {
	array<T> b(std::max(2 * n, 1));
	for (int i = 0; i < n; i++) {
		b[i] = a[i];
	}
	a = b;
}
