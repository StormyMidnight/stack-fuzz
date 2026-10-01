#include "Array.hpp"
#include <algorithm>
#include <cassert>
#include <cstddef>

template <typename T>
array<T>::array(int len) : length(len), a(new T[len]{}) {}

template <typename T>
array<T>::~array() {
	delete[] a;
}

template <typename T>
T& array<T>::operator[](int i) {
	assert(i >= 0 && i < length);
	return a[i];
}

template <typename T>
const T& array<T>::operator[](int i) const {
	assert(i >= 0 && i < length);
	return a[i];
}

template <typename T>
array<T>& array<T>::operator=(array<T> &b) {
	if (this != &b) {
		delete[] a;
		a = b.a;
		b.a = nullptr;
		length = b.length;
		b.length = 0;
	}
	return *this;
}

template <typename T>
void array<T>::resize() {
	array<T> b(std::max(2 * length, 1));
	for (int i = 0; i < length; i++) {
		b[i] = a[i];
	}
	*this = b;
}
