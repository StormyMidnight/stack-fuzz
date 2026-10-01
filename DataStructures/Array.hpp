#ifndef DATASTRUCTURES_ARRAY_HPP
#define DATASTRUCTURES_ARRAY_HPP

#include <algorithm>

template <typename T>
class array {
public:
	array() : a(nullptr), length(0) {} // Default constructor
	array(int len);
	~array();

	T& operator[](int i);
	const T& operator[](int i) const;

	array<T>& operator=(array<T> &b);

	int length_() const { return length; } // Public getter for length

	void swap(int i, int j) {
		std::swap(a[i], a[j]);
	}

	void resize();

private:
	T *a;
	int length;
};

#include "Array.cpp"

#endif //DATASTRUCTURES_ARRAY_HPP
