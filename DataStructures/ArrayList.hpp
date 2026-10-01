//
// Created by marle on 10/1/2026.
//

#ifndef DATASTRUCTURES_ARRAYLIST_HPP
#define DATASTRUCTURES_ARRAYLIST_HPP

#include <iostream>
#include <stdexcept>
#include <cstddef>

template <typename T>
class ArrayList {
private:
	T* data = nullptr;
	size_t size_ = 0;
	size_t capacity_ = 0;

	void reallocate(size_t new_capacity);

public:
	ArrayList();
	~ArrayList();
	ArrayList(const ArrayList& other);
	ArrayList& operator=(const ArrayList& other);
	void push_back(const T& value);
	void pop_back();

	T& operator[](size_t index);
	const T& operator[](size_t index) const;

	T& at(size_t index);

	size_t size() const;
	size_t capacity() const;
	bool empty() const;
};

#include "ArrayList.cpp"

#endif //DATASTRUCTURES_ARRAYLIST_HPP
