//
// Created by marle on 10/1/2026.
//

#include "ArrayList.hpp"

template <typename T>
void ArrayList<T>::reallocate(size_t new_capacity) {
	T* new_data = new T[new_capacity];

	for (size_t i = 0; i < size_; ++i) {
		new_data[i] = std::move(data[i]);
	}

	delete[] data;
	data = new_data;
	capacity_ = new_capacity;
}

template <typename T>
ArrayList<T>::ArrayList() {
	reallocate(2);
}

template <typename T>
ArrayList<T>::~ArrayList() {
	delete[] data;
}

template <typename T>
ArrayList<T>::ArrayList(const ArrayList& other) : size_(other.size_), capacity_(other.capacity_) {
	data = new T[capacity_];
	for (size_t i = 0; i < size_; ++i) {
		data[i] = other.data[i];
	}
}

template <typename T>
ArrayList<T>& ArrayList<T>::operator=(const ArrayList& other) {
	if (this != &other) {
		delete[] data;
		size_ = other.size_;
		capacity_ = other.capacity_;
		data = new T[capacity_];
		for (size_t i = 0; i < size_; ++i) {
			data[i] = other.data[i];
		}
	}
	return *this;
}

template <typename T>
void ArrayList<T>::push_back(const T& value) {
	if (size_ >= capacity_) {
		reallocate(capacity_ * 2);
	}
	data[size_] = value;
	size_++;
}

template <typename T>
void ArrayList<T>::pop_back() {
	if (size_ > 0) {
		size_--;
	}
}

template <typename T>
T& ArrayList<T>::operator[](size_t index) { return data[index]; }

template <typename T>
const T& ArrayList<T>::operator[](size_t index) const { return data[index]; }

template <typename T>
T& ArrayList<T>::at(size_t index) {
	if (index >= size_) {
		throw std::out_of_range("ArrayList index out of bounds");
	}
	return data[index];
}

template <typename T>
size_t ArrayList<T>::size() const { return size_; }

template <typename T>
size_t ArrayList<T>::capacity() const { return capacity_; }

template <typename T>
bool ArrayList<T>::empty() const { return size_ == 0; }
