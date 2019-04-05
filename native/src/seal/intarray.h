// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/memorymanager.h"
#include "seal/util/pointer.h"
#include "seal/util/defines.h"
#include "seal/util/common.h"
#include <type_traits>
#include <algorithm>
#include <limits>
#include <iostream>
#include <cstring>

namespace seal
{
    /**
    A resizable container for storing an array of integral data types. The
    allocations are done from a memory pool. The IntArray class is mainly
    intended for internal use and provides the underlying data structure for
    Plaintext and Ciphertext classes.

    @par Size and Capacity
    IntArray allows the user to pre-allocate memory (capacity) for the array
    in cases where the array is known to be resized in the future and memory
    moves are to be avoided at the time of resizing. The size of the IntArray
    can never exceed its capacity. The capacity and size can be changed using
    the reserve and resize functions, respectively.

    @par Thread Safety
    In general, reading from IntArray is thread-safe as long as no other thread
    is concurrently mutating it.
    */
    template<typename T_, typename = std::enable_if_t<std::is_integral<T_>::value>>
    class IntArray
    {
    public:
        using size_type = std::size_t;
        using T = typename std::decay<T_>::type;

        /**
        Creates a new IntArray. No memory is allocated by this constructor.

        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if pool is uninitialized
        */
        IntArray(MemoryPoolHandle pool = MemoryManager::GetPool()) :
            pool_(std::move(pool))
        {
            if (!pool_)
            {
                throw std::invalid_argument("pool is uninitialized");
            }
        }

        /**
        Creates a new IntArray with given size.

        @param[in] size The size of the array
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if size is less than zero
        @throws std::invalid_argument if pool is uninitialized
        */
        explicit IntArray(size_type size,
            MemoryPoolHandle pool = MemoryManager::GetPool()) :
            pool_(std::move(pool))
        {
            if (!pool_)
            {
                throw std::invalid_argument("pool is uninitialized");
            }

            // Reserve memory, resize, and set to zero
            resize(size);
        }

        /**
        Creates a new IntArray with given capacity and size.

        @param[in] capacity The capacity of the array
        @param[in] size The size of the array
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if capacity is less than size
        @throws std::invalid_argument if capacity is less than zero
        @throws std::invalid_argument if size is less than zero
        @throws std::invalid_argument if pool is uninitialized
        */
        explicit IntArray(size_type capacity, size_type size,
            MemoryPoolHandle pool = MemoryManager::GetPool()) :
            pool_(std::move(pool))
        {
            if (!pool_)
            {
                throw std::invalid_argument("pool is uninitialized");
            }
            if (capacity < size)
            {
                throw std::invalid_argument("capacity cannot be smaller than size");
            }

            // Reserve memory, resize, and set to zero
            reserve(capacity);
            resize(size);
        }

        /**
        Constructs a new IntArray by copying a given one.

        @param[in] copy The IntArray to copy from
        */
        IntArray(const IntArray<T> &copy) :
            pool_(MemoryManager::GetPool()),
            capacity_(copy.size_),
            size_(copy.size_),
            data_(util::allocate<T>(copy.size_, pool_))
        {
            // Copy over value
            std::copy_n(copy.cbegin(), copy.size_, begin());
        }

        /**
        Constructs a new IntArray by moving a given one.

        @param[in] source The IntArray to move from
        */
        IntArray(IntArray<T> &&source) noexcept :
            pool_(std::move(source.pool_)),
            capacity_(source.capacity_),
            size_(source.size_),
            data_(std::move(source.data_))
        {
        }

        /**
        Returns a pointer to the beginning of the array data.
        */
        inline T* begin() noexcept
        {
            return data_.get();
        }

        /**
        Returns a constant pointer to the beginning of the array data.
        */
        inline const T* cbegin() const noexcept
        {
            return data_.get();
        }

        /**
        Returns a pointer to the end of the array data.
        */
        inline T* end() noexcept
        {
            return size_ ? begin() + size_ : begin();
        }

        /**
        Returns a constant pointer to the end of the array data.
        */
        inline const T* cend() const noexcept
        {
            return size_ ? cbegin() + size_ : cbegin();
        }
#ifdef SEAL_USE_MSGSL_SPAN
        /**
        Returns a span pointing to the beginning of the IntArray.
        */
        inline gsl::span<T> span()
        {
            return gsl::span<T>(
                begin(), static_cast<std::ptrdiff_t>(size_));
        }

        /**
        Returns a span pointing to the beginning of the IntArray.
        */
        inline gsl::span<const T> span() const
        {
            return gsl::span<const T>(
                cbegin(), static_cast<std::ptrdiff_t>(size_));
        }
#endif
        /**
        Returns a constant reference to the array element at a given index.
        This function performs bounds checking and will throw an error if
        the index is out of range.

        @param[in] index The index of the array element
        @throws std::out_of_range if index is out of range
        */
        inline const T &at(size_type index) const
        {
            if (index >= size_)
            {
                throw std::out_of_range("index must be within [0, size)");
            }
            return data_[index];
        }

        /**
        Returns a reference to the array element at a given index. This
        function performs bounds checking and will throw an error if the
        index is out of range.

        @param[in] index The index of the array element
        @throws std::out_of_range if index is out of range
        */
        inline T &at(size_type index)
        {
            if (index >= size_)
            {
                throw std::out_of_range("index must be within [0, size)");
            }
            return data_[index];
        }

        /**
        Returns a constant reference to the array element at a given index.
        This function does not perform bounds checking.

        @param[in] index The index of the array element
        */
        inline const T &operator [](size_type index) const
        {
            return data_[index];
        }

        /**
        Returns a reference to the array element at a given index. This
        function does not perform bounds checking.

        @param[in] index The index of the array element
        */
        inline T &operator [](size_type index)
        {
            return data_[index];
        }

        /**
        Returns whether the array has size zero.
        */
        inline bool empty() const noexcept
        {
            return (size_ == 0);
        }

        /**
        Returns the largest possible array size.
        */
        inline size_type max_size() const noexcept
        {
            return std::numeric_limits<size_type>::max();
        }

        /**
        Returns the size of the array.
        */
        inline size_type size() const noexcept
        {
            return size_;
        }

        /**
        Returns the capacity of the array.
        */
        inline size_type capacity() const noexcept
        {
            return capacity_;
        }

        /**
        Returns the currently used MemoryPoolHandle.
        */
        inline MemoryPoolHandle pool() const noexcept
        {
            return pool_;
        }

        /**
        Releases any allocated memory to the memory pool and sets the size
        and capacity of the array to zero.
        */
        inline void release() noexcept
        {
            capacity_ = 0;
            size_ = 0;
            data_.release();
        }

        /**
        Sets the size of the array to zero. The capacity is not changed.
        */
        inline void clear() noexcept
        {
            size_ = 0;
        }

        /**
        Allocates enough memory for storing a given number of elements without
        changing the size of the array. If the given capacity is smaller than
        the current size, the size is automatically set to equal the new capacity.

        @param[in] capacity The capacity of the array
        */
        inline void reserve(size_type capacity)
        {
            size_type copy_size = std::min(capacity, size_);

            // Create new allocation and copy over value
            auto new_data(util::allocate<T>(capacity, pool_));
            std::copy_n(cbegin(), copy_size, new_data.get());
            std::swap(data_, new_data);

            // Set the coeff_count and capacity
            capacity_ = capacity;
            size_ = copy_size;
        }

        /**
        Reallocates the array so that its capacity exactly matches its size.
        */
        inline void shrink_to_fit()
        {
            reserve(size_);
        }

        /**
        Resizes the array to given size. When resizing to larger size the data
        in the array remains unchanged and any new space is initialized to zero;
        when resizing to smaller size the last elements of the array are dropped.
        If the capacity is not already large enough to hold the new size, the
        array is also reallocated.

        @param[in] size The size of the array
        */
        inline void resize(size_type size)
        {
            if (size <= capacity_)
            {
                // Are we changing size to bigger within current capacity?
                // If so, need to set top terms to zero
                if (size > size_)
                {
                    std::fill(end(), begin() + size, T{ 0 });
                }

                // Set the size
                size_ = size;

                return;
            }

            // At this point we know for sure that size_ <= capacity_ < size so need
            // to reallocate to bigger
            auto new_data(util::allocate<T>(size, pool_));
            std::copy_n(cbegin(), size_, new_data.get());
            std::fill(new_data.get() + size_, new_data.get() + size, T{ 0 });
            std::swap(data_, new_data);

            // Set the coeff_count and capacity
            capacity_ = size;
            size_ = size;
        }

        /**
        Copies a given IntArray to the current one.

        @param[in] assign The IntArray to copy from
        */
        inline IntArray<T> &operator =(const IntArray<T> &assign)
        {
            // Check for self-assignment
            if (this == &assign)
            {
                return *this;
            }

            // First resize to correct size
            resize(assign.size_);

            // Size is guaranteed to be OK now so copy over
            std::copy_n(assign.cbegin(), assign.size_, begin());

            return *this;
        }

        /**
        Moves a given IntArray to the current one.

        @param[in] assign The IntArray to move from
        */
        IntArray<T> &operator =(IntArray<T> &&assign) noexcept
        {
            pool_ = std::move(assign.pool_);
            capacity_ = assign.capacity_;
            size_ = assign.size_;
            data_ = std::move(assign.data_);

            return *this;
        }

        /**
        Saves the IntArray to an output stream. The output is in binary format
        and not human-readable. The output stream must have the "binary" flag set.

        @param[in] stream The stream to save the IntArray to
        @throws std::exception if the IntArray could not be written to stream
        */
        inline void save(std::ostream &stream) const
        {
            auto old_except_mask = stream.exceptions();
            try
            {
                // Throw exceptions on std::ios_base::badbit and std::ios_base::failbit
                stream.exceptions(std::ios_base::badbit | std::ios_base::failbit);

                std::uint64_t size64 = size_;
                stream.write(reinterpret_cast<const char*>(&size64), sizeof(std::uint64_t));
                stream.write(reinterpret_cast<const char*>(cbegin()),
                    util::safe_cast<std::streamsize>(
                        util::mul_safe(size_, util::safe_cast<size_type>(sizeof(T)))));
            }
            catch (const std::exception &)
            {
                stream.exceptions(old_except_mask);
                throw;
            }

            stream.exceptions(old_except_mask);
        }

        /**
        Loads a IntArray from an input stream overwriting the current IntArray.

        @param[in] stream The stream to load the IntArray from
        @throws std::exception if a valid IntArray could not be read from stream
        */
        inline void load(std::istream &stream)
        {
            auto old_except_mask = stream.exceptions();
            try
            {
                // Throw exceptions on std::ios_base::badbit and std::ios_base::failbit
                stream.exceptions(std::ios_base::badbit | std::ios_base::failbit);

                std::uint64_t size64 = 0;
                stream.read(reinterpret_cast<char*>(&size64), sizeof(std::uint64_t));

                // Set new size
                resize(util::safe_cast<size_type>(size64));

                // Read data
                stream.read(reinterpret_cast<char*>(begin()),
                    util::safe_cast<std::streamsize>(
                        util::mul_safe(size_, util::safe_cast<size_type>(sizeof(T)))));
            }
            catch (const std::exception &)
            {
                stream.exceptions(old_except_mask);
                throw;
            }

            stream.exceptions(old_except_mask);
        }

    private:
        MemoryPoolHandle pool_;

        size_type capacity_ = 0;

        size_type size_ = 0;

        util::Pointer<T> data_;
    };
}
