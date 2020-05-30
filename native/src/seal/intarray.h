// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/memorymanager.h"
#include "seal/serialization.h"
#include "seal/util/common.h"
#include "seal/util/defines.h"
#include "seal/util/pointer.h"
#include <algorithm>
#include <cstring>
#include <iostream>
#include <limits>
#include <type_traits>
#ifdef SEAL_USE_MSGSL
#include <gsl/span>
#endif

namespace seal
{
    class Ciphertext;

    // Forward-declaring the deflate_size_bound function
    namespace util
    {
        namespace ztools
        {
            template <typename SizeT>
            SEAL_NODISCARD SizeT deflate_size_bound(SizeT in_size);
        } // namespace ztools
    }     // namespace util

    /**
    A resizable container for storing an array of arithmetic data types or
    SEAL_BYTE types (e.g., std::byte). The allocations are done from a memory
    pool. The IntArray class is mainly intended for internal use and provides
    the underlying data structure for Plaintext and Ciphertext classes.

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
    template <
        typename T_,
        typename = std::enable_if_t<
            std::is_arithmetic<T_>::value || std::is_same<typename std::decay<T_>::type, SEAL_BYTE>::value>>
    class IntArray
    {
        friend class Ciphertext;

    public:
        using T = typename std::decay<T_>::type;

        /**
        Creates a new IntArray. No memory is allocated by this constructor.

        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if pool is uninitialized
        */
        IntArray(MemoryPoolHandle pool = MemoryManager::GetPool()) : pool_(std::move(pool))
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
        @throws std::invalid_argument if pool is uninitialized
        */
        explicit IntArray(std::size_t size, MemoryPoolHandle pool = MemoryManager::GetPool()) : pool_(std::move(pool))
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
        @throws std::invalid_argument if pool is uninitialized
        */
        explicit IntArray(std::size_t capacity, std::size_t size, MemoryPoolHandle pool = MemoryManager::GetPool())
            : pool_(std::move(pool))
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
        Creates a new IntArray with given size wrapping a given pointer. This
        constructor allocates no memory. If the IntArray goes out of scope, the
        Pointer object given here is destroyed. On resizing the IntArray to larger
        size, the data will be copied over to a new allocation from the memory pool
        pointer to by the given MemoryPoolHandle and the Pointer object given here
        will subsequently be destroyed. Unlike the other constructors, this one
        exposes the option of not automatically zero-filling the allocated memory.

        @param[in] ptr An initial Pointer object to wrap
        @param[in] capacity The capacity of the array
        @param[in] size The size of the array
        @param[in] fill_zero If true, fills ptr with zeros
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if ptr is null and capacity is positive
        @throws std::invalid_argument if capacity is less than size
        @throws std::invalid_argument if pool is uninitialized
        */
        explicit IntArray(
            util::Pointer<T> &&ptr, std::size_t capacity, std::size_t size, bool fill_zero,
            MemoryPoolHandle pool = MemoryManager::GetPool())
            : pool_(std::move(pool)), capacity_(capacity)
        {
            if (!ptr && capacity)
            {
                throw std::invalid_argument("ptr cannot be null");
            }
            if (!pool_)
            {
                throw std::invalid_argument("pool is uninitialized");
            }
            if (capacity < size)
            {
                throw std::invalid_argument("capacity cannot be smaller than size");
            }

            // Grab the given Pointer
            data_ = std::move(ptr);

            // Resize, and optionally set to zero
            resize(size, fill_zero);
        }

        /**
        Creates a new IntArray with given size wrapping a given pointer. This
        constructor allocates no memory. If the IntArray goes out of scope, the
        Pointer object given here is destroyed. On resizing the IntArray to larger
        size, the data will be copied over to a new allocation from the memory pool
        pointer to by the given MemoryPoolHandle and the Pointer object given here
        will subsequently be destroyed. Unlike the other constructors, this one
        exposes the option of not automatically zero-filling the allocated memory.

        @param[in] ptr An initial Pointer object to wrap
        @param[in] size The size of the array
        @param[in] fill_zero If true, fills ptr with zeros
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if ptr is null and size is positive
        @throws std::invalid_argument if pool is uninitialized
        */
        explicit IntArray(
            util::Pointer<T> &&ptr, std::size_t size, bool fill_zero, MemoryPoolHandle pool = MemoryManager::GetPool())
            : IntArray(std::move(ptr), size, size, fill_zero, std::move(pool))
        {}

        /**
        Constructs a new IntArray by copying a given one.

        @param[in] copy The IntArray to copy from
        */
        IntArray(const IntArray<T> &copy)
            : pool_(MemoryManager::GetPool()), capacity_(copy.size_), size_(copy.size_),
              data_(util::allocate<T>(copy.size_, pool_))
        {
            // Copy over value
            std::copy_n(copy.cbegin(), copy.size_, begin());
        }

        /**
        Constructs a new IntArray by moving a given one.

        @param[in] source The IntArray to move from
        */
        IntArray(IntArray<T> &&source) noexcept
            : pool_(std::move(source.pool_)), capacity_(source.capacity_), size_(source.size_),
              data_(std::move(source.data_))
        {}

        /**
        Destroys the IntArray.
        */
        ~IntArray()
        {
            release();
        }

        /**
        Returns a pointer to the beginning of the array data.
        */
        SEAL_NODISCARD inline T *begin() noexcept
        {
            return data_.get();
        }

        /**
        Returns a constant pointer to the beginning of the array data.
        */
        SEAL_NODISCARD inline const T *cbegin() const noexcept
        {
            return data_.get();
        }

        /**
        Returns a pointer to the end of the array data.
        */
        SEAL_NODISCARD inline T *end() noexcept
        {
            return size_ ? begin() + size_ : begin();
        }

        /**
        Returns a constant pointer to the end of the array data.
        */
        SEAL_NODISCARD inline const T *cend() const noexcept
        {
            return size_ ? cbegin() + size_ : cbegin();
        }
#ifdef SEAL_USE_MSGSL
        /**
        Returns a span pointing to the beginning of the IntArray.
        */
        SEAL_NODISCARD inline gsl::span<T> span()
        {
            return gsl::span<T>(begin(), size_);
        }

        /**
        Returns a span pointing to the beginning of the IntArray.
        */
        SEAL_NODISCARD inline gsl::span<const T> span() const
        {
            return gsl::span<const T>(cbegin(), size_);
        }
#endif
        /**
        Returns a constant reference to the array element at a given index.
        This function performs bounds checking and will throw an error if
        the index is out of range.

        @param[in] index The index of the array element
        @throws std::out_of_range if index is out of range
        */
        SEAL_NODISCARD inline const T &at(std::size_t index) const
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
        SEAL_NODISCARD inline T &at(std::size_t index)
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
        SEAL_NODISCARD inline const T &operator[](std::size_t index) const
        {
            return data_[index];
        }

        /**
        Returns a reference to the array element at a given index. This
        function does not perform bounds checking.

        @param[in] index The index of the array element
        */
        SEAL_NODISCARD inline T &operator[](std::size_t index)
        {
            return data_[index];
        }

        /**
        Returns whether the array has size zero.
        */
        SEAL_NODISCARD inline bool empty() const noexcept
        {
            return (size_ == 0);
        }

        /**
        Returns the largest possible array size.
        */
        SEAL_NODISCARD inline std::size_t max_size() const noexcept
        {
            return std::numeric_limits<std::size_t>::max();
        }

        /**
        Returns the size of the array.
        */
        SEAL_NODISCARD inline std::size_t size() const noexcept
        {
            return size_;
        }

        /**
        Returns the capacity of the array.
        */
        SEAL_NODISCARD inline std::size_t capacity() const noexcept
        {
            return capacity_;
        }

        /**
        Returns the currently used MemoryPoolHandle.
        */
        SEAL_NODISCARD inline MemoryPoolHandle pool() const noexcept
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
        inline void reserve(std::size_t capacity)
        {
            std::size_t copy_size = std::min(capacity, size_);

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
        in the array remains unchanged and any new space is initialized to zero
        if fill_zero is set to true; when resizing to smaller size the last
        elements of the array are dropped. If the capacity is not already large
        enough to hold the new size, the array is also reallocated.

        @param[in] size The size of the array
        @param[in] fill_zero If true, fills expanded space with zeros
        */
        inline void resize(std::size_t size, bool fill_zero = true)
        {
            if (size <= capacity_)
            {
                // Are we changing size to bigger within current capacity?
                // If so, need to set top terms to zero
                if (size > size_ && fill_zero)
                {
                    std::fill(end(), begin() + size, T(0));
                }

                // Set the size
                size_ = size;

                return;
            }

            // At this point we know for sure that size_ <= capacity_ < size so need
            // to reallocate to bigger
            auto new_data(util::allocate<T>(size, pool_));
            std::copy_n(cbegin(), size_, new_data.get());
            if (fill_zero)
            {
                std::fill(new_data.get() + size_, new_data.get() + size, T(0));
            }
            std::swap(data_, new_data);

            // Set the coeff_count and capacity
            capacity_ = size;
            size_ = size;
        }

        /**
        Copies a given IntArray to the current one.

        @param[in] assign The IntArray to copy from
        */
        inline IntArray<T> &operator=(const IntArray<T> &assign)
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
        IntArray<T> &operator=(IntArray<T> &&assign) noexcept
        {
            capacity_ = assign.capacity_;
            size_ = assign.size_;
            data_ = std::move(assign.data_);
            pool_ = std::move(assign.pool_);

            return *this;
        }

        /**
        Returns an upper bound on the size of the IntArray, as if it was written
        to an output stream.

        @param[in] compr_mode The compression mode
        @throws std::invalid_argument if the compression mode is not supported
        @throws std::logic_error if the size does not fit in the return type
        */
        SEAL_NODISCARD inline std::streamoff save_size(
            compr_mode_type compr_mode = Serialization::compr_mode_default) const
        {
            std::size_t members_size = Serialization::ComprSizeEstimate(
                util::add_safe(
                    sizeof(std::uint64_t),             // size_
                    util::mul_safe(size_, sizeof(T))), // data_
                compr_mode);

            return util::safe_cast<std::streamoff>(util::add_safe(sizeof(Serialization::SEALHeader), members_size));
        }

        /**
        Saves the IntArray to an output stream. The output is in binary format
        and not human-readable. The output stream must have the "binary" flag set.

        @param[out] stream The stream to save the IntArray to
        @param[in] compr_mode The desired compression mode
        @throws std::invalid_argument if the compression mode is not supported
        @throws std::logic_error if the data to be saved is invalid, or if
        compression failed
        @throws std::runtime_error if I/O operations failed
        */
        inline std::streamoff save(
            std::ostream &stream, compr_mode_type compr_mode = Serialization::compr_mode_default) const
        {
            using namespace std::placeholders;
            return Serialization::Save(
                std::bind(&IntArray<T_>::save_members, this, _1), save_size(compr_mode_type::none), stream, compr_mode);
        }

        /**
        Loads a IntArray from an input stream overwriting the current IntArray.
        This function takes optionally a bound on the size for the loaded IntArray
        and throws an exception if the size indicated by the loaded metadata exceeds
        the provided value. The check is omitted if in_size_bound is zero.

        @param[in] stream The stream to load the IntArray from
        @param[in] in_size_bound A bound on the size of the loaded IntArray
        @throws std::logic_error if the data cannot be loaded by this version of
        Microsoft SEAL, if the loaded data is invalid, if decompression failed,
        or if the loaded size exceeds in_size_bound
        @throws std::logic_error if the loaded data is invalid, if the loaded size
        exceeds in_size_bound, or if decompression failed
        @throws std::runtime_error if I/O operations failed
        */
        inline std::streamoff load(std::istream &stream, std::size_t in_size_bound = 0)
        {
            using namespace std::placeholders;
            return Serialization::Load(std::bind(&IntArray<T_>::load_members, this, _1, in_size_bound), stream);
        }

        /**
        Saves the IntArray to a given memory location. The output is in binary
        format and not human-readable.

        @param[out] out The memory location to write the Modulus to
        @param[in] size The number of bytes available in the given memory location
        @param[in] compr_mode The desired compression mode
        @throws std::invalid_argument if out is null or if size is too small to
        contain a SEALHeader, or if the compression mode is not supported
        @throws std::logic_error if the data to be saved is invalid, or if
        compression failed
        @throws std::runtime_error if I/O operations failed
        */
        inline std::streamoff save(
            SEAL_BYTE *out, std::size_t size, compr_mode_type compr_mode = Serialization::compr_mode_default) const
        {
            using namespace std::placeholders;
            return Serialization::Save(
                std::bind(&IntArray<T_>::save_members, this, _1), save_size(compr_mode_type::none), out, size,
                compr_mode);
        }

        /**
        Loads a IntArray from a given memory location overwriting the current
        IntArray. This function takes optionally a bound on the size for the loaded
        IntArray and throws an exception if the size indicated by the loaded
        metadata exceeds the provided value. The check is omitted if in_size_bound
        is zero.

        @param[in] in The memory location to load the Modulus from
        @param[in] size The number of bytes available in the given memory location
        @param[in] in_size_bound A bound on the size of the loaded IntArray
        @throws std::invalid_argument if in is null or if size is too small to
        contain a SEALHeader
        @throws std::logic_error if the data cannot be loaded by this version of
        Microsoft SEAL, if the loaded data is invalid, if decompression failed,
        or if the loaded size exceeds in_size_bound
        @throws std::runtime_error if I/O operations failed
        */
        inline std::streamoff load(const SEAL_BYTE *in, std::size_t size, std::size_t in_size_bound = 0)
        {
            using namespace std::placeholders;
            return Serialization::Load(std::bind(&IntArray<T_>::load_members, this, _1, in_size_bound), in, size);
        }

    private:
        void save_members(std::ostream &stream) const
        {
            auto old_except_mask = stream.exceptions();
            try
            {
                // Throw exceptions on std::ios_base::badbit and std::ios_base::failbit
                stream.exceptions(std::ios_base::badbit | std::ios_base::failbit);

                std::uint64_t size64 = size_;
                stream.write(reinterpret_cast<const char *>(&size64), sizeof(std::uint64_t));
                if (size_)
                {
                    stream.write(
                        reinterpret_cast<const char *>(cbegin()),
                        util::safe_cast<std::streamsize>(util::mul_safe(size_, sizeof(T))));
                }
            }
            catch (const std::ios_base::failure &)
            {
                stream.exceptions(old_except_mask);
                throw std::runtime_error("I/O error");
            }
            catch (...)
            {
                stream.exceptions(old_except_mask);
                throw;
            }
            stream.exceptions(old_except_mask);
        }

        void load_members(std::istream &stream, std::size_t in_size_bound)
        {
            auto old_except_mask = stream.exceptions();
            try
            {
                // Throw exceptions on std::ios_base::badbit and std::ios_base::failbit
                stream.exceptions(std::ios_base::badbit | std::ios_base::failbit);

                std::uint64_t size64 = 0;
                stream.read(reinterpret_cast<char *>(&size64), sizeof(std::uint64_t));

                // Check (optionally) that the size in the metadata does not exceed
                // in_size_bound
                if (in_size_bound && util::unsigned_gt(size64, in_size_bound))
                {
                    throw std::logic_error("unexpected size");
                }

                // Set new size; this is potentially unsafe if size64 was not checked
                // against expected_size
                resize(util::safe_cast<std::size_t>(size64));

                // Read data
                if (size_)
                {
                    stream.read(
                        reinterpret_cast<char *>(begin()),
                        util::safe_cast<std::streamsize>(util::mul_safe(size_, sizeof(T))));
                }
            }
            catch (const std::ios_base::failure &)
            {
                stream.exceptions(old_except_mask);
                throw std::runtime_error("I/O error");
            }
            catch (...)
            {
                stream.exceptions(old_except_mask);
                throw;
            }
            stream.exceptions(old_except_mask);
        }

        MemoryPoolHandle pool_;

        std::size_t capacity_ = 0;

        std::size_t size_ = 0;

        util::Pointer<T> data_;
    };
} // namespace seal
