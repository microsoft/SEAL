// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/util/common.h"
#include "seal/util/defines.h"
#include "seal/util/globals.h"
#include "seal/util/locks.h"
#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <new>
#include <stdexcept>
#include <type_traits>
#include <vector>

namespace seal
{
    namespace util
    {
        template <typename T = void, typename = std::enable_if_t<std::is_standard_layout<T>::value>>
        class ConstPointer;

        template <>
        class ConstPointer<SEAL_BYTE>;

        template <typename T = void, typename = std::enable_if_t<std::is_standard_layout<T>::value>>
        class Pointer;

        class MemoryPoolItem
        {
        public:
            MemoryPoolItem(SEAL_BYTE *data) noexcept : data_(data)
            {}

            SEAL_NODISCARD inline SEAL_BYTE *data() noexcept
            {
                return data_;
            }

            SEAL_NODISCARD inline const SEAL_BYTE *data() const noexcept
            {
                return data_;
            }

            SEAL_NODISCARD inline MemoryPoolItem *&next() noexcept
            {
                return next_;
            }

            SEAL_NODISCARD inline const MemoryPoolItem *next() const noexcept
            {
                return next_;
            }

        private:
            MemoryPoolItem(const MemoryPoolItem &copy) = delete;

            MemoryPoolItem &operator=(const MemoryPoolItem &assign) = delete;

            SEAL_BYTE *data_ = nullptr;

            MemoryPoolItem *next_ = nullptr;
        };

        class MemoryPoolHead
        {
        public:
            struct allocation
            {
                allocation() : size(0), data_ptr(nullptr), free(0), head_ptr(nullptr)
                {}

                // Size of the allocation (number of items it can hold)
                std::size_t size;

                // Pointer to start of the allocation
                SEAL_BYTE *data_ptr;

                // How much free space is left (number of items that still fit)
                std::size_t free;

                // Pointer to current head of allocation
                SEAL_BYTE *head_ptr;
            };

            // The overriding functions are noexcept(false)
            virtual ~MemoryPoolHead() = default;

            // Byte size of the allocations (items) owned by this pool
            virtual std::size_t item_byte_count() const noexcept = 0;

            // Total number of items allocated
            virtual std::size_t item_count() const noexcept = 0;

            virtual MemoryPoolItem *get() = 0;

            // Return item back to this pool
            virtual void add(MemoryPoolItem *new_first) noexcept = 0;
        };

        class MemoryPoolHeadMT : public MemoryPoolHead
        {
        public:
            // Creates a new MemoryPoolHeadMT with allocation for one single item.
            MemoryPoolHeadMT(std::size_t item_byte_count, bool clear_on_destruction = false);

            ~MemoryPoolHeadMT() noexcept override;

            // Byte size of the allocations (items) owned by this pool
            SEAL_NODISCARD inline std::size_t item_byte_count() const noexcept override
            {
                return item_byte_count_;
            }

            // Returns the total number of items allocated
            SEAL_NODISCARD inline std::size_t item_count() const noexcept override
            {
                return item_count_;
            }

            MemoryPoolItem *get() override;

            inline void add(MemoryPoolItem *new_first) noexcept override
            {
                bool expected = false;
                while (!locked_.compare_exchange_strong(expected, true, std::memory_order_acquire))
                {
                    expected = false;
                }
                MemoryPoolItem *old_first = first_item_;
                new_first->next() = old_first;
                first_item_ = new_first;
                locked_.store(false, std::memory_order_release);
            }

        private:
            MemoryPoolHeadMT(const MemoryPoolHeadMT &copy) = delete;

            MemoryPoolHeadMT &operator=(const MemoryPoolHeadMT &assign) = delete;

            const bool clear_on_destruction_;

            mutable std::atomic<bool> locked_;

            const std::size_t item_byte_count_;

            volatile std::size_t item_count_;

            std::vector<allocation> allocs_;

            MemoryPoolItem *volatile first_item_;
        };

        class MemoryPoolHeadST : public MemoryPoolHead
        {
        public:
            // Creates a new MemoryPoolHeadST with allocation for one single item.
            MemoryPoolHeadST(std::size_t item_byte_count, bool clear_on_destruction = false);

            ~MemoryPoolHeadST() noexcept override;

            // Byte size of the allocations (items) owned by this pool
            SEAL_NODISCARD inline std::size_t item_byte_count() const noexcept override
            {
                return item_byte_count_;
            }

            // Returns the total number of items allocated
            SEAL_NODISCARD inline std::size_t item_count() const noexcept override
            {
                return item_count_;
            }

            SEAL_NODISCARD MemoryPoolItem *get() override;

            inline void add(MemoryPoolItem *new_first) noexcept override
            {
                new_first->next() = first_item_;
                first_item_ = new_first;
            }

        private:
            MemoryPoolHeadST(const MemoryPoolHeadST &copy) = delete;

            MemoryPoolHeadST &operator=(const MemoryPoolHeadST &assign) = delete;

            const bool clear_on_destruction_;

            std::size_t item_byte_count_;

            std::size_t item_count_;

            std::vector<allocation> allocs_;

            MemoryPoolItem *first_item_;
        };

        class MemoryPool
        {
        public:
            static constexpr double alloc_size_multiplier = 1.05;

            // Largest size of single allocation that can be requested from memory pool
            static const std::size_t max_single_alloc_byte_count;

            // Number of different size allocations allowed by a single memory pool
            static constexpr std::size_t max_pool_head_count = std::numeric_limits<std::size_t>::max();

            // Largest allowed size of batch allocation
            static const std::size_t max_batch_alloc_byte_count;

            static constexpr std::size_t first_alloc_count = 1;

            virtual ~MemoryPool() = default;

            virtual Pointer<SEAL_BYTE> get_for_byte_count(std::size_t byte_count) = 0;

            virtual std::size_t pool_count() const = 0;

            virtual std::size_t alloc_byte_count() const = 0;
        };

        class MemoryPoolMT : public MemoryPool
        {
        public:
            MemoryPoolMT(bool clear_on_destruction = false) : clear_on_destruction_(clear_on_destruction){};

            ~MemoryPoolMT() noexcept override;

            SEAL_NODISCARD Pointer<SEAL_BYTE> get_for_byte_count(std::size_t byte_count) override;

            SEAL_NODISCARD inline std::size_t pool_count() const override
            {
                ReaderLock lock(pools_locker_.acquire_read());
                return pools_.size();
            }

            SEAL_NODISCARD std::size_t alloc_byte_count() const override;

        protected:
            MemoryPoolMT(const MemoryPoolMT &copy) = delete;

            MemoryPoolMT &operator=(const MemoryPoolMT &assign) = delete;

            const bool clear_on_destruction_;

            mutable ReaderWriterLocker pools_locker_;

            std::vector<MemoryPoolHead *> pools_;
        };

        class MemoryPoolST : public MemoryPool
        {
        public:
            MemoryPoolST(bool clear_on_destruction = false) : clear_on_destruction_(clear_on_destruction){};

            ~MemoryPoolST() noexcept override;

            SEAL_NODISCARD Pointer<SEAL_BYTE> get_for_byte_count(std::size_t byte_count) override;

            SEAL_NODISCARD inline std::size_t pool_count() const override
            {
                return pools_.size();
            }

            std::size_t alloc_byte_count() const override;

        protected:
            MemoryPoolST(const MemoryPoolST &copy) = delete;

            MemoryPoolST &operator=(const MemoryPoolST &assign) = delete;

            const bool clear_on_destruction_;

            std::vector<MemoryPoolHead *> pools_;
        };
    } // namespace util
} // namespace seal
