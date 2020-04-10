// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/util/defines.h"

#ifdef SEAL_USE_SHARED_MUTEX
#include <shared_mutex>

namespace seal
{
    namespace util
    {
        using ReaderLock = std::shared_lock<std::shared_mutex>;

        using WriterLock = std::unique_lock<std::shared_mutex>;

        class SEAL_NODISCARD ReaderWriterLocker
        {
        public:
            ReaderWriterLocker() = default;

            SEAL_NODISCARD inline ReaderLock acquire_read()
            {
                return ReaderLock(rw_lock_mutex_);
            }

            SEAL_NODISCARD inline WriterLock acquire_write()
            {
                return WriterLock(rw_lock_mutex_);
            }

            SEAL_NODISCARD inline ReaderLock try_acquire_read() noexcept
            {
                return ReaderLock(rw_lock_mutex_, std::try_to_lock);
            }

            SEAL_NODISCARD inline WriterLock try_acquire_write() noexcept
            {
                return WriterLock(rw_lock_mutex_, std::try_to_lock);
            }

        private:
            ReaderWriterLocker(const ReaderWriterLocker &copy) = delete;

            ReaderWriterLocker &operator=(const ReaderWriterLocker &assign) = delete;

            std::shared_mutex rw_lock_mutex_{};
        };
    } // namespace util
} // namespace seal
#else
#include <atomic>
#include <utility>

namespace seal
{
    namespace util
    {
        struct try_to_lock_t
        {};

        constexpr try_to_lock_t try_to_lock{};

        class ReaderWriterLocker;

        class SEAL_NODISCARD ReaderLock
        {
        public:
            ReaderLock() noexcept : locker_(nullptr)
            {}

            ReaderLock(ReaderLock &&move) noexcept : locker_(move.locker_)
            {
                move.locker_ = nullptr;
            }

            ReaderLock(ReaderWriterLocker &locker) noexcept : locker_(nullptr)
            {
                acquire(locker);
            }

            ReaderLock(ReaderWriterLocker &locker, try_to_lock_t) noexcept : locker_(nullptr)
            {
                try_acquire(locker);
            }

            ~ReaderLock() noexcept
            {
                unlock();
            }

            SEAL_NODISCARD inline bool owns_lock() const noexcept
            {
                return locker_ != nullptr;
            }

            void unlock() noexcept;

            inline void swap_with(ReaderLock &lock) noexcept
            {
                std::swap(locker_, lock.locker_);
            }

            inline ReaderLock &operator=(ReaderLock &&lock) noexcept
            {
                swap_with(lock);
                lock.unlock();
                return *this;
            }

        private:
            void acquire(ReaderWriterLocker &locker) noexcept;

            bool try_acquire(ReaderWriterLocker &locker) noexcept;

            ReaderWriterLocker *locker_;
        };

        class SEAL_NODISCARD WriterLock
        {
        public:
            WriterLock() noexcept : locker_(nullptr)
            {}

            WriterLock(WriterLock &&move) noexcept : locker_(move.locker_)
            {
                move.locker_ = nullptr;
            }

            WriterLock(ReaderWriterLocker &locker) noexcept : locker_(nullptr)
            {
                acquire(locker);
            }

            WriterLock(ReaderWriterLocker &locker, try_to_lock_t) noexcept : locker_(nullptr)
            {
                try_acquire(locker);
            }

            ~WriterLock() noexcept
            {
                unlock();
            }

            SEAL_NODISCARD inline bool owns_lock() const noexcept
            {
                return locker_ != nullptr;
            }

            void unlock() noexcept;

            inline void swap_with(WriterLock &lock) noexcept
            {
                std::swap(locker_, lock.locker_);
            }

            inline WriterLock &operator=(WriterLock &&lock) noexcept
            {
                swap_with(lock);
                lock.unlock();
                return *this;
            }

        private:
            void acquire(ReaderWriterLocker &locker) noexcept;

            bool try_acquire(ReaderWriterLocker &locker) noexcept;

            ReaderWriterLocker *locker_;
        };

        class SEAL_NODISCARD ReaderWriterLocker
        {
            friend class ReaderLock;

            friend class WriterLock;

        public:
            ReaderWriterLocker() noexcept : reader_locks_(0), writer_locked_(false)
            {}

            SEAL_NODISCARD inline ReaderLock acquire_read() noexcept
            {
                return ReaderLock(*this);
            }

            SEAL_NODISCARD inline WriterLock acquire_write() noexcept
            {
                return WriterLock(*this);
            }

            SEAL_NODISCARD inline ReaderLock try_acquire_read() noexcept
            {
                return ReaderLock(*this, try_to_lock);
            }

            SEAL_NODISCARD inline WriterLock try_acquire_write() noexcept
            {
                return WriterLock(*this, try_to_lock);
            }

        private:
            ReaderWriterLocker(const ReaderWriterLocker &copy) = delete;

            ReaderWriterLocker &operator=(const ReaderWriterLocker &assign) = delete;

            std::atomic<int> reader_locks_;

            std::atomic<bool> writer_locked_;
        };

        inline void ReaderLock::unlock() noexcept
        {
            if (locker_ == nullptr)
            {
                return;
            }
            locker_->reader_locks_.fetch_sub(1, std::memory_order_release);
            locker_ = nullptr;
        }

        inline void ReaderLock::acquire(ReaderWriterLocker &locker) noexcept
        {
            unlock();
            do
            {
                locker.reader_locks_.fetch_add(1, std::memory_order_acquire);
                locker_ = &locker;
                if (locker.writer_locked_.load(std::memory_order_acquire))
                {
                    unlock();
                    while (locker.writer_locked_.load(std::memory_order_acquire))
                        ;
                }
            } while (locker_ == nullptr);
        }

        SEAL_NODISCARD inline bool ReaderLock::try_acquire(ReaderWriterLocker &locker) noexcept
        {
            unlock();
            locker.reader_locks_.fetch_add(1, std::memory_order_acquire);
            locker_ = &locker;
            if (locker.writer_locked_.load(std::memory_order_acquire))
            {
                unlock();
                return false;
            }
            return true;
        }

        inline void WriterLock::acquire(ReaderWriterLocker &locker) noexcept
        {
            unlock();
            bool expected = false;
            while (!locker.writer_locked_.compare_exchange_strong(expected, true, std::memory_order_acquire))
            {
                expected = false;
            }
            locker_ = &locker;
            while (locker.reader_locks_.load(std::memory_order_acquire) != 0)
                ;
        }

        SEAL_NODISCARD inline bool WriterLock::try_acquire(ReaderWriterLocker &locker) noexcept
        {
            unlock();
            bool expected = false;
            if (!locker.writer_locked_.compare_exchange_strong(expected, true, std::memory_order_acquire))
            {
                return false;
            }
            locker_ = &locker;
            if (locker.reader_locks_.load(std::memory_order_acquire) != 0)
            {
                unlock();
                return false;
            }
            return true;
        }

        inline void WriterLock::unlock() noexcept
        {
            if (locker_ == nullptr)
            {
                return;
            }
            locker_->writer_locked_.store(false, std::memory_order_release);
            locker_ = nullptr;
        }
    } // namespace util
} // namespace seal
#endif
