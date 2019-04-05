// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/util/defines.h"
#include "seal/util/common.h"
#include "seal/util/mempool.h"
#include <type_traits>
#include <memory>
#include <utility>

namespace seal
{
    namespace util
    {
        // Specialization for SEAL_BYTE
        template<>
        class Pointer<SEAL_BYTE>
        {
            friend class MemoryPoolST;
            friend class MemoryPoolMT;

        public:
            template<typename, typename> friend class Pointer;
            template<typename, typename> friend class ConstPointer;

            Pointer() = default;

            // Move of the same type
            Pointer(Pointer<SEAL_BYTE> &&source) noexcept :
                data_(source.data_), head_(source.head_),
                item_(source.item_), alias_(source.alias_)
            {
                source.data_ = nullptr;
                source.head_ = nullptr;
                source.item_ = nullptr;
                source.alias_ = false;
            }

            // Move of the same type
            Pointer(Pointer<SEAL_BYTE> &&source, SEAL_BYTE value) :
                Pointer(std::move(source))
            {
                std::fill_n(data_, head_->item_byte_count(), value);
            }

            inline SEAL_BYTE &operator [](std::size_t index)
            {
                return data_[index];
            }

            inline const SEAL_BYTE &operator [](std::size_t index) const
            {
                return data_[index];
            }

            inline auto &operator =(Pointer<SEAL_BYTE> &&assign) noexcept
            {
                acquire(std::move(assign));
                return *this;
            }

            inline bool is_set() const noexcept
            {
                return data_ != nullptr;
            }

            inline SEAL_BYTE *get() noexcept
            {
                return data_;
            }

            inline const SEAL_BYTE *get() const noexcept
            {
                return data_;
            }

            inline SEAL_BYTE *operator ->() noexcept
            {
                return data_;
            }

            inline const SEAL_BYTE *operator ->() const noexcept
            {
                return data_;
            }

            inline SEAL_BYTE &operator *()
            {
                return *data_;
            }

            inline const SEAL_BYTE &operator *() const
            {
                return *data_;
            }

            inline bool is_alias() const noexcept
            {
                return alias_;
            }

            inline void release() noexcept
            {
                if (head_)
                {
                    // Return the memory to pool
                    head_->add(item_);
                }
                else if (data_ && !alias_)
                {
                    // Free the memory
                    delete[] data_;
                }

                data_ = nullptr;
                head_ = nullptr;
                item_ = nullptr;
                alias_ = false;
            }

            void acquire(Pointer<SEAL_BYTE> &other) noexcept
            {
                if (this == &other)
                {
                    return;
                }

                release();

                data_ = other.data_;
                head_ = other.head_;
                item_ = other.item_;
                alias_ = other.alias_;
                other.data_ = nullptr;
                other.head_ = nullptr;
                other.item_ = nullptr;
                other.alias_ = false;
            }

            inline void acquire(Pointer<SEAL_BYTE> &&other) noexcept
            {
                acquire(other);
            }

            ~Pointer() noexcept
            {
                release();
            }

            operator bool() const noexcept
            {
                return (data_ != nullptr);
            }

            inline static Pointer<SEAL_BYTE> Owning(SEAL_BYTE *pointer) noexcept
            {
                return {pointer, false};
            }

            inline static Pointer<SEAL_BYTE> Aliasing(SEAL_BYTE *pointer) noexcept
            {
                return {pointer, true};
            }

        private:
            Pointer(const Pointer<SEAL_BYTE> &copy) = delete;

            Pointer<SEAL_BYTE> &operator =(const Pointer<SEAL_BYTE> &assign) = delete;

            Pointer(SEAL_BYTE *pointer, bool alias) noexcept :
                data_(pointer), alias_(alias)
            {
            }

            Pointer(class MemoryPoolHead *head)
            {
#ifdef SEAL_DEBUG
                if (!head)
                {
                    throw std::invalid_argument("head cannot be nullptr");
                }
#endif
                head_ = head;
                item_ = head->get();
                data_ = item_->data();
            }

            SEAL_BYTE *data_ = nullptr;

            MemoryPoolHead *head_ = nullptr;

            MemoryPoolItem *item_ = nullptr;

            bool alias_ = false;
        };

        template<typename T, typename>
        class Pointer
        {
            friend class MemoryPoolST;
            friend class MemoryPoolMT;

        public:
            friend class Pointer<SEAL_BYTE>;
            friend class ConstPointer<SEAL_BYTE>;
            friend class ConstPointer<T>;

            Pointer() = default;

            // Move of the same type
            Pointer(Pointer<T> &&source) noexcept :
                data_(source.data_), head_(source.head_),
                item_(source.item_), alias_(source.alias_)
            {
                source.data_ = nullptr;
                source.head_ = nullptr;
                source.item_ = nullptr;
                source.alias_ = false;
            }

            // Move when T is not SEAL_BYTE
            Pointer(Pointer<SEAL_BYTE> &&source)
            {
                // Cannot acquire a non-pool pointer of different type
                if (!source.head_ && source.data_)
                {
                    throw std::invalid_argument("cannot acquire a non-pool pointer of different type");
                }

                head_ = source.head_;
                item_ = source.item_;
                if (head_)
                {
                    data_ = reinterpret_cast<T*>(item_->data());
                    SEAL_IF_CONSTEXPR (!std::is_trivially_constructible<T>::value)
                    {
                        auto count = head_->item_byte_count() / sizeof(T);
                        for (auto alloc_ptr = data_; count--; alloc_ptr++)
                        {
                            new(alloc_ptr) T;
                        }
                    }
                }
                alias_ = source.alias_;

                source.data_ = nullptr;
                source.head_ = nullptr;
                source.item_ = nullptr;
                source.alias_ = false;
            }

            // Move when T is not SEAL_BYTE
            template<typename ...Args>
            Pointer(Pointer<SEAL_BYTE> &&source, Args &&...args)
            {
                // Cannot acquire a non-pool pointer of different type
                if (!source.head_ && source.data_)
                {
                    throw std::invalid_argument("cannot acquire a non-pool pointer of different type");
                }

                head_ = source.head_;
                item_ = source.item_;
                if (head_)
                {
                    data_ = reinterpret_cast<T*>(item_->data());
                    auto count = head_->item_byte_count() / sizeof(T);
                    for (auto alloc_ptr = data_; count--; alloc_ptr++)
                    {
                        new(alloc_ptr) T(std::forward<Args>(args)...);
                    }
                }
                alias_ = source.alias_;

                source.data_ = nullptr;
                source.head_ = nullptr;
                source.item_ = nullptr;
                source.alias_ = false;
            }

            inline T &operator [](std::size_t index)
            {
                return data_[index];
            }

            inline const T &operator [](std::size_t index) const
            {
                return data_[index];
            }

            inline auto &operator =(Pointer<T> &&assign) noexcept
            {
                acquire(std::move(assign));
                return *this;
            }

            inline auto &operator =(Pointer<SEAL_BYTE> &&assign)
            {
                acquire(std::move(assign));
                return *this;
            }

            inline bool is_set() const noexcept
            {
                return data_ != nullptr;
            }

            inline T *get() noexcept
            {
                return data_;
            }

            inline const T *get() const noexcept
            {
                return data_;
            }

            inline T *operator ->() noexcept
            {
                return data_;
            }

            inline const T *operator ->() const noexcept
            {
                return data_;
            }

            inline T &operator *()
            {
                return *data_;
            }

            inline const T &operator *() const
            {
                return *data_;
            }

            inline bool is_alias() const noexcept
            {
                return alias_;
            }

            inline void release() noexcept
            {
                if (head_)
                {
                    SEAL_IF_CONSTEXPR (!std::is_trivially_destructible<T>::value)
                    {
                        // Manual destructor calls
                        auto count = head_->item_byte_count() / sizeof(T);
                        for (auto alloc_ptr = data_; count--; alloc_ptr++)
                        {
                            alloc_ptr->~T();
                        }
                    }

                    // Return the memory to pool
                    head_->add(item_);
                }
                else if (data_ && !alias_)
                {
                    // Free the memory
                    delete[] data_;
                }

                data_ = nullptr;
                head_ = nullptr;
                item_ = nullptr;
                alias_ = false;
            }

            void acquire(Pointer<T> &other) noexcept
            {
                if (this == &other)
                {
                    return;
                }

                release();

                data_ = other.data_;
                head_ = other.head_;
                item_ = other.item_;
                alias_ = other.alias_;
                other.data_ = nullptr;
                other.head_ = nullptr;
                other.item_ = nullptr;
                other.alias_ = false;
            }

            inline void acquire(Pointer<T> &&other) noexcept
            {
                acquire(other);
            }

            void acquire(Pointer<SEAL_BYTE> &other)
            {
                // Cannot acquire a non-pool pointer of different type
                if (!other.head_ && other.data_)
                {
                    throw std::invalid_argument("cannot acquire a non-pool pointer of different type");
                }

                release();

                head_ = other.head_;
                item_ = other.item_;
                if (head_)
                {
                    data_ = reinterpret_cast<T*>(item_->data());
                    SEAL_IF_CONSTEXPR (!std::is_trivially_constructible<T>::value)
                    {
                        auto count = head_->item_byte_count() / sizeof(T);
                        for (auto alloc_ptr = data_; count--; alloc_ptr++)
                        {
                            new(alloc_ptr) T;
                        }
                    }
                }
                alias_ = other.alias_;
                other.data_ = nullptr;
                other.head_ = nullptr;
                other.item_ = nullptr;
                other.alias_ = false;
            }

            inline void acquire(Pointer<SEAL_BYTE> &&other)
            {
                acquire(other);
            }

            ~Pointer() noexcept
            {
                release();
            }

            operator bool() const noexcept
            {
                return (data_ != nullptr);
            }

            inline static Pointer<T> Owning(T *pointer) noexcept
            {
                return {pointer, false};
            }

            inline static Pointer<T> Aliasing(T *pointer) noexcept
            {
                return {pointer, true};
            }

        private:
            Pointer(const Pointer<T> &copy) = delete;

            Pointer<T> &operator =(const Pointer<T> &assign) = delete;

            Pointer(T *pointer, bool alias) noexcept :
                data_(pointer), alias_(alias)
            {
            }

            Pointer(class MemoryPoolHead *head)
            {
#ifdef SEAL_DEBUG
                if (!head)
                {
                    throw std::invalid_argument("head cannot be nullptr");
                }
#endif
                head_ = head;
                item_ = head->get();
                data_ = reinterpret_cast<T*>(item_->data());
                SEAL_IF_CONSTEXPR (!std::is_trivially_constructible<T>::value)
                {
                    auto count = head_->item_byte_count() / sizeof(T);
                    for (auto alloc_ptr = data_; count--; alloc_ptr++)
                    {
                        new(alloc_ptr) T;
                    }
                }
            }

            template<typename ...Args>
            Pointer(class MemoryPoolHead *head, Args &&...args)
            {
#ifdef SEAL_DEBUG
                if (!head)
                {
                    throw std::invalid_argument("head cannot be nullptr");
                }
#endif
                head_ = head;
                item_ = head->get();
                data_ = reinterpret_cast<T*>(item_->data());
                auto count = head_->item_byte_count() / sizeof(T);
                for (auto alloc_ptr = data_; count--; alloc_ptr++)
                {
                    new(alloc_ptr) T(std::forward<Args>(args)...);
                }
            }

            T *data_ = nullptr;

            MemoryPoolHead *head_ = nullptr;

            MemoryPoolItem *item_ = nullptr;

            bool alias_ = false;
        };

        // Specialization for SEAL_BYTE
        template<>
        class ConstPointer<SEAL_BYTE>
        {
            friend class MemoryPoolST;
            friend class MemoryPoolMT;

        public:
            template<typename, typename> friend class ConstPointer;

            ConstPointer() = default;

            // Move of the same type
            ConstPointer(Pointer<SEAL_BYTE> &&source) noexcept :
                data_(source.data_), head_(source.head_),
                item_(source.item_), alias_(source.alias_)
            {
                source.data_ = nullptr;
                source.head_ = nullptr;
                source.item_ = nullptr;
                source.alias_ = false;
            }

            // Move of the same type
            ConstPointer(Pointer<SEAL_BYTE> &&source, SEAL_BYTE value) noexcept :
                ConstPointer(std::move(source))
            {
                std::fill_n(data_, head_->item_byte_count(), value);
            }

            // Move of the same type
            ConstPointer(ConstPointer<SEAL_BYTE> &&source) noexcept :
                data_(source.data_), head_(source.head_),
                item_(source.item_), alias_(source.alias_)
            {
                source.data_ = nullptr;
                source.head_ = nullptr;
                source.item_ = nullptr;
                source.alias_ = false;
            }

            // Move of the same type
            ConstPointer(ConstPointer<SEAL_BYTE> &&source, SEAL_BYTE value) noexcept :
                ConstPointer(std::move(source))
            {
                std::fill_n(data_, head_->item_byte_count(), value);
            }

            inline auto &operator =(ConstPointer<SEAL_BYTE> &&assign) noexcept
            {
                acquire(std::move(assign));
                return *this;
            }

            inline auto &operator =(Pointer<SEAL_BYTE> &&assign) noexcept
            {
                acquire(std::move(assign));
                return *this;
            }

            inline const SEAL_BYTE &operator [](std::size_t index) const
            {
                return data_[index];
            }

            inline bool is_set() const noexcept
            {
                return data_ != nullptr;
            }

            inline const SEAL_BYTE *get() const noexcept
            {
                return data_;
            }

            inline const SEAL_BYTE *operator ->() const noexcept
            {
                return data_;
            }

            inline const SEAL_BYTE &operator *() const
            {
                return *data_;
            }

            inline void release() noexcept
            {
                if (head_)
                {
                    // Return the memory to pool
                    head_->add(item_);
                }
                else if (data_ && !alias_)
                {
                    // Free the memory
                    delete[] data_;
                }

                data_ = nullptr;
                head_ = nullptr;
                item_ = nullptr;
                alias_ = false;
            }

            void acquire(Pointer<SEAL_BYTE> &other) noexcept
            {
                release();

                data_ = other.data_;
                head_ = other.head_;
                item_ = other.item_;
                alias_ = other.alias_;
                other.data_ = nullptr;
                other.head_ = nullptr;
                other.item_ = nullptr;
                other.alias_ = false;
            }

            inline void acquire(Pointer<SEAL_BYTE> &&other) noexcept
            {
                acquire(other);
            }

            void acquire(ConstPointer<SEAL_BYTE> &other) noexcept
            {
                if (this == &other)
                {
                    return;
                }

                release();

                data_ = other.data_;
                head_ = other.head_;
                item_ = other.item_;
                alias_ = other.alias_;
                other.data_ = nullptr;
                other.head_ = nullptr;
                other.item_ = nullptr;
                other.alias_ = false;
            }

            inline void acquire(ConstPointer<SEAL_BYTE> &&other) noexcept
            {
                acquire(other);
            }

            ~ConstPointer() noexcept
            {
                release();
            }

            operator bool() const
            {
                return (data_ != nullptr);
            }

            inline static auto Owning(SEAL_BYTE *pointer) noexcept
                -> ConstPointer<SEAL_BYTE>
            {
                return {pointer, false};
            }

            inline static auto Aliasing(const SEAL_BYTE *pointer) noexcept
                -> ConstPointer<SEAL_BYTE>
            {
                return {const_cast<SEAL_BYTE*>(pointer), true};
            }

        private:
            ConstPointer(const ConstPointer<SEAL_BYTE> &copy) = delete;

            ConstPointer &operator =(const ConstPointer<SEAL_BYTE> &assign) = delete;

            ConstPointer(SEAL_BYTE *pointer, bool alias) noexcept :
                data_(pointer), alias_(alias)
            {
            }

            ConstPointer(class MemoryPoolHead *head)
            {
#ifdef SEAL_DEBUG
                if (!head)
                {
                    throw std::invalid_argument("head cannot be nullptr");
                }
#endif
                head_ = head;
                item_ = head->get();
                data_ = item_->data();
            }

            SEAL_BYTE *data_ = nullptr;

            MemoryPoolHead *head_ = nullptr;

            MemoryPoolItem *item_ = nullptr;

            bool alias_ = false;
        };

        template<typename T, typename>
        class ConstPointer
        {
            friend class MemoryPoolST;
            friend class MemoryPoolMT;

        public:
            ConstPointer() = default;

            // Move of the same type
            ConstPointer(Pointer<T> &&source) noexcept :
                data_(source.data_), head_(source.head_),
                item_(source.item_), alias_(source.alias_)
            {
                source.data_ = nullptr;
                source.head_ = nullptr;
                source.item_ = nullptr;
                source.alias_ = false;
            }

            // Move when T is not SEAL_BYTE
            ConstPointer(Pointer<SEAL_BYTE> &&source)
            {
                // Cannot acquire a non-pool pointer of different type
                if (!source.head_ && source.data_)
                {
                    throw std::invalid_argument("cannot acquire a non-pool pointer of different type");
                }

                head_ = source.head_;
                item_ = source.item_;
                if (head_)
                {
                    data_ = reinterpret_cast<T*>(item_->data());
                    SEAL_IF_CONSTEXPR (!std::is_trivially_constructible<T>::value)
                    {
                        auto count = head_->item_byte_count() / sizeof(T);
                        for (auto alloc_ptr = data_; count--; alloc_ptr++)
                        {
                            new(alloc_ptr) T;
                        }
                    }
                }
                alias_ = source.alias_;

                source.data_ = nullptr;
                source.head_ = nullptr;
                source.item_ = nullptr;
                source.alias_ = false;
            }

            // Move when T is not SEAL_BYTE
            template<typename ...Args>
            ConstPointer(Pointer<SEAL_BYTE> &&source, Args &&...args)
            {
                // Cannot acquire a non-pool pointer of different type
                if (!source.head_ && source.data_)
                {
                    throw std::invalid_argument("cannot acquire a non-pool pointer of different type");
                }

                head_ = source.head_;
                item_ = source.item_;
                if (head_)
                {
                    data_ = reinterpret_cast<T*>(item_->data());
                    auto count = head_->item_byte_count() / sizeof(T);
                    for (auto alloc_ptr = data_; count--; alloc_ptr++)
                    {
                        new(alloc_ptr) T(std::forward<Args>(args)...);
                    }
                }
                alias_ = source.alias_;

                source.data_ = nullptr;
                source.head_ = nullptr;
                source.item_ = nullptr;
                source.alias_ = false;
            }

            // Move of the same type
            ConstPointer(ConstPointer<T> &&source) noexcept :
                data_(source.data_), head_(source.head_),
                item_(source.item_), alias_(source.alias_)
            {
                source.data_ = nullptr;
                source.head_ = nullptr;
                source.item_ = nullptr;
                source.alias_ = false;
            }

            // Move when T is not SEAL_BYTE
            ConstPointer(ConstPointer<SEAL_BYTE> &&source)
            {
                // Cannot acquire a non-pool pointer of different type
                if (!source.head_ && source.data_)
                {
                    throw std::invalid_argument("cannot acquire a non-pool pointer of different type");
                }

                head_ = source.head_;
                item_ = source.item_;
                if (head_)
                {
                    data_ = reinterpret_cast<T*>(item_->data());
                    SEAL_IF_CONSTEXPR (!std::is_trivially_constructible<T>::value)
                    {
                        auto count = head_->item_byte_count() / sizeof(T);
                        for (auto alloc_ptr = data_; count--; alloc_ptr++)
                        {
                            new(alloc_ptr) T;
                        }
                    }
                }
                alias_ = source.alias_;

                source.data_ = nullptr;
                source.head_ = nullptr;
                source.item_ = nullptr;
                source.alias_ = false;
            }

            // Move when T is not SEAL_BYTE
            template<typename ...Args>
            ConstPointer(ConstPointer<SEAL_BYTE> &&source, Args &&...args)
            {
                // Cannot acquire a non-pool pointer of different type
                if (!source.head_ && source.data_)
                {
                    throw std::invalid_argument("cannot acquire a non-pool pointer of different type");
                }

                head_ = source.head_;
                item_ = source.item_;
                if (head_)
                {
                    data_ = reinterpret_cast<T*>(item_->data());
                    auto count = head_->item_byte_count() / sizeof(T);
                    for (auto alloc_ptr = data_; count--; alloc_ptr++)
                    {
                        new(alloc_ptr) T(std::forward<Args>(args)...);
                    }
                }
                alias_ = source.alias_;

                source.data_ = nullptr;
                source.head_ = nullptr;
                source.item_ = nullptr;
                source.alias_ = false;
            }

            inline auto &operator =(ConstPointer<T> &&assign) noexcept
            {
                acquire(std::move(assign));
                return *this;
            }

            inline auto &operator =(ConstPointer<SEAL_BYTE> &&assign)
            {
                acquire(std::move(assign));
                return *this;
            }

            inline auto &operator =(Pointer<T> &&assign) noexcept
            {
                acquire(std::move(assign));
                return *this;
            }

            inline auto &operator =(Pointer<SEAL_BYTE> &&assign)
            {
                acquire(std::move(assign));
                return *this;
            }

            inline const T &operator [](std::size_t index) const
            {
                return data_[index];
            }

            inline bool is_set() const noexcept
            {
                return data_ != nullptr;
            }

            inline const T *get() const noexcept
            {
                return data_;
            }

            inline const T *operator ->() const noexcept
            {
                return data_;
            }

            inline const T &operator *() const
            {
                return *data_;
            }

            inline void release() noexcept
            {
                if (head_)
                {
                    SEAL_IF_CONSTEXPR (!std::is_trivially_destructible<T>::value)
                    {
                        // Manual destructor calls
                        auto count = head_->item_byte_count() / sizeof(T);
                        for (auto alloc_ptr = data_; count--; alloc_ptr++)
                        {
                            alloc_ptr->~T();
                        }
                    }

                    // Return the memory to pool
                    head_->add(item_);
                }
                else if (data_ && !alias_)
                {
                    // Free the memory
                    delete[] data_;
                }

                data_ = nullptr;
                head_ = nullptr;
                item_ = nullptr;
                alias_ = false;
            }

            void acquire(ConstPointer<T> &other) noexcept
            {
                if (this == &other)
                {
                    return;
                }

                release();

                data_ = other.data_;
                head_ = other.head_;
                item_ = other.item_;
                alias_ = other.alias_;
                other.data_ = nullptr;
                other.head_ = nullptr;
                other.item_ = nullptr;
                other.alias_ = false;
            }

            inline void acquire(ConstPointer<T> &&other) noexcept
            {
                acquire(other);
            }

            void acquire(ConstPointer<SEAL_BYTE> &other)
            {
                // Cannot acquire a non-pool pointer of different type
                if (!other.head_ && other.data_)
                {
                    throw std::invalid_argument("cannot acquire a non-pool pointer of different type");
                }

                release();

                head_ = other.head_;
                item_ = other.item_;
                if (head_)
                {
                    data_ = reinterpret_cast<T*>(item_->data());
                    SEAL_IF_CONSTEXPR (!std::is_trivially_constructible<T>::value)
                    {
                        auto count = head_->item_byte_count() / sizeof(T);
                        for (auto alloc_ptr = data_; count--; alloc_ptr++)
                        {
                            new(alloc_ptr) T;
                        }
                    }
                }
                alias_ = other.alias_;
                other.data_ = nullptr;
                other.head_ = nullptr;
                other.item_ = nullptr;
                other.alias_ = false;
            }

            inline void acquire(ConstPointer<SEAL_BYTE> &&other)
            {
                acquire(other);
            }

            void acquire(Pointer<T> &other) noexcept
            {
                release();

                data_ = other.data_;
                head_ = other.head_;
                item_ = other.item_;
                alias_ = other.alias_;
                other.data_ = nullptr;
                other.head_ = nullptr;
                other.item_ = nullptr;
                other.alias_ = false;
            }

            inline void acquire(Pointer<T> &&other) noexcept
            {
                acquire(other);
            }

            void acquire(Pointer<SEAL_BYTE> &other)
            {
                // Cannot acquire a non-pool pointer of different type
                if (!other.head_ && other.data_)
                {
                    throw std::invalid_argument("cannot acquire a non-pool pointer of different type");
                }

                release();

                head_ = other.head_;
                item_ = other.item_;
                if (head_)
                {
                    data_ = reinterpret_cast<T*>(item_->data());
                    SEAL_IF_CONSTEXPR (!std::is_trivially_constructible<T>::value)
                    {
                        auto count = head_->item_byte_count() / sizeof(T);
                        for (auto alloc_ptr = data_; count--; alloc_ptr++)
                        {
                            new(alloc_ptr) T;
                        }
                    }
                }
                alias_ = other.alias_;
                other.data_ = nullptr;
                other.head_ = nullptr;
                other.item_ = nullptr;
                other.alias_ = false;
            }

            inline void acquire(Pointer<SEAL_BYTE> &&other)
            {
                acquire(other);
            }

            ~ConstPointer() noexcept
            {
                release();
            }

            operator bool() const noexcept
            {
                return (data_ != nullptr);
            }

            inline static ConstPointer<T> Owning(T *pointer) noexcept
            {
                return {pointer, false};
            }

            inline static ConstPointer<T> Aliasing(const T *pointer) noexcept
            {
                return {const_cast<T*>(pointer), true};
            }

        private:
            ConstPointer(const ConstPointer<T> &copy) = delete;

            ConstPointer &operator =(const ConstPointer<T> &assign) = delete;

            ConstPointer(T *pointer, bool alias) noexcept : data_(pointer), alias_(alias)
            {
            }

            ConstPointer(class MemoryPoolHead *head)
            {
#ifdef SEAL_DEBUG
                if (!head)
                {
                    throw std::invalid_argument("head cannot be nullptr");
                }
#endif
                head_ = head;
                item_ = head->get();
                data_ = reinterpret_cast<T*>(item_->data());
                SEAL_IF_CONSTEXPR (!std::is_trivially_constructible<T>::value)
                {
                    auto count = head_->item_byte_count() / sizeof(T);
                    for (auto alloc_ptr = data_; count--; alloc_ptr++)
                    {
                        new(alloc_ptr) T;
                    }
                }
            }

            template<typename ...Args>
            ConstPointer(class MemoryPoolHead *head, Args &&...args)
            {
#ifdef SEAL_DEBUG
                if (!head)
                {
                    throw std::invalid_argument("head cannot be nullptr");
                }
#endif
                head_ = head;
                item_ = head->get();
                data_ = reinterpret_cast<T*>(item_->data());
                auto count = head_->item_byte_count() / sizeof(T);
                for (auto alloc_ptr = data_; count--; alloc_ptr++)
                {
                    new(alloc_ptr) T(std::forward<Args>(args)...);
                }
            }

            T *data_ = nullptr;

            MemoryPoolHead *head_ = nullptr;

            MemoryPoolItem *item_ = nullptr;

            bool alias_ = false;
        };

        // Allocate single element
        template<typename T_, typename... Args,
            typename = std::enable_if<std::is_standard_layout<T_>::value>>
        inline auto allocate(MemoryPool &pool, Args &&...args)
        {
            using T = typename std::remove_cv<typename std::remove_reference<T_>::type>::type;
            return Pointer<T>(pool.get_for_byte_count(sizeof(T)),
                std::forward<Args>(args)...);
        }

        // Allocate array of elements
        template<typename T_, typename... Args,
            typename = std::enable_if<std::is_standard_layout<T_>::value>>
        inline auto allocate(std::size_t count, MemoryPool &pool, Args &&...args)
        {
            using T = typename std::remove_cv<typename std::remove_reference<T_>::type>::type;
            return Pointer<T>(pool.get_for_byte_count(util::mul_safe(count, sizeof(T))),
                std::forward<Args>(args)...);
        }

        template<typename T_,
            typename = std::enable_if<std::is_standard_layout<T_>::value>>
        inline auto duplicate_if_needed(T_ *original, std::size_t count,
            bool condition, MemoryPool &pool)
        {
            using T = typename std::remove_cv<typename std::remove_reference<T_>::type>::type;
#ifdef SEAL_DEBUG
            if (original == nullptr && count > 0)
            {
                throw std::invalid_argument("original");
            }
#endif
            if (condition == false)
            {
                return Pointer<T>::Aliasing(original);
            }
            auto allocation(allocate<T>(count, pool));
            std::copy_n(original, count, allocation.get());
            return allocation;
        }

        template<typename T_,
            typename = std::enable_if<std::is_standard_layout<T_>::value>>
        inline auto duplicate_if_needed(const T_ *original,
            std::size_t count, bool condition, MemoryPool &pool)
        {
            using T = typename std::remove_cv<typename std::remove_reference<T_>::type>::type;
#ifdef SEAL_DEBUG
            if (original == nullptr && count > 0)
            {
                throw std::invalid_argument("original");
            }
#endif
            if (condition == false)
            {
                return ConstPointer<T>::Aliasing(original);
            }
            auto allocation(allocate<T>(count, pool));
            std::copy_n(original, count, allocation.get());
            return ConstPointer<T>(std::move(allocation));
        }
    }
}
