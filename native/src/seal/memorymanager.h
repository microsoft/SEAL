// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/util/defines.h"
#include "seal/util/globals.h"
#include "seal/util/mempool.h"
#include <memory>
#include <stdexcept>
#include <unordered_map>
#include <utility>

/*
For .NET Framework wrapper support (C++/CLI) we need to
    (1) compile the MemoryManager class as thread-unsafe because C++
        mutexes cannot be brought through C++/CLI layer;
    (2) disable thread-safe memory pools.
*/
#ifndef _M_CEE
#include <mutex>
#include <thread>
#endif

namespace seal
{
    /**
    Manages a shared pointer to a memory pool. Microsoft SEAL uses memory pools
    for improved performance due to the large number of memory allocations
    needed by the homomorphic encryption operations, and the underlying polynomial
    arithmetic. The library automatically creates a shared global memory pool
    that is used for all dynamic allocations by default, and the user can
    optionally create any number of custom memory pools to be used instead.

    @par Uses in Multi-Threaded Applications
    Sometimes the user might want to use specific memory pools for dynamic
    allocations in certain functions. For example, in heavily multi-threaded
    applications allocating concurrently from a shared memory pool might lead
    to significant performance issues due to thread contention. For these cases
    Microsoft SEAL provides overloads of the functions that take a MemoryPoolHandle
    as an additional argument, and uses the associated memory pool for all dynamic
    allocations inside the function. Whenever these functions are called, the
    user can then simply pass a thread-local MemoryPoolHandle to be used.

    @par Thread-Unsafe Memory Pools
    While memory pools are by default thread-safe, in some cases it suffices
    to have a memory pool be thread-unsafe. To get a little extra performance,
    the user can optionally create such thread-unsafe memory pools and use them
    just as they would use thread-safe memory pools.

    @par Initialized and Uninitialized Handles
    A MemoryPoolHandle has to be set to point either to the global memory pool,
    or to a new memory pool. If this is not done, the MemoryPoolHandle is
    said to be uninitialized, and cannot be used. Initialization simple means
    assigning MemoryPoolHandle::Global() or MemoryPoolHandle::New() to it.

    @par Managing Lifetime
    Internally, the MemoryPoolHandle wraps an std::shared_ptr pointing to
    a memory pool class. Thus, as long as a MemoryPoolHandle pointing to
    a particular memory pool exists, the pool stays alive. Classes such as
    Evaluator and Ciphertext store their own local copies of a MemoryPoolHandle
    to guarantee that the pool stays alive as long as the managing object
    itself stays alive. The global memory pool is implemented as a global
    std::shared_ptr to a memory pool class, and is thus expected to stay
    alive for the entire duration of the program execution. Note that it can
    be problematic to create other global objects that use the memory pool
    e.g. in their constructor, as one would have to ensure the initialization
    order of these global variables to be correct (i.e. global memory pool
    first).
    */
    class MemoryPoolHandle
    {
    public:
        /**
        Creates a new uninitialized MemoryPoolHandle.
        */
        MemoryPoolHandle() = default;

        /**
        Creates a MemoryPoolHandle pointing to a given MemoryPool object.
        */
        MemoryPoolHandle(std::shared_ptr<util::MemoryPool> pool) noexcept : pool_(std::move(pool))
        {}

        /**
        Creates a copy of a given MemoryPoolHandle. As a result, the created
        MemoryPoolHandle will point to the same underlying memory pool as the
        copied instance.


        @param[in] copy The MemoryPoolHandle to copy from
        */
        MemoryPoolHandle(const MemoryPoolHandle &copy) noexcept
        {
            operator=(copy);
        }

        /**
        Creates a new MemoryPoolHandle by moving a given one. As a result, the
        moved MemoryPoolHandle will become uninitialized.


        @param[in] source The MemoryPoolHandle to move from
        */
        MemoryPoolHandle(MemoryPoolHandle &&source) noexcept
        {
            operator=(std::move(source));
        }

        /**
        Overwrites the MemoryPoolHandle instance with the specified instance. As
        a result, the current MemoryPoolHandle will point to the same underlying
        memory pool as the assigned instance.

        @param[in] assign The MemoryPoolHandle instance to assign to the current
        instance
        */
        inline MemoryPoolHandle &operator=(const MemoryPoolHandle &assign) noexcept
        {
            pool_ = assign.pool_;
            return *this;
        }

        /**
        Moves a specified MemoryPoolHandle instance to the current instance. As
        a result, the assigned MemoryPoolHandle will become uninitialized.

        @param[in] assign The MemoryPoolHandle instance to assign to the current
        instance
        */
        inline MemoryPoolHandle &operator=(MemoryPoolHandle &&assign) noexcept
        {
            pool_ = std::move(assign.pool_);
            return *this;
        }

        /**
        Returns a MemoryPoolHandle pointing to the global memory pool.
        */
        SEAL_NODISCARD inline static MemoryPoolHandle Global() noexcept
        {
            return util::global_variables::global_memory_pool;
        }
#ifndef _M_CEE
        /**
        Returns a MemoryPoolHandle pointing to the thread-local memory pool.
        */
        SEAL_NODISCARD inline static MemoryPoolHandle ThreadLocal() noexcept
        {
            return util::global_variables::tls_memory_pool;
        }
#endif
        /**
        Returns a MemoryPoolHandle pointing to a new thread-safe memory pool.

        @param[in] clear_on_destruction Indicates whether the memory pool data
        should be cleared when destroyed. This can be important when memory pools
        are used to store private data.
        */
        SEAL_NODISCARD inline static MemoryPoolHandle New(bool clear_on_destruction = false)
        {
            return MemoryPoolHandle(std::make_shared<util::MemoryPoolMT>(clear_on_destruction));
        }

        /**
        Returns a reference to the internal memory pool that the MemoryPoolHandle
        points to. This function is mainly for internal use.

        @throws std::logic_error if the MemoryPoolHandle is uninitialized
        */
        SEAL_NODISCARD inline operator util::MemoryPool &() const
        {
            if (!pool_)
            {
                throw std::logic_error("pool not initialized");
            }
            return *pool_.get();
        }

        /**
        Returns the number of different allocation sizes. This function returns
        the number of different allocation sizes the memory pool pointed to by
        the current MemoryPoolHandle has made. For example, if the memory pool has
        only allocated two allocations of sizes 128 KB, this function returns 1.
        If it has instead allocated one allocation of size 64 KB and one of 128 KB,
        this function returns 2.
        */
        SEAL_NODISCARD inline std::size_t pool_count() const noexcept
        {
            return !pool_ ? std::size_t(0) : pool_->pool_count();
        }

        /**
        Returns the size of allocated memory. This functions returns the total
        amount of memory (in bytes) allocated by the memory pool pointed to by
        the current MemoryPoolHandle.
        */
        SEAL_NODISCARD inline std::size_t alloc_byte_count() const noexcept
        {
            return !pool_ ? std::size_t(0) : pool_->alloc_byte_count();
        }

        /**
        Returns the number of MemoryPoolHandle objects sharing this memory pool.
        */
        SEAL_NODISCARD inline long use_count() const noexcept
        {
            return !pool_ ? 0 : pool_.use_count();
        }

        /**
        Returns whether the MemoryPoolHandle is initialized.
        */
        SEAL_NODISCARD inline explicit operator bool() const noexcept
        {
            return pool_.operator bool();
        }

        /**
        Compares MemoryPoolHandles. This function returns whether the current
        MemoryPoolHandle points to the same memory pool as a given MemoryPoolHandle.
        */
        inline bool operator==(const MemoryPoolHandle &compare) noexcept
        {
            return pool_ == compare.pool_;
        }

        /**
        Compares MemoryPoolHandles. This function returns whether the current
        MemoryPoolHandle points to a different memory pool than a given
        MemoryPoolHandle.
        */
        inline bool operator!=(const MemoryPoolHandle &compare) noexcept
        {
            return pool_ != compare.pool_;
        }

    private:
        std::shared_ptr<util::MemoryPool> pool_ = nullptr;
    };

    using mm_prof_opt_t = std::uint64_t;

    /**
    Control options for MemoryManager::GetPool function. These force the MemoryManager
    to override the current MMProf and instead return a MemoryPoolHandle pointing
    to a memory pool of the indicated type.
    */
    enum mm_prof_opt : mm_prof_opt_t
    {
        DEFAULT = 0x0,
        FORCE_GLOBAL = 0x1,
        FORCE_NEW = 0x2,
        FORCE_THREAD_LOCAL = 0x4
    };

    /**
    The MMProf is a pure virtual class that every profile for the MemoryManager
    should inherit from. The only functionality this class implements is the
    get_pool(mm_prof_opt_t) function that returns a MemoryPoolHandle pointing
    to a pool selected by internal logic optionally using the input parameter
    of type mm_prof_opt_t. The returned MemoryPoolHandle must point to a valid
    memory pool.
    */
    class MMProf
    {
    public:
        /**
        Creates a new MMProf.
        */
        MMProf() = default;

        /**
        Destroys the MMProf.
        */
        virtual ~MMProf() noexcept
        {}

        /**
        Returns a MemoryPoolHandle pointing to a pool selected by internal logic
        in a derived class and by the mm_prof_opt_t input parameter.

        */
        virtual MemoryPoolHandle get_pool(mm_prof_opt_t) = 0;

    private:
    };

    /**
    A memory manager profile that always returns a MemoryPoolHandle pointing to
    the global memory pool. Microsoft SEAL uses this memory manager profile by default.
    */
    class MMProfGlobal : public MMProf
    {
    public:
        /**
        Creates a new MMProfGlobal.
        */
        MMProfGlobal() = default;

        /**
        Destroys the MMProfGlobal.
        */
        virtual ~MMProfGlobal() noexcept override
        {}

        /**
        Returns a MemoryPoolHandle pointing to the global memory pool. The
        mm_prof_opt_t input parameter has no effect.
        */
        SEAL_NODISCARD inline virtual MemoryPoolHandle get_pool(mm_prof_opt_t) override
        {
            return MemoryPoolHandle::Global();
        }

    private:
    };

    /**
    A memory manager profile that always returns a MemoryPoolHandle pointing to
    the new thread-safe memory pool. This profile should not be used except in
    special circumstances, as it does not result in any reuse of allocated memory.
    */
    class MMProfNew : public MMProf
    {
    public:
        /**
        Creates a new MMProfNew.
        */
        MMProfNew() = default;

        /**
        Destroys the MMProfNew.
        */
        virtual ~MMProfNew() noexcept override
        {}

        /**
        Returns a MemoryPoolHandle pointing to a new thread-safe memory pool. The
        mm_prof_opt_t input parameter has no effect.
        */
        SEAL_NODISCARD inline virtual MemoryPoolHandle get_pool(mm_prof_opt_t) override
        {
            return MemoryPoolHandle::New();
        }

    private:
    };

    /**
    A memory manager profile that always returns a MemoryPoolHandle pointing to
    specific memory pool.
    */
    class MMProfFixed : public MMProf
    {
    public:
        /**
        Creates a new MMProfFixed. The MemoryPoolHandle given as argument is returned
        by every call to get_pool(mm_prof_opt_t).

        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if pool is uninitialized
        */
        MMProfFixed(MemoryPoolHandle pool) : pool_(std::move(pool))
        {
            if (!pool_)
            {
                throw std::invalid_argument("pool is uninitialized");
            }
        }

        /**
        Destroys the MMProfFixed.
        */
        virtual ~MMProfFixed() noexcept override
        {}

        /**
        Returns a MemoryPoolHandle pointing to the stored memory pool. The
        mm_prof_opt_t input parameter has no effect.
        */
        SEAL_NODISCARD inline virtual MemoryPoolHandle get_pool(mm_prof_opt_t) override
        {
            return pool_;
        }

    private:
        MemoryPoolHandle pool_;
    };
#ifndef _M_CEE
    /**
    A memory manager profile that always returns a MemoryPoolHandle pointing to
    the thread-local memory pool. This profile should be used with care, as any
    memory allocated by it will be released once the thread exits. In other words,
    the thread-local memory pool cannot be used to share memory across different
    threads. On the other hand, this profile can be useful when a very high number
    of threads doing simultaneous allocations would cause contention in the
    global memory pool.
    */
    class MMProfThreadLocal : public MMProf
    {
    public:
        /**
        Creates a new MMProfThreadLocal.
        */
        MMProfThreadLocal() = default;

        /**
        Destroys the MMProfThreadLocal.
        */
        virtual ~MMProfThreadLocal() noexcept override
        {}

        /**
        Returns a MemoryPoolHandle pointing to the thread-local memory pool. The
        mm_prof_opt_t input parameter has no effect.
        */
        SEAL_NODISCARD inline virtual MemoryPoolHandle get_pool(mm_prof_opt_t) override
        {
            return MemoryPoolHandle::ThreadLocal();
        }

    private:
    };
#endif
    /**
    The MemoryManager class can be used to create instances of MemoryPoolHandle
    based on a given "profile". A profile is implemented by inheriting from the
    MMProf class (pure virtual) and encapsulates internal logic for deciding which
    memory pool to use.
    */
    class MemoryManager
    {
        friend class MMProfGuard;

    public:
        MemoryManager() = delete;

        /**
        Sets the current profile to a given one and returns a unique_ptr pointing
        to the previously set profile.

        @param[in] mm_prof Pointer to a new memory manager profile
        @throws std::invalid_argument if mm_prof is nullptr
        */
        static inline std::unique_ptr<MMProf> SwitchProfile(MMProf *&&mm_prof) noexcept
        {
#ifndef _M_CEE
            std::lock_guard<std::mutex> switching_lock(switch_mutex_);
#endif
            return SwitchProfileThreadUnsafe(std::move(mm_prof));
        }

        /**
        Sets the current profile to a given one and returns a unique_ptr pointing
        to the previously set profile.

        @param[in] mm_prof Pointer to a new memory manager profile
        @throws std::invalid_argument if mm_prof is nullptr
        */
        static inline std::unique_ptr<MMProf> SwitchProfile(std::unique_ptr<MMProf> &&mm_prof) noexcept
        {
#ifndef _M_CEE
            std::lock_guard<std::mutex> switch_lock(switch_mutex_);
#endif
            return SwitchProfileThreadUnsafe(std::move(mm_prof));
        }

        /**
        Returns a MemoryPoolHandle according to the currently set memory manager
        profile and prof_opt. The following values for prof_opt have an effect
        independent of the current profile:

            mm_prof_opt::FORCE_NEW: return MemoryPoolHandle::New()
            mm_prof_opt::FORCE_GLOBAL: return MemoryPoolHandle::Global()
            mm_prof_opt::FORCE_THREAD_LOCAL: return MemoryPoolHandle::ThreadLocal()

        Other values for prof_opt are forwarded to the current profile and, depending
        on the profile, may or may not have an effect. The value mm_prof_opt::DEFAULT
        will always invoke a default behavior for the current profile.

        @param[in] prof_opt A mm_prof_opt_t parameter used to provide additional
        instructions to the memory manager profile for internal logic.
        */
        template <typename... Args>
        SEAL_NODISCARD static inline MemoryPoolHandle GetPool(mm_prof_opt_t prof_opt, Args &&... args)
        {
            switch (prof_opt)
            {
            case mm_prof_opt::FORCE_GLOBAL:
                return MemoryPoolHandle::Global();

            case mm_prof_opt::FORCE_NEW:
                return MemoryPoolHandle::New(std::forward<Args>(args)...);
#ifndef _M_CEE
            case mm_prof_opt::FORCE_THREAD_LOCAL:
                return MemoryPoolHandle::ThreadLocal();
#endif
            default:
#ifdef SEAL_DEBUG
            {
                auto pool = GetMMProf()->get_pool(prof_opt);
                if (!pool)
                {
                    throw std::logic_error("cannot return uninitialized pool");
                }
                return pool;
            }
#endif
                return GetMMProf()->get_pool(prof_opt);
            }
        }

        SEAL_NODISCARD static inline MemoryPoolHandle GetPool()
        {
            return GetPool(mm_prof_opt::DEFAULT);
        }

    private:
        SEAL_NODISCARD static inline std::unique_ptr<MMProf> SwitchProfileThreadUnsafe(MMProf *&&mm_prof)
        {
            if (!mm_prof)
            {
                throw std::invalid_argument("mm_prof cannot be null");
            }
            auto ret_mm_prof = std::move(GetMMProf());
            GetMMProf().reset(mm_prof);
            return ret_mm_prof;
        }

        SEAL_NODISCARD static inline std::unique_ptr<MMProf> SwitchProfileThreadUnsafe(
            std::unique_ptr<MMProf> &&mm_prof)
        {
            if (!mm_prof)
            {
                throw std::invalid_argument("mm_prof cannot be null");
            }
            std::swap(GetMMProf(), mm_prof);
            return std::move(mm_prof);
        }

        SEAL_NODISCARD static inline std::unique_ptr<MMProf> &GetMMProf()
        {
            static std::unique_ptr<MMProf> mm_prof{ new MMProfGlobal };
            return mm_prof;
        }
#ifndef _M_CEE
        static std::mutex switch_mutex_;
#endif
    };
#ifndef _M_CEE
    /**
    Class for a scoped switch of memory manager profile. This class acts as a scoped
    "guard" for changing the memory manager profile so that the programmer does
    not have to explicitly switch back afterwards and that other threads cannot
    change the MMProf. It can also help with exception safety by guaranteeing that
    the profile is switched back to the original if a function throws an exception
    after changing the profile for local use.
    */
    class MMProfGuard
    {
    public:
        /**
        Creates a new MMProfGuard. If start_locked is true, this function will
        attempt to lock the MemoryManager for profile switch to mm_prof, perform
        the switch, and keep the lock until unlocked or destroyed. If start_lock
        is false, mm_prof will be stored but the switch will not be performed and
        a lock will not be obtained until lock() is explicitly called.

        @param[in] mm_prof Pointer to a new memory manager profile
        @param[in] start_locked Bool indicating whether the lock should be
        immediately obtained (true by default)
        */
        MMProfGuard(std::unique_ptr<MMProf> &&mm_prof, bool start_locked = true) noexcept
            : mm_switch_lock_(MemoryManager::switch_mutex_, std::defer_lock)
        {
            if (start_locked)
            {
                lock(std::move(mm_prof));
            }
            else
            {
                old_prof_ = std::move(mm_prof);
            }
        }

        /**
        Creates a new MMProfGuard. If start_locked is true, this function will
        attempt to lock the MemoryManager for profile switch to mm_prof, perform
        the switch, and keep the lock until unlocked or destroyed. If start_lock
        is false, mm_prof will be stored but the switch will not be performed and
        a lock will not be obtained until lock() is explicitly called.

        @param[in] mm_prof Pointer to a new memory manager profile
        @param[in] start_locked Bool indicating whether the lock should be
        immediately obtained (true by default)
        */
        MMProfGuard(MMProf *&&mm_prof, bool start_locked = true) noexcept
            : mm_switch_lock_(MemoryManager::switch_mutex_, std::defer_lock)
        {
            if (start_locked)
            {
                lock(std::move(mm_prof));
            }
            else
            {
                old_prof_.reset(std::move(mm_prof));
            }
        }

        /**
        Attempts to lock the MemoryManager for profile switch, perform the switch
        to currently stored memory manager profile, store the previously held profile,
        and keep the lock until unlocked or destroyed. If the lock cannot be obtained
        on the first attempt, the function returns false; otherwise returns true.

        @throws std::runtime_error if the lock is already owned
        */
        inline bool try_lock()
        {
            if (mm_switch_lock_.owns_lock())
            {
                throw std::runtime_error("lock is already owned");
            }
            if (!mm_switch_lock_.try_lock())
            {
                return false;
            }
            old_prof_ = MemoryManager::SwitchProfileThreadUnsafe(std::move(old_prof_));
            return true;
        }

        /**
        Locks the MemoryManager for profile switch, performs the switch to currently
        stored memory manager profile, stores the previously held profile, and
        keep the lock until unlocked or destroyed. The calling thread will block
        until the lock can be obtained.

        @throws std::runtime_error if the lock is already owned
        */
#ifdef _MSC_VER
        _Acquires_lock_(mm_switch_lock_)
#endif
            inline void lock()
        {
            if (mm_switch_lock_.owns_lock())
            {
                throw std::runtime_error("lock is already owned");
            }
            mm_switch_lock_.lock();
            old_prof_ = MemoryManager::SwitchProfileThreadUnsafe(std::move(old_prof_));
        }

        /**
        Attempts to lock the MemoryManager for profile switch, perform the switch
        to the given memory manager profile, store the previously held profile,
        and keep the lock until unlocked or destroyed. If the lock cannot be
        obtained on the first attempt, the function returns false; otherwise
        returns true.

        @param[in] mm_prof Pointer to a new memory manager profile
        @throws std::runtime_error if the lock is already owned
        */
        inline bool try_lock(std::unique_ptr<MMProf> &&mm_prof)
        {
            if (mm_switch_lock_.owns_lock())
            {
                throw std::runtime_error("lock is already owned");
            }
            if (!mm_switch_lock_.try_lock())
            {
                return false;
            }
            old_prof_ = MemoryManager::SwitchProfileThreadUnsafe(std::move(mm_prof));
            return true;
        }

        /**
        Locks the MemoryManager for profile switch, performs the switch to the given
        memory manager profile, stores the previously held profile, and keep the
        lock until unlocked or destroyed. The calling thread will block until the
        lock can be obtained.

        @param[in] mm_prof Pointer to a new memory manager profile
        @throws std::runtime_error if the lock is already owned
        */
#ifdef _MSC_VER
        _Acquires_lock_(mm_switch_lock_)
#endif
            inline void lock(std::unique_ptr<MMProf> &&mm_prof)
        {
            if (mm_switch_lock_.owns_lock())
            {
                throw std::runtime_error("lock is already owned");
            }
            mm_switch_lock_.lock();
            old_prof_ = MemoryManager::SwitchProfileThreadUnsafe(std::move(mm_prof));
        }

        /**
        Attempts to lock the MemoryManager for profile switch, perform the switch
        to the given memory manager profile, store the previously held profile,
        and keep the lock until unlocked or destroyed. If the lock cannot be
        obtained on the first attempt, the function returns false; otherwise returns
        true.

        @param[in] mm_prof Pointer to a new memory manager profile
        @throws std::runtime_error if the lock is already owned
        */
        inline bool try_lock(MMProf *&&mm_prof)
        {
            if (mm_switch_lock_.owns_lock())
            {
                throw std::runtime_error("lock is already owned");
            }
            if (!mm_switch_lock_.try_lock())
            {
                return false;
            }
            old_prof_ = MemoryManager::SwitchProfileThreadUnsafe(std::move(mm_prof));
            return true;
        }

        /**
        Locks the MemoryManager for profile switch, performs the switch to the
        given memory manager profile, stores the previously held profile, and keep
        the lock until unlocked or destroyed. The calling thread will block until
        the lock can be obtained.

        @param[in] mm_prof Pointer to a new memory manager profile
        @throws std::runtime_error if the lock is already owned
        */
#ifdef _MSC_VER
        _Acquires_lock_(mm_switch_lock_)
#endif
            inline void lock(MMProf *&&mm_prof)
        {
            if (mm_switch_lock_.owns_lock())
            {
                throw std::runtime_error("lock is already owned");
            }
            mm_switch_lock_.lock();
            old_prof_ = MemoryManager::SwitchProfileThreadUnsafe(std::move(mm_prof));
        }

        /**
        Releases the memory manager profile switch lock for MemoryManager, stores
        the current profile, and resets the profile to the one used before locking.

        @throws std::runtime_error if the lock is not owned
        */
#ifdef _MSC_VER
        _Releases_lock_(mm_switch_lock_)
#endif
            inline void unlock()
        {
            if (!mm_switch_lock_.owns_lock())
            {
                throw std::runtime_error("lock is not owned");
            }
            old_prof_ = MemoryManager::SwitchProfileThreadUnsafe(std::move(old_prof_));
            mm_switch_lock_.unlock();
        }

        /**
        Destroys the MMProfGuard. If the memory manager profile switch lock is
        owned, releases the lock, and resets the profile to the one used before
        locking.
        */
        ~MMProfGuard()
        {
            if (mm_switch_lock_.owns_lock())
            {
                old_prof_ = MemoryManager::SwitchProfileThreadUnsafe(std::move(old_prof_));
                mm_switch_lock_.unlock();
            }
        }

        /**
        Returns whether the current MMProfGuard owns the memory manager profile
        switch lock.
        */
        inline bool owns_lock() noexcept
        {
            return mm_switch_lock_.owns_lock();
        }

    private:
        std::unique_ptr<MMProf> old_prof_;

        std::unique_lock<std::mutex> mm_switch_lock_;
    };
#endif
} // namespace seal
