// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/util/locks.h"
#include <atomic>
#include <thread>
#include "gtest/gtest.h"

using namespace seal::util;
using namespace std;

namespace sealtest
{
    namespace util
    {
        class Reader
        {
        public:
            Reader(ReaderWriterLocker &locker) : locker_(locker), locked_(false), trying_(false)
            {}

            bool is_locked() const
            {
                return locked_;
            }

            bool is_trying_to_lock() const
            {
                return trying_;
            }

            void acquire_read()
            {
                trying_ = true;
                lock_ = locker_.acquire_read();
                locked_ = true;
                trying_ = false;
            }

            void release()
            {
                lock_.unlock();
                locked_ = false;
            }

            void wait_until_trying()
            {
                while (!trying_)
                    ;
            }

            void wait_until_locked()
            {
                while (!locked_)
                    ;
            }

        private:
            ReaderWriterLocker &locker_;

            ReaderLock lock_;

            volatile bool locked_;

            volatile bool trying_;
        };

        class Writer
        {
        public:
            Writer(ReaderWriterLocker &locker) : locker_(locker), locked_(false), trying_(false)
            {}

            bool is_locked() const
            {
                return locked_;
            }

            bool is_trying_to_lock() const
            {
                return trying_;
            }

            void acquire_write()
            {
                trying_ = true;
                lock_ = locker_.acquire_write();
                locked_ = true;
                trying_ = false;
            }

            void release()
            {
                lock_.unlock();
                locked_ = false;
            }

            void wait_until_trying()
            {
                while (!trying_)
                    ;
            }

            void wait_until_locked()
            {
                while (!locked_)
                    ;
            }

            void wait_until_unlocked()
            {
                while (locked_)
                    ;
            }

        private:
            ReaderWriterLocker &locker_;

            WriterLock lock_;

            volatile bool locked_;

            volatile bool trying_;
        };

        TEST(ReaderWriterLockerTests, ReaderWriterLockNonBlocking)
        {
            ReaderWriterLocker locker;

            WriterLock writeLock = locker.acquire_write();
            ASSERT_TRUE(writeLock.owns_lock());
            writeLock.unlock();
            ASSERT_FALSE(writeLock.owns_lock());

            ReaderLock readLock = locker.acquire_read();
            ASSERT_TRUE(readLock.owns_lock());
            readLock.unlock();

            ReaderLock readLock2 = locker.acquire_read();
            ASSERT_TRUE(readLock2.owns_lock());
            ASSERT_FALSE(readLock.owns_lock());
            readLock2.unlock();
            ASSERT_FALSE(readLock2.owns_lock());

            readLock = locker.try_acquire_read();
            ASSERT_TRUE(readLock.owns_lock());
            writeLock = locker.try_acquire_write();
            ASSERT_FALSE(writeLock.owns_lock());

            readLock2 = locker.try_acquire_read();
            ASSERT_TRUE(readLock2.owns_lock());
            writeLock = locker.try_acquire_write();
            ASSERT_FALSE(writeLock.owns_lock());

            readLock.unlock();
            writeLock = locker.try_acquire_write();
            ASSERT_FALSE(writeLock.owns_lock());

            readLock2.unlock();
            writeLock = locker.try_acquire_write();
            ASSERT_TRUE(writeLock.owns_lock());

            WriterLock writeLock2 = locker.try_acquire_write();

            ASSERT_FALSE(writeLock2.owns_lock());
            readLock2 = locker.try_acquire_read();
            ASSERT_FALSE(readLock2.owns_lock());

            writeLock.unlock();

            writeLock2 = locker.try_acquire_write();
            ASSERT_TRUE(writeLock2.owns_lock());
            readLock2 = locker.try_acquire_read();
            ASSERT_FALSE(readLock2.owns_lock());

            writeLock2.unlock();
        }

        TEST(ReaderWriterLockerTests, ReaderWriterLockBlocking)
        {
            ReaderWriterLocker locker;

            Reader *reader1 = new Reader(locker);
            Reader *reader2 = new Reader(locker);
            Writer *writer1 = new Writer(locker);
            Writer *writer2 = new Writer(locker);

            ASSERT_FALSE(reader1->is_locked());
            ASSERT_FALSE(reader2->is_locked());
            ASSERT_FALSE(writer1->is_locked());
            ASSERT_FALSE(writer2->is_locked());

            reader1->acquire_read();
            ASSERT_TRUE(reader1->is_locked());
            ASSERT_FALSE(reader2->is_locked());
            reader2->acquire_read();
            ASSERT_TRUE(reader1->is_locked());
            ASSERT_TRUE(reader2->is_locked());

            atomic<bool> should_unlock1{ false };
            atomic<bool> should_unlock2{ false };

            thread writer1_thread([&] {
                writer1->acquire_write();
                while (!should_unlock1)
                {
                    this_thread::sleep_for(10ms);
                }
                writer1->release();
            });

            writer1->wait_until_trying();
            ASSERT_TRUE(writer1->is_trying_to_lock());
            ASSERT_FALSE(writer1->is_locked());

            reader2->release();
            ASSERT_TRUE(reader1->is_locked());
            ASSERT_FALSE(reader2->is_locked());
            ASSERT_TRUE(writer1->is_trying_to_lock());
            ASSERT_FALSE(writer1->is_locked());

            thread writer2_thread([&] {
                writer2->acquire_write();
                while (!should_unlock2)
                {
                    this_thread::sleep_for(10ms);
                }
                writer2->release();
            });

            writer2->wait_until_trying();
            ASSERT_TRUE(writer1->is_trying_to_lock());
            ASSERT_FALSE(writer1->is_locked());
            ASSERT_TRUE(writer2->is_trying_to_lock());
            ASSERT_FALSE(writer2->is_locked());

            reader1->release();
            ASSERT_FALSE(reader1->is_locked());

            while (writer1->is_trying_to_lock() && writer2->is_trying_to_lock())
                ;

            Writer *winner;
            Writer *waiting;
            atomic<bool> *should_unlock_winner;
            atomic<bool> *should_unlock_waiting;

            if (writer1->is_locked())
            {
                winner = writer1;
                waiting = writer2;
                should_unlock_winner = &should_unlock1;
                should_unlock_waiting = &should_unlock2;
            }
            else
            {
                winner = writer2;
                waiting = writer1;
                should_unlock_winner = &should_unlock2;
                should_unlock_waiting = &should_unlock1;
            }

            ASSERT_TRUE(winner->is_locked());
            ASSERT_FALSE(waiting->is_locked());

            *should_unlock_winner = true;
            winner->wait_until_unlocked();
            ASSERT_FALSE(winner->is_locked());

            waiting->wait_until_locked();
            ASSERT_TRUE(waiting->is_locked());

            thread reader1_thread(&Reader::acquire_read, reader1);
            reader1->wait_until_trying();
            ASSERT_TRUE(reader1->is_trying_to_lock());
            ASSERT_FALSE(reader1->is_locked());

            thread reader2_thread(&Reader::acquire_read, reader2);
            reader2->wait_until_trying();
            ASSERT_TRUE(reader2->is_trying_to_lock());
            ASSERT_FALSE(reader2->is_locked());

            *should_unlock_waiting = true;

            reader1->wait_until_locked();
            reader2->wait_until_locked();
            ASSERT_TRUE(reader1->is_locked());
            ASSERT_TRUE(reader2->is_locked());

            reader1->release();
            reader2->release();

            ASSERT_FALSE(reader1->is_locked());
            ASSERT_FALSE(reader2->is_locked());
            ASSERT_FALSE(writer1->is_locked());
            ASSERT_FALSE(reader2->is_locked());
            ASSERT_FALSE(reader1->is_trying_to_lock());
            ASSERT_FALSE(reader2->is_trying_to_lock());
            ASSERT_FALSE(writer1->is_trying_to_lock());
            ASSERT_FALSE(reader2->is_trying_to_lock());

            writer1_thread.join();
            writer2_thread.join();
            reader1_thread.join();
            reader2_thread.join();

            delete reader1;
            delete reader2;
            delete writer1;
            delete writer2;
        }
    } // namespace util
} // namespace sealtest
