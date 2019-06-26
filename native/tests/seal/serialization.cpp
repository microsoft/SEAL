// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <sstream>
#include <fstream>
#include <string>
#include <functional>
#include "gtest/gtest.h"
#include "seal/util/defines.h"
#include "seal/serialization.h"

using namespace seal;
using namespace std;

namespace SEALTest
{
    struct test_struct
    {
        int a;
        double b;

        void save_members(ostream &stream)
        {
            stream.write(reinterpret_cast<const char*>(&a), sizeof(int));
            stream.write(reinterpret_cast<const char*>(&b), sizeof(double));
        }

        void load_members(istream &stream)
        {
            stream.read(reinterpret_cast<char*>(&a), sizeof(int));
            stream.read(reinterpret_cast<char*>(&b), sizeof(double));
        }
    };

    TEST(SerializationTest, SaveLoadToStream)
    {
        test_struct st{ 3, 3.14159 }, st2;
        using namespace std::placeholders;
        stringstream stream;

        auto out_size = Serialization::Save(
            bind(&test_struct::save_members, &st, _1),
            stream, compr_mode_type::none);
        auto in_size = Serialization::Load(
            bind(&test_struct::load_members, &st2, _1),
            stream);
        ASSERT_EQ(out_size, in_size);
        ASSERT_EQ(st.a, st2.a);
        ASSERT_EQ(st.b, st2.b);
#ifdef SEAL_USE_ZLIB
        test_struct st3;
        out_size = Serialization::Save(
            bind(&test_struct::save_members, &st, _1),
            stream, compr_mode_type::zlib);
        in_size = Serialization::Load(
            bind(&test_struct::load_members, &st3, _1),
            stream);
        ASSERT_EQ(out_size, in_size);
        ASSERT_EQ(st.a, st3.a);
        ASSERT_EQ(st.b, st3.b);
#endif
    }

    TEST(SerializationTest, SaveLoadToBuffer)
    {
        test_struct st{ 3, 3.14159 }, st2;
        using namespace std::placeholders;

        constexpr size_t arr_size = 1024;
        SEAL_BYTE buffer[arr_size]{};

        auto test_out_size = Serialization::Save(
            bind(&test_struct::save_members, &st, _1),
            nullptr, compr_mode_type::none);
        auto out_size = Serialization::Save(
            bind(&test_struct::save_members, &st, _1),
            buffer, compr_mode_type::none);
        ASSERT_EQ(test_out_size, out_size);
        for (size_t i = static_cast<size_t>(out_size); i < arr_size; i++)
        {
            ASSERT_EQ(SEAL_BYTE(0), buffer[i]);
        }

        auto in_size = Serialization::Load(
            bind(&test_struct::load_members, &st2, _1),
            buffer);
        ASSERT_EQ(out_size, in_size);
        ASSERT_EQ(st.a, st2.a);
        ASSERT_EQ(st.b, st2.b);
#ifdef SEAL_USE_ZLIB
        test_struct st3;
        test_out_size = Serialization::Save(
            bind(&test_struct::save_members, &st, _1),
            nullptr, compr_mode_type::zlib);
        out_size = Serialization::Save(
            bind(&test_struct::save_members, &st, _1),
            buffer, compr_mode_type::zlib);
        ASSERT_EQ(test_out_size, out_size);
        for (size_t i = static_cast<size_t>(out_size); i < arr_size; i++)
        {
            ASSERT_EQ(SEAL_BYTE(0), buffer[i]);
        }

        in_size = Serialization::Load(
            bind(&test_struct::load_members, &st3, _1),
            buffer);
        ASSERT_EQ(out_size, in_size);
        ASSERT_EQ(st.a, st3.a);
        ASSERT_EQ(st.b, st3.b);
#endif
    }
}
