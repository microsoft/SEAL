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
        int b;
        double c;

        void save_members(ostream &stream)
        {
            stream.write(reinterpret_cast<const char*>(&a), sizeof(int));
            stream.write(reinterpret_cast<const char*>(&b), sizeof(int));
            stream.write(reinterpret_cast<const char*>(&c), sizeof(double));
        }

        void load_members(istream &stream)
        {
            stream.read(reinterpret_cast<char*>(&a), sizeof(int));
            stream.read(reinterpret_cast<char*>(&b), sizeof(int));
            stream.read(reinterpret_cast<char*>(&c), sizeof(double));
        }

        streamoff save_size(compr_mode_type compr_mode) const
        {
            size_t members_size = Serialization::ComprSizeEstimate(
                sizeof(test_struct), compr_mode);

            return static_cast<streamoff>(sizeof(Serialization::SEALHeader) + members_size);
        }
    };

    TEST(SerializationTest, SaveLoadToStream)
    {
        test_struct st{ 3, ~0, 3.14159 }, st2;
        using namespace std::placeholders;
        stringstream stream;

        auto out_size = Serialization::Save(
            bind(&test_struct::save_members, &st, _1),
            st.save_size(compr_mode_type::none),
            stream, compr_mode_type::none);
        auto in_size = Serialization::Load(
            bind(&test_struct::load_members, &st2, _1),
            stream);
        ASSERT_EQ(out_size, in_size);
        ASSERT_EQ(st.a, st2.a);
        ASSERT_EQ(st.b, st2.b);
        ASSERT_EQ(st.c, st2.c);
#ifdef SEAL_USE_ZLIB
        test_struct st3;
        out_size = Serialization::Save(
            bind(&test_struct::save_members, &st, _1),
            st.save_size(compr_mode_type::none),
            stream, compr_mode_type::deflate);
        in_size = Serialization::Load(
            bind(&test_struct::load_members, &st3, _1),
            stream);
        ASSERT_EQ(out_size, in_size);
        ASSERT_EQ(st.a, st3.a);
        ASSERT_EQ(st.b, st3.b);
        ASSERT_EQ(st.c, st3.c);
#endif
    }

    TEST(SerializationTest, SaveLoadToBuffer)
    {
        test_struct st{ 3, ~0, 3.14159 }, st2;
        using namespace std::placeholders;

        constexpr size_t arr_size = 1024;
        SEAL_BYTE buffer[arr_size]{};

        stringstream ss;
        auto test_out_size = Serialization::Save(
            bind(&test_struct::save_members, &st, _1),
            st.save_size(compr_mode_type::none),
            ss, compr_mode_type::none);
        auto out_size = Serialization::Save(
            bind(&test_struct::save_members, &st, _1),
            st.save_size(compr_mode_type::none),
            buffer, arr_size, compr_mode_type::none);
        ASSERT_EQ(test_out_size, out_size);
        for (size_t i = static_cast<size_t>(out_size); i < arr_size; i++)
        {
            ASSERT_TRUE(SEAL_BYTE(0) == buffer[i]);
        }

        auto in_size = Serialization::Load(
            bind(&test_struct::load_members, &st2, _1),
            buffer, arr_size);
        ASSERT_EQ(out_size, in_size);
        ASSERT_EQ(st.a, st2.a);
        ASSERT_EQ(st.b, st2.b);
        ASSERT_EQ(st.c, st2.c);
#ifdef SEAL_USE_ZLIB
        // Reset buffer back to zero
        memset(buffer, 0, arr_size);

        test_struct st3;
        ss.seekp(0);
        test_out_size = Serialization::Save(
            bind(&test_struct::save_members, &st, _1),
            st.save_size(compr_mode_type::none),
            ss, compr_mode_type::deflate);
        out_size = Serialization::Save(
            bind(&test_struct::save_members, &st, _1),
            st.save_size(compr_mode_type::none),
            buffer, arr_size, compr_mode_type::deflate);
        ASSERT_EQ(test_out_size, out_size);
        for (size_t i = static_cast<size_t>(out_size); i < arr_size; i++)
        {
            ASSERT_EQ(SEAL_BYTE(0), buffer[i]);
        }

        in_size = Serialization::Load(
            bind(&test_struct::load_members, &st3, _1),
            buffer, arr_size);
        ASSERT_EQ(out_size, in_size);
        ASSERT_EQ(st.a, st3.a);
        ASSERT_EQ(st.b, st3.b);
        ASSERT_EQ(st.c, st3.c);
#endif
    }
}
