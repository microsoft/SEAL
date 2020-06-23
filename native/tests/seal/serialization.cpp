// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/serialization.h"
#include "seal/util/defines.h"
#include <fstream>
#include <functional>
#include <sstream>
#include <string>
#include "gtest/gtest.h"

using namespace seal;
using namespace std;

namespace sealtest
{
    namespace
    {
        struct test_struct
        {
            int a;
            int b;
            double c;

            void save_members(ostream &stream)
            {
                stream.write(reinterpret_cast<const char *>(&a), sizeof(int));
                stream.write(reinterpret_cast<const char *>(&b), sizeof(int));
                stream.write(reinterpret_cast<const char *>(&c), sizeof(double));
            }

            void load_members(istream &stream)
            {
                stream.read(reinterpret_cast<char *>(&a), sizeof(int));
                stream.read(reinterpret_cast<char *>(&b), sizeof(int));
                stream.read(reinterpret_cast<char *>(&c), sizeof(double));
            }

            streamoff save_size(compr_mode_type compr_mode) const
            {
                size_t members_size = Serialization::ComprSizeEstimate(sizeof(test_struct), compr_mode);

                return static_cast<streamoff>(sizeof(Serialization::SEALHeader) + members_size);
            }
        };
    } // namespace

    TEST(SerializationTest, IsValidHeader)
    {
        ASSERT_EQ(sizeof(Serialization::SEALHeader), Serialization::seal_header_size);

        Serialization::SEALHeader header;
        ASSERT_TRUE(Serialization::IsValidHeader(header));

        Serialization::SEALHeader invalid_header;
        invalid_header.magic = 0x1212;
        ASSERT_FALSE(Serialization::IsValidHeader(invalid_header));
        invalid_header.magic = Serialization::seal_magic;
        ASSERT_EQ(invalid_header.header_size, Serialization::seal_header_size);
        invalid_header.version_major = 0x02;
        ASSERT_FALSE(Serialization::IsValidHeader(invalid_header));
        invalid_header.version_major = SEAL_VERSION_MAJOR;
        invalid_header.compr_mode = (compr_mode_type)0x02;
        ASSERT_FALSE(Serialization::IsValidHeader(invalid_header));
    }

    TEST(SerializationTest, SEALHeaderSaveLoad)
    {
        {
            // Serialize to stream
            Serialization::SEALHeader header, loaded_header;
            header.compr_mode = Serialization::compr_mode_default;
            header.size = 256;

            stringstream stream;
            Serialization::SaveHeader(header, stream);
            ASSERT_TRUE(Serialization::IsValidHeader(header));
            Serialization::LoadHeader(stream, loaded_header);
            ASSERT_EQ(Serialization::seal_magic, loaded_header.magic);
            ASSERT_EQ(Serialization::seal_header_size, loaded_header.header_size);
            ASSERT_EQ(SEAL_VERSION_MAJOR, loaded_header.version_major);
            ASSERT_EQ(SEAL_VERSION_MINOR, loaded_header.version_minor);
            ASSERT_EQ(Serialization::compr_mode_default, loaded_header.compr_mode);
            ASSERT_EQ(0x00, loaded_header.reserved);
            ASSERT_EQ(256, loaded_header.size);
        }
        {
            // Serialize to buffer
            Serialization::SEALHeader header, loaded_header;
            header.compr_mode = Serialization::compr_mode_default;
            header.size = 256;

            vector<SEAL_BYTE> buffer(16);
            Serialization::SaveHeader(header, buffer.data(), buffer.size());
            ASSERT_TRUE(Serialization::IsValidHeader(header));
            Serialization::LoadHeader(buffer.data(), buffer.size(), loaded_header);
            ASSERT_EQ(Serialization::seal_magic, loaded_header.magic);
            ASSERT_EQ(Serialization::seal_header_size, loaded_header.header_size);
            ASSERT_EQ(SEAL_VERSION_MAJOR, loaded_header.version_major);
            ASSERT_EQ(SEAL_VERSION_MINOR, loaded_header.version_minor);
            ASSERT_EQ(Serialization::compr_mode_default, loaded_header.compr_mode);
            ASSERT_EQ(0x00, loaded_header.reserved);
            ASSERT_EQ(256, loaded_header.size);
        }
    }

    TEST(SerializationTest, SEALHeaderUpgrade)
    {
        legacy_headers::SEALHeader_3_4 header_3_4;
        header_3_4.compr_mode = Serialization::compr_mode_default;
        header_3_4.size = 0xF3F3;

        {
            Serialization::SEALHeader header;
            Serialization::LoadHeader(
                reinterpret_cast<const SEAL_BYTE *>(&header_3_4), sizeof(legacy_headers::SEALHeader_3_4), header);
            ASSERT_TRUE(Serialization::IsValidHeader(header));
            ASSERT_EQ(header_3_4.compr_mode, header.compr_mode);
            ASSERT_EQ(header_3_4.size, header.size);
        }
        {
            Serialization::SEALHeader header;
            Serialization::LoadHeader(
                reinterpret_cast<const SEAL_BYTE *>(&header_3_4), sizeof(legacy_headers::SEALHeader_3_4), header,
                false);

            // No upgrade requested
            ASSERT_FALSE(Serialization::IsValidHeader(header));
        }
    }

    TEST(SerializationTest, SaveLoadToStream)
    {
        test_struct st{ 3, ~0, 3.14159 }, st2;
        using namespace placeholders;
        stringstream stream;

        auto out_size = Serialization::Save(
            bind(&test_struct::save_members, &st, _1), st.save_size(compr_mode_type::none), stream,
            compr_mode_type::none);
        auto in_size = Serialization::Load(bind(&test_struct::load_members, &st2, _1), stream);
        ASSERT_EQ(out_size, in_size);
        ASSERT_EQ(st.a, st2.a);
        ASSERT_EQ(st.b, st2.b);
        ASSERT_EQ(st.c, st2.c);
#ifdef SEAL_USE_ZLIB
        test_struct st3;
        out_size = Serialization::Save(
            bind(&test_struct::save_members, &st, _1), st.save_size(compr_mode_type::deflate), stream,
            compr_mode_type::deflate);
        in_size = Serialization::Load(bind(&test_struct::load_members, &st3, _1), stream);
        ASSERT_EQ(out_size, in_size);
        ASSERT_EQ(st.a, st3.a);
        ASSERT_EQ(st.b, st3.b);
        ASSERT_EQ(st.c, st3.c);
#endif
    }

    TEST(SerializationTest, SaveLoadToBuffer)
    {
        test_struct st{ 3, ~0, 3.14159 }, st2;
        using namespace placeholders;

        constexpr size_t arr_size = 1024;
        SEAL_BYTE buffer[arr_size]{};

        stringstream ss;
        auto test_out_size = Serialization::Save(
            bind(&test_struct::save_members, &st, _1), st.save_size(Serialization::compr_mode_default), ss,
            Serialization::compr_mode_default);
        auto out_size = Serialization::Save(
            bind(&test_struct::save_members, &st, _1), st.save_size(Serialization::compr_mode_default), buffer,
            arr_size, Serialization::compr_mode_default);
        ASSERT_EQ(test_out_size, out_size);
        for (size_t i = static_cast<size_t>(out_size); i < arr_size; i++)
        {
            ASSERT_TRUE(SEAL_BYTE(0) == buffer[i]);
        }

        auto in_size = Serialization::Load(bind(&test_struct::load_members, &st2, _1), buffer, arr_size);
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
            bind(&test_struct::save_members, &st, _1), st.save_size(compr_mode_type::deflate), ss,
            compr_mode_type::deflate);
        out_size = Serialization::Save(
            bind(&test_struct::save_members, &st, _1), st.save_size(compr_mode_type::deflate), buffer, arr_size,
            compr_mode_type::deflate);
        ASSERT_EQ(test_out_size, out_size);
        for (size_t i = static_cast<size_t>(out_size); i < arr_size; i++)
        {
            ASSERT_EQ(SEAL_BYTE(0), buffer[i]);
        }

        in_size = Serialization::Load(bind(&test_struct::load_members, &st3, _1), buffer, arr_size);
        ASSERT_EQ(out_size, in_size);
        ASSERT_EQ(st.a, st3.a);
        ASSERT_EQ(st.b, st3.b);
        ASSERT_EQ(st.c, st3.c);
#endif
    }
} // namespace sealtest
