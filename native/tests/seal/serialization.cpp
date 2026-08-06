// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/serialization.h"
#include "seal/util/defines.h"
#include "seal/util/ztools.h"
#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <functional>
#include <sstream>
#include <streambuf>
#include <string>
#include <vector>
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

        // A serializable object whose payload is larger than the internal decompression buffer (256 KB), used to
        // exercise multi-chunk streaming inflation.
        struct large_struct
        {
            std::vector<uint8_t> data;

            void save_members(ostream &stream)
            {
                uint64_t n = static_cast<uint64_t>(data.size());
                stream.write(reinterpret_cast<const char *>(&n), sizeof(uint64_t));
                stream.write(reinterpret_cast<const char *>(data.data()), static_cast<streamsize>(data.size()));
            }

            void load_members(istream &stream)
            {
                uint64_t n = 0;
                stream.read(reinterpret_cast<char *>(&n), sizeof(uint64_t));
                data.resize(static_cast<size_t>(n));
                stream.read(reinterpret_cast<char *>(data.data()), static_cast<streamsize>(n));
            }

            streamoff save_size(compr_mode_type compr_mode) const
            {
                size_t raw = sizeof(uint64_t) + data.size();
                return static_cast<streamoff>(
                    sizeof(Serialization::SEALHeader) + Serialization::ComprSizeEstimate(raw, compr_mode));
            }
        };

        // A serializable object whose payload is a sequence of 64-bit words, mirroring how real SEAL objects store
        // coefficient data; used to pin down the exact bit-packed output size.
        struct word_struct
        {
            std::vector<uint64_t> words;

            void save_members(ostream &stream)
            {
                uint64_t n = static_cast<uint64_t>(words.size());
                stream.write(reinterpret_cast<const char *>(&n), sizeof(uint64_t));
                stream.write(reinterpret_cast<const char *>(words.data()), static_cast<streamsize>(words.size() * 8));
            }

            void load_members(istream &stream)
            {
                uint64_t n = 0;
                stream.read(reinterpret_cast<char *>(&n), sizeof(uint64_t));
                words.resize(static_cast<size_t>(n));
                stream.read(reinterpret_cast<char *>(words.data()), static_cast<streamsize>(n * 8));
            }

            streamoff save_size(compr_mode_type compr_mode) const
            {
                size_t raw = sizeof(uint64_t) + words.size() * 8;
                return static_cast<streamoff>(
                    sizeof(Serialization::SEALHeader) + Serialization::ComprSizeEstimate(raw, compr_mode));
            }
        };

        // A serializable object that, on save, writes a small prefix followed by a large filler, but on load reads
        // only the prefix. Modeling a hostile/oversized payload: the loader must not need to inflate the unread filler
        // (the decompression-bomb defense), and must leave the stream positioned at the end of the object.
        struct prefix_struct
        {
            static constexpr size_t prefix_size = 32;
            std::array<uint8_t, prefix_size> prefix{};
            std::vector<uint8_t> filler;

            void save_members(ostream &stream)
            {
                stream.write(reinterpret_cast<const char *>(prefix.data()), static_cast<streamsize>(prefix_size));
                stream.write(reinterpret_cast<const char *>(filler.data()), static_cast<streamsize>(filler.size()));
            }

            void load_members(istream &stream)
            {
                // Intentionally reads only the prefix and never the filler.
                stream.read(reinterpret_cast<char *>(prefix.data()), static_cast<streamsize>(prefix_size));
            }

            streamoff save_size(compr_mode_type compr_mode) const
            {
                size_t raw = prefix_size + filler.size();
                return static_cast<streamoff>(
                    sizeof(Serialization::SEALHeader) + Serialization::ComprSizeEstimate(raw, compr_mode));
            }
        };

        // An object that embeds a nested serialized object (itself saved uncompressed), mirroring how real SEAL
        // objects embed sub-objects such as Modulus. Loading it performs a nested Serialization::Load, which verifies
        // its size via tellg() on the (inflating) stream.
        struct nested_struct
        {
            test_struct inner{};
            int32_t tag = 0;

            void save_members(ostream &stream)
            {
                using namespace std::placeholders;
                Serialization::Save(
                    std::bind(&test_struct::save_members, &inner, _1), inner.save_size(compr_mode_type::none), stream,
                    compr_mode_type::none, false);
                stream.write(reinterpret_cast<const char *>(&tag), sizeof(int32_t));
            }

            void load_members(istream &stream)
            {
                using namespace std::placeholders;
                Serialization::Load(std::bind(&test_struct::load_members, &inner, _1), stream, false);
                stream.read(reinterpret_cast<char *>(&tag), sizeof(int32_t));
            }

            streamoff save_size(compr_mode_type compr_mode) const
            {
                size_t raw = static_cast<size_t>(inner.save_size(compr_mode_type::none)) + sizeof(int32_t);
                return static_cast<streamoff>(
                    sizeof(Serialization::SEALHeader) + Serialization::ComprSizeEstimate(raw, compr_mode));
            }
        };

        // Serializes a nested object under a compressed mode, overstates that nested frame's declared header.size,
        // and appends an incompressible filler. Loading performs a nested Serialization::Load over the inflating
        // stream, where stream positions cannot bound the nested size; the overstated size must not drive the outer
        // decompressor through the filler.
        struct inflated_nested_struct
        {
            test_struct inner{};
            compr_mode_type inner_mode = compr_mode_type::none;
            uint64_t inner_size_extra = 0;
            size_t filler_size = 0;

            void save_members(ostream &stream)
            {
                using namespace std::placeholders;

                // Serialize the nested object, then overstate its header.size (offset 8, 8 bytes).
                stringstream inner_ss;
                Serialization::Save(
                    std::bind(&test_struct::save_members, &inner, _1), inner.save_size(inner_mode), inner_ss,
                    inner_mode, false);
                string inner_bytes = inner_ss.str();
                uint64_t inner_size = 0;
                memcpy(&inner_size, &inner_bytes[8], sizeof(uint64_t));
                inner_size += inner_size_extra;
                memcpy(&inner_bytes[8], &inner_size, sizeof(uint64_t));
                stream.write(inner_bytes.data(), static_cast<streamsize>(inner_bytes.size()));

                // Incompressible filler (splitmix64 output) so the outer compressed frame stays about as large as
                // the filler itself; this makes bytes read from the underlying stream track decompression work.
                std::vector<char> filler(filler_size);
                uint64_t state = 0x9E3779B97F4A7C15ULL;
                for (size_t i = 0; i < filler_size; i++)
                {
                    state += 0x9E3779B97F4A7C15ULL;
                    uint64_t z = state;
                    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
                    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
                    z = z ^ (z >> 31);
                    filler[i] = static_cast<char>(z & 0xFF);
                }
                stream.write(filler.data(), static_cast<streamsize>(filler.size()));
            }

            void load_members(istream &stream)
            {
                using namespace std::placeholders;
                Serialization::Load(std::bind(&test_struct::load_members, &inner, _1), stream, false);
            }

            streamoff save_size(compr_mode_type compr_mode) const
            {
                size_t raw = static_cast<size_t>(inner.save_size(compr_mode_type::none)) +
                             static_cast<size_t>(sizeof(Serialization::SEALHeader)) + filler_size;
                return static_cast<streamoff>(
                    sizeof(Serialization::SEALHeader) + Serialization::ComprSizeEstimate(raw, compr_mode));
            }
        };

        // An input streambuf that presents its whole backing buffer for reading but refuses every seek
        // (seekoff/seekpos return -1). Serialization::Load treats such a stream as non-seekable, exercising the
        // load paths that cannot rely on tellg(). consumed() reports how many bytes have been read so far.
        class NonSeekableBuffer : public std::streambuf
        {
        public:
            explicit NonSeekableBuffer(std::string data) : data_(std::move(data))
            {
                char *base = &data_[0];
                setg(base, base, base + data_.size());
            }

            std::streamsize consumed() const
            {
                return gptr() - eback();
            }

        protected:
            pos_type seekoff(off_type, std::ios_base::seekdir, std::ios_base::openmode) override
            {
                return pos_type(off_type(-1));
            }

            pos_type seekpos(pos_type, std::ios_base::openmode) override
            {
                return pos_type(off_type(-1));
            }

        private:
            std::string data_;
        };

        // The compression modes available in this build.
        std::vector<compr_mode_type> available_compr_modes()
        {
            std::vector<compr_mode_type> modes;
#ifdef SEAL_USE_ZLIB
            modes.push_back(compr_mode_type::zlib);
#endif
#ifdef SEAL_USE_ZSTD
            modes.push_back(compr_mode_type::zstd);
#endif
            modes.push_back(compr_mode_type::bitpack);
            return modes;
        }

        // The compression modes that verify the integrity of the compressed data on load. Bit-packing performs no
        // integrity checking: corrupted packed bits decode to wrong values rather than a detected error, like
        // compr_mode_type::none.
        std::vector<compr_mode_type> checksummed_compr_modes()
        {
            std::vector<compr_mode_type> modes;
#ifdef SEAL_USE_ZLIB
            modes.push_back(compr_mode_type::zlib);
#endif
#ifdef SEAL_USE_ZSTD
            modes.push_back(compr_mode_type::zstd);
#endif
            return modes;
        }
    } // namespace

    TEST(SerializationTest, IsValidHeader)
    {
        ASSERT_EQ(sizeof(Serialization::SEALHeader), Serialization::seal_header_size);

        Serialization::SEALHeader header;
        ASSERT_TRUE(Serialization::IsValidHeader(header));

#ifdef SEAL_USE_ZLIB
        header.compr_mode = compr_mode_type::zlib;
        ASSERT_TRUE(Serialization::IsValidHeader(header));
#endif

#ifdef SEAL_USE_ZSTD
        header.compr_mode = compr_mode_type::zstd;
        ASSERT_TRUE(Serialization::IsValidHeader(header));
#endif

        Serialization::SEALHeader invalid_header;
        invalid_header.magic = 0x1212;
        ASSERT_FALSE(Serialization::IsValidHeader(invalid_header));
        invalid_header.magic = Serialization::seal_magic;
        ASSERT_EQ(invalid_header.header_size, Serialization::seal_header_size);
        invalid_header.version_major = 0x02;
        ASSERT_FALSE(Serialization::IsValidHeader(invalid_header));
        invalid_header.version_major = SEAL_VERSION_MAJOR;
        invalid_header.compr_mode = compr_mode_type::bitpack;
        ASSERT_TRUE(Serialization::IsValidHeader(invalid_header));
        invalid_header.compr_mode = (compr_mode_type)0x04;
        ASSERT_FALSE(Serialization::IsValidHeader(invalid_header));
    }

    TEST(SerializationTest, PreviousMinorVersionCompatibility)
    {
        Serialization::SEALHeader header;
        for (int minor = 0; minor <= SEAL_VERSION_MINOR; minor++)
        {
            header.version_minor = static_cast<uint8_t>(minor);
            ASSERT_TRUE(Serialization::IsCompatibleVersion(header));
        }
        header.version_minor = static_cast<uint8_t>(SEAL_VERSION_MINOR + 1);
        ASSERT_FALSE(Serialization::IsCompatibleVersion(header));

        test_struct source{ 3, ~0, 3.14159 };
        using namespace placeholders;
        stringstream stream;
        Serialization::Save(
            bind(&test_struct::save_members, &source, _1), source.save_size(compr_mode_type::none), stream,
            compr_mode_type::none, false);
        string serialized = stream.str();

        for (int minor = 0; minor <= SEAL_VERSION_MINOR; minor++)
        {
            Serialization::SEALHeader previous_header;
            memcpy(&previous_header, serialized.data(), sizeof(previous_header));
            previous_header.version_minor = static_cast<uint8_t>(minor);

            string previous_serialized = serialized;
            memcpy(&previous_serialized[0], &previous_header, sizeof(previous_header));
            stringstream previous_stream(previous_serialized);

            test_struct loaded;
            Serialization::Load(bind(&test_struct::load_members, &loaded, _1), previous_stream, false);
            ASSERT_EQ(source.a, loaded.a);
            ASSERT_EQ(source.b, loaded.b);
            ASSERT_EQ(source.c, loaded.c);
        }
    }

#ifdef SEAL_USE_ZSTD
    TEST(SerializationTest, ZstdWindowLimit)
    {
        const unsigned char frame[]{ 0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x88, 0x01, 0x00, 0x00 };
        string frame_bytes(reinterpret_cast<const char *>(frame), sizeof(frame));
        istringstream input(frame_bytes);
        auto inflater = util::ztools::make_zstd_inflate_buffer(
            input, static_cast<streamoff>(frame_bytes.size()), MemoryManager::GetPool());
        istream inflated(inflater.get());

        ASSERT_EQ(istream::traits_type::eof(), inflated.peek());
        ASSERT_TRUE(inflater->failed());
    }
#endif

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

            vector<seal_byte> buffer(16);
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
    /*
        TEST(SerializationTest, SEALHeaderUpgrade)
        {
            legacy_headers::SEALHeader_3_4 header_3_4;
            header_3_4.compr_mode = Serialization::compr_mode_default;
            header_3_4.size = 0xF3F3;

            {
                Serialization::SEALHeader header;
                Serialization::LoadHeader(
                    reinterpret_cast<const seal_byte *>(&header_3_4), sizeof(legacy_headers::SEALHeader_3_4), header);
                ASSERT_TRUE(Serialization::IsValidHeader(header));
                ASSERT_EQ(header_3_4.compr_mode, header.compr_mode);
                ASSERT_EQ(header_3_4.size, header.size);
            }
            {
                Serialization::SEALHeader header;
                Serialization::LoadHeader(
                    reinterpret_cast<const seal_byte *>(&header_3_4), sizeof(legacy_headers::SEALHeader_3_4), header,
                    false);

                // No upgrade requested
                ASSERT_FALSE(Serialization::IsValidHeader(header));
            }
        }
    */
    TEST(SerializationTest, SaveLoadToStream)
    {
        test_struct st{ 3, ~0, 3.14159 }, st2;
        using namespace placeholders;
        stringstream stream;

        auto out_size = Serialization::Save(
            bind(&test_struct::save_members, &st, _1), st.save_size(compr_mode_type::none), stream,
            compr_mode_type::none, false);
        auto in_size = Serialization::Load(bind(&test_struct::load_members, &st2, _1), stream, false);
        ASSERT_EQ(out_size, in_size);
        ASSERT_EQ(st.a, st2.a);
        ASSERT_EQ(st.b, st2.b);
        ASSERT_EQ(st.c, st2.c);
#ifdef SEAL_USE_ZSTD
        {
            test_struct st3;
            out_size = Serialization::Save(
                bind(&test_struct::save_members, &st, _1), st.save_size(compr_mode_type::zstd), stream,
                compr_mode_type::zstd, false);
            in_size = Serialization::Load(bind(&test_struct::load_members, &st3, _1), stream, false);
            ASSERT_EQ(out_size, in_size);
            ASSERT_EQ(st.a, st3.a);
            ASSERT_EQ(st.b, st3.b);
            ASSERT_EQ(st.c, st3.c);
        }
#endif
#ifdef SEAL_USE_ZLIB
        {
            test_struct st3;
            out_size = Serialization::Save(
                bind(&test_struct::save_members, &st, _1), st.save_size(compr_mode_type::zlib), stream,
                compr_mode_type::zlib, false);
            in_size = Serialization::Load(bind(&test_struct::load_members, &st3, _1), stream, false);
            ASSERT_EQ(out_size, in_size);
            ASSERT_EQ(st.a, st3.a);
            ASSERT_EQ(st.b, st3.b);
            ASSERT_EQ(st.c, st3.c);
        }
#endif
        {
            test_struct st3;
            out_size = Serialization::Save(
                bind(&test_struct::save_members, &st, _1), st.save_size(compr_mode_type::bitpack), stream,
                compr_mode_type::bitpack, false);
            in_size = Serialization::Load(bind(&test_struct::load_members, &st3, _1), stream, false);
            ASSERT_EQ(out_size, in_size);
            ASSERT_EQ(st.a, st3.a);
            ASSERT_EQ(st.b, st3.b);
            ASSERT_EQ(st.c, st3.c);
        }
    }

    TEST(SerializationTest, SaveLoadToBuffer)
    {
        test_struct st{ 3, ~0, 3.14159 }, st2;
        using namespace placeholders;

        constexpr size_t arr_size = 1024;
        seal_byte buffer[arr_size]{};

        stringstream ss;
        auto test_out_size = Serialization::Save(
            bind(&test_struct::save_members, &st, _1), st.save_size(Serialization::compr_mode_default), ss,
            Serialization::compr_mode_default, false);
        auto out_size = Serialization::Save(
            bind(&test_struct::save_members, &st, _1), st.save_size(Serialization::compr_mode_default), buffer,
            arr_size, Serialization::compr_mode_default, false);
        ASSERT_EQ(test_out_size, out_size);
        for (size_t i = static_cast<size_t>(out_size); i < arr_size; i++)
        {
            ASSERT_TRUE(seal_byte{} == buffer[i]);
        }

        auto in_size = Serialization::Load(bind(&test_struct::load_members, &st2, _1), buffer, arr_size, false);
        ASSERT_EQ(out_size, in_size);
        ASSERT_EQ(st.a, st2.a);
        ASSERT_EQ(st.b, st2.b);
        ASSERT_EQ(st.c, st2.c);
#ifdef SEAL_USE_ZSTD
        {
            // Reset buffer back to zero
            memset(buffer, 0, arr_size);

            test_struct st3;
            ss.seekp(0);
            test_out_size = Serialization::Save(
                bind(&test_struct::save_members, &st, _1), st.save_size(compr_mode_type::zstd), ss,
                compr_mode_type::zstd, false);
            out_size = Serialization::Save(
                bind(&test_struct::save_members, &st, _1), st.save_size(compr_mode_type::zstd), buffer, arr_size,
                compr_mode_type::zstd, false);
            ASSERT_EQ(test_out_size, out_size);
            for (size_t i = static_cast<size_t>(out_size); i < arr_size; i++)
            {
                ASSERT_EQ(seal_byte{}, buffer[i]);
            }

            in_size = Serialization::Load(bind(&test_struct::load_members, &st3, _1), buffer, arr_size, false);
            ASSERT_EQ(out_size, in_size);
            ASSERT_EQ(st.a, st3.a);
            ASSERT_EQ(st.b, st3.b);
            ASSERT_EQ(st.c, st3.c);
        }
#endif
#ifdef SEAL_USE_ZLIB
        {
            // Reset buffer back to zero
            memset(buffer, 0, arr_size);

            test_struct st3;
            ss.seekp(0);
            test_out_size = Serialization::Save(
                bind(&test_struct::save_members, &st, _1), st.save_size(compr_mode_type::zlib), ss,
                compr_mode_type::zlib, false);
            out_size = Serialization::Save(
                bind(&test_struct::save_members, &st, _1), st.save_size(compr_mode_type::zlib), buffer, arr_size,
                compr_mode_type::zlib, false);
            ASSERT_EQ(test_out_size, out_size);
            for (size_t i = static_cast<size_t>(out_size); i < arr_size; i++)
            {
                ASSERT_EQ(seal_byte{}, buffer[i]);
            }

            in_size = Serialization::Load(bind(&test_struct::load_members, &st3, _1), buffer, arr_size, false);
            ASSERT_EQ(out_size, in_size);
            ASSERT_EQ(st.a, st3.a);
            ASSERT_EQ(st.b, st3.b);
            ASSERT_EQ(st.c, st3.c);
        }
#endif
        {
            // Reset buffer back to zero
            memset(buffer, 0, arr_size);

            test_struct st3;
            ss.seekp(0);
            test_out_size = Serialization::Save(
                bind(&test_struct::save_members, &st, _1), st.save_size(compr_mode_type::bitpack), ss,
                compr_mode_type::bitpack, false);
            out_size = Serialization::Save(
                bind(&test_struct::save_members, &st, _1), st.save_size(compr_mode_type::bitpack), buffer, arr_size,
                compr_mode_type::bitpack, false);
            ASSERT_EQ(test_out_size, out_size);
            for (size_t i = static_cast<size_t>(out_size); i < arr_size; i++)
            {
                ASSERT_EQ(seal_byte{}, buffer[i]);
            }

            in_size = Serialization::Load(bind(&test_struct::load_members, &st3, _1), buffer, arr_size, false);
            ASSERT_EQ(out_size, in_size);
            ASSERT_EQ(st.a, st3.a);
            ASSERT_EQ(st.b, st3.b);
            ASSERT_EQ(st.c, st3.c);
        }
    }

    // Round-trips a payload larger than the 256 KB internal decompression buffer to exercise multi-chunk streaming
    // inflation under each compression mode.
    TEST(SerializationTest, CompressedLargeRoundTrip)
    {
        using namespace placeholders;

        large_struct st;
        st.data.resize(size_t(1) << 20); // 1 MB
        for (size_t i = 0; i < st.data.size(); i++)
        {
            // A deterministic, high-entropy pattern so the payload does not compress away to a single chunk.
            st.data[i] = static_cast<uint8_t>((i * 2654435761ULL + 1013904223ULL) >> 24);
        }

        std::vector<compr_mode_type> modes = available_compr_modes();
        modes.push_back(compr_mode_type::none);

        for (auto mode : modes)
        {
            stringstream stream;
            auto out_size = Serialization::Save(
                bind(&large_struct::save_members, &st, _1), st.save_size(mode), stream, mode, false);

            large_struct st2;
            auto in_size = Serialization::Load(bind(&large_struct::load_members, &st2, _1), stream, false);

            ASSERT_EQ(out_size, in_size);
            ASSERT_EQ(st.data, st2.data);
        }
    }

    // A loader that consumes only part of the decompressed payload must not require the remainder to be inflated (the
    // decompression-bomb defense) and must leave the stream positioned exactly at the end of the object so that a
    // following concatenated object loads correctly.
    TEST(SerializationTest, CompressedPartialConsumptionAndConcatenation)
    {
        using namespace placeholders;

        for (auto mode : available_compr_modes())
        {
            // Filler large enough to span many decompression buffers; incompressible so the compressed payload also
            // exceeds the buffer, forcing the loader to skip an unread compressed remainder.
            prefix_struct first;
            for (size_t i = 0; i < prefix_struct::prefix_size; i++)
            {
                first.prefix[i] = static_cast<uint8_t>(i + 1);
            }
            first.filler.resize(size_t(2) << 20); // 2 MB
            for (size_t i = 0; i < first.filler.size(); i++)
            {
                first.filler[i] = static_cast<uint8_t>((i * 6364136223846793005ULL) >> 56);
            }

            test_struct second{ 11, ~3, 2.71828 };

            stringstream stream;
            Serialization::Save(
                bind(&prefix_struct::save_members, &first, _1), first.save_size(mode), stream, mode, false);
            Serialization::Save(
                bind(&test_struct::save_members, &second, _1), second.save_size(mode), stream, mode, false);

            // Load the first object: reads only the prefix, skips the rest.
            prefix_struct first_loaded;
            Serialization::Load(bind(&prefix_struct::load_members, &first_loaded, _1), stream, false);
            ASSERT_EQ(first.prefix, first_loaded.prefix);

            // Load the second object: succeeds only if the first load left the stream correctly positioned.
            test_struct second_loaded;
            Serialization::Load(bind(&test_struct::load_members, &second_loaded, _1), stream, false);
            ASSERT_EQ(second.a, second_loaded.a);
            ASSERT_EQ(second.b, second_loaded.b);
            ASSERT_EQ(second.c, second_loaded.c);
        }
    }

    // A highly compressible filler (the classic bomb shape: tiny compressed, huge decompressed) that the loader never
    // fully reads must load successfully without inflating the whole payload.
    TEST(SerializationTest, CompressedBombShapeLoads)
    {
        using namespace placeholders;

        for (auto mode : available_compr_modes())
        {
            prefix_struct first;
            for (size_t i = 0; i < prefix_struct::prefix_size; i++)
            {
                first.prefix[i] = static_cast<uint8_t>(0xA0 + i);
            }
            first.filler.assign(size_t(8) << 20, uint8_t(0)); // 8 MB of zeros -> tiny compressed

            stringstream stream;
            Serialization::Save(
                bind(&prefix_struct::save_members, &first, _1), first.save_size(mode), stream, mode, false);

            prefix_struct first_loaded;
            Serialization::Load(bind(&prefix_struct::load_members, &first_loaded, _1), stream, false);
            ASSERT_EQ(first.prefix, first_loaded.prefix);
        }
    }

    // A corrupted compressed body must be rejected cleanly rather than crashing or hanging.
    TEST(SerializationTest, LoadCorruptCompressedThrows)
    {
        using namespace placeholders;

        large_struct st;
        st.data.resize(size_t(1) << 20); // 1 MB, incompressible-ish
        for (size_t i = 0; i < st.data.size(); i++)
        {
            st.data[i] = static_cast<uint8_t>((i * 2654435761ULL) >> 24);
        }

        for (auto mode : checksummed_compr_modes())
        {
            stringstream stream;
            Serialization::Save(bind(&large_struct::save_members, &st, _1), st.save_size(mode), stream, mode, false);

            string bytes = stream.str();
            // Mangle the compressed body (leave the header intact and the length unchanged).
            for (size_t i = sizeof(Serialization::SEALHeader) + 16; i < bytes.size(); i += 11)
            {
                bytes[i] = static_cast<char>(bytes[i] ^ 0xFF);
            }

            stringstream corrupt(bytes);
            large_struct st2;
            ASSERT_ANY_THROW(Serialization::Load(bind(&large_struct::load_members, &st2, _1), corrupt, false));
        }
    }

    // Regression test for nested loads through the inflating buffer: an object whose load performs a nested
    // Serialization::Load (which verifies its size via tellg()) must round-trip, including interleaved save/load on a
    // single stream as real objects do.
    TEST(SerializationTest, CompressedNestedAndInterleaved)
    {
        using namespace placeholders;

        std::vector<compr_mode_type> modes = available_compr_modes();
        modes.push_back(compr_mode_type::none);

        for (auto mode : modes)
        {
            nested_struct first;
            first.inner = test_struct{ 5, 6, 7.5 };
            first.tag = 1234;

            stringstream stream;
            Serialization::Save(
                bind(&nested_struct::save_members, &first, _1), first.save_size(mode), stream, mode, false);

            nested_struct first_loaded;
            Serialization::Load(bind(&nested_struct::load_members, &first_loaded, _1), stream, false);
            ASSERT_EQ(first.inner.a, first_loaded.inner.a);
            ASSERT_EQ(first.inner.b, first_loaded.inner.b);
            ASSERT_EQ(first.inner.c, first_loaded.inner.c);
            ASSERT_EQ(first.tag, first_loaded.tag);

            // Save and load a second object on the same stream (interleaved), which only works if the first load left
            // the stream correctly positioned and in a good state.
            nested_struct second;
            second.inner = test_struct{ -1, 9, 0.25 };
            second.tag = 4321;
            Serialization::Save(
                bind(&nested_struct::save_members, &second, _1), second.save_size(mode), stream, mode, false);

            nested_struct second_loaded;
            Serialization::Load(bind(&nested_struct::load_members, &second_loaded, _1), stream, false);
            ASSERT_EQ(second.inner.a, second_loaded.inner.a);
            ASSERT_EQ(second.inner.b, second_loaded.inner.b);
            ASSERT_EQ(second.inner.c, second_loaded.inner.c);
            ASSERT_EQ(second.tag, second_loaded.tag);
        }
    }

    // A truncated compressed stream must be rejected cleanly.
    TEST(SerializationTest, LoadTruncatedCompressedThrows)
    {
        using namespace placeholders;

        large_struct st;
        st.data.resize(size_t(1) << 20); // 1 MB
        for (size_t i = 0; i < st.data.size(); i++)
        {
            st.data[i] = static_cast<uint8_t>((i * 40503ULL) >> 8);
        }

        for (auto mode : available_compr_modes())
        {
            stringstream stream;
            Serialization::Save(bind(&large_struct::save_members, &st, _1), st.save_size(mode), stream, mode, false);

            string bytes = stream.str();
            ASSERT_GT(bytes.size(), sizeof(Serialization::SEALHeader) + 64);
            bytes.resize(bytes.size() / 2); // drop the second half of the compressed payload

            stringstream truncated(bytes);
            large_struct st2;
            ASSERT_ANY_THROW(Serialization::Load(bind(&large_struct::load_members, &st2, _1), truncated, false));
        }
    }

    // On a non-seekable stream the size-vs-available clamp cannot run, so an oversized header.size must not drive
    // the loader into an unbounded skip of trailing bytes. The load must still succeed while consuming only a
    // bounded amount.
    TEST(SerializationTest, NonSeekableStreamInflatedSizeBoundedConsumption)
    {
        using namespace placeholders;

        for (auto mode : available_compr_modes())
        {
            test_struct st{ 7, ~5, 1.4142 };
            stringstream ss;
            Serialization::Save(bind(&test_struct::save_members, &st, _1), st.save_size(mode), ss, mode, false);

            string bytes = ss.str();
            size_t real_size = bytes.size();

            // Overstate header.size (offset 8, 8 bytes) by 8 MB and append 8 MB it could skip into.
            constexpr uint64_t extra = uint64_t(8) << 20;
            uint64_t inflated = static_cast<uint64_t>(real_size) + extra;
            memcpy(&bytes[8], &inflated, sizeof(uint64_t));
            bytes.append(static_cast<size_t>(extra), '\0');

            NonSeekableBuffer buf(std::move(bytes));
            istream in(&buf);

            test_struct st2;
            Serialization::Load(bind(&test_struct::load_members, &st2, _1), in, false);
            ASSERT_EQ(st.a, st2.a);
            ASSERT_EQ(st.b, st2.b);
            ASSERT_EQ(st.c, st2.c);

            // Reads only the object plus at most one internal decompression buffer, never the 8 MB trailer.
            ASSERT_LT(buf.consumed(), streamsize(1) << 20);
        }
    }

    // An uncompressed object must load from a non-seekable stream, where stream positions are unavailable and so
    // cannot be used to cross-check the object size.
    TEST(SerializationTest, NonSeekableStreamUncompressedLoads)
    {
        using namespace placeholders;

        test_struct st{ -2, 8, 2.5 };
        stringstream ss;
        Serialization::Save(
            bind(&test_struct::save_members, &st, _1), st.save_size(compr_mode_type::none), ss, compr_mode_type::none,
            false);

        NonSeekableBuffer buf(ss.str());
        istream in(&buf);

        test_struct st2;
        Serialization::Load(bind(&test_struct::load_members, &st2, _1), in, false);
        ASSERT_EQ(st.a, st2.a);
        ASSERT_EQ(st.b, st2.b);
        ASSERT_EQ(st.c, st2.c);
    }

    // A nested compressed frame reads from an inflating stream, where positions cannot bound its header.size. An
    // overstated nested header.size must not drive the outer decompressor past the nested object into the trailing
    // filler; the load succeeds while consuming only a bounded amount.
    TEST(SerializationTest, CompressedNestedInflatedSizeBoundedConsumption)
    {
        using namespace placeholders;

        for (auto mode : available_compr_modes())
        {
            inflated_nested_struct outer;
            outer.inner = test_struct{ 9, ~2, 3.5 };
            outer.inner_mode = mode;
            outer.inner_size_extra = uint64_t(1) << 40;
            outer.filler_size = size_t(8) << 20; // 8 MB incompressible

            stringstream ss;
            Serialization::Save(
                bind(&inflated_nested_struct::save_members, &outer, _1), outer.save_size(mode), ss, mode, false);

            NonSeekableBuffer buf(ss.str());
            istream in(&buf);

            inflated_nested_struct loaded;
            Serialization::Load(bind(&inflated_nested_struct::load_members, &loaded, _1), in, false);
            ASSERT_EQ(outer.inner.a, loaded.inner.a);
            ASSERT_EQ(outer.inner.b, loaded.inner.b);
            ASSERT_EQ(outer.inner.c, loaded.inner.c);

            // Consumes the nested object plus a bounded number of decompression buffers, never the 8 MB filler.
            ASSERT_LT(buf.consumed(), streamsize(1) << 20);
        }
    }

    // Bit-packing an all-word payload of bounded-width values must produce exactly the size the format prescribes
    // (the original size and the block size, then per block a width byte, a phase byte, and the packed words) and
    // must round-trip.
    TEST(SerializationTest, BitPackSizeAndRoundTrip)
    {
        using namespace placeholders;

        // 1023 values of at most 36 significant bits; with the 8-byte count in front, the serialized stream is
        // exactly 8192 bytes, i.e. eight full 1024-byte blocks of 128 word-aligned words each (phase 0, no
        // verbatim bytes).
        word_struct st;
        st.words.resize(1023);
        uint64_t state = 1;
        for (size_t i = 0; i < st.words.size(); i++)
        {
            state = state * 6364136223846793005ULL + 1442695040888963407ULL;
            st.words[i] = state & ((uint64_t(1) << 36) - 1);
        }

        // Pin the width of every block to exactly 36 bits. The stream words are the count followed by the values,
        // so block i (of 128 stream words each) starts at value index 128 * i - 1.
        st.words[0] |= uint64_t(1) << 35;
        for (size_t block = 1; block < 8; block++)
        {
            st.words[128 * block - 1] |= uint64_t(1) << 35;
        }

        stringstream stream;
        auto out_size = Serialization::Save(
            bind(&word_struct::save_members, &st, _1), st.save_size(compr_mode_type::bitpack), stream,
            compr_mode_type::bitpack, false);

        // 16 (SEALHeader) + 8 (original size) + 1 (block size) + 8 * (1 width byte + 1 phase byte + 128 * 36 / 8)
        ASSERT_EQ(16 + 8 + 1 + 8 * (2 + 576), out_size);

        word_struct st2;
        auto in_size = Serialization::Load(bind(&word_struct::load_members, &st2, _1), stream, false);
        ASSERT_EQ(out_size, in_size);
        ASSERT_TRUE(st.words == st2.words);
    }

    // The encoder must find word data that does not fall on the stream's own word grid: values shifted off the
    // grid by a 1-byte prefix (as a seal_byte member does in real objects) must still pack at their bit width,
    // costing only the per-block phase bytes relative to the aligned encoding.
    TEST(SerializationTest, BitPackMisalignedWords)
    {
        using namespace placeholders;

        word_struct aligned;
        aligned.words.resize(1023);
        uint64_t state = 12345;
        for (size_t i = 0; i < aligned.words.size(); i++)
        {
            state = state * 6364136223846793005ULL + 1442695040888963407ULL;
            aligned.words[i] = state & ((uint64_t(1) << 36) - 1);
        }

        struct prefixed_word_struct
        {
            word_struct inner;

            void save_members(ostream &stream)
            {
                seal_byte prefix{};
                stream.write(reinterpret_cast<const char *>(&prefix), 1);
                inner.save_members(stream);
            }

            streamoff save_size(compr_mode_type compr_mode) const
            {
                size_t raw = 1 + sizeof(uint64_t) + inner.words.size() * 8;
                return static_cast<streamoff>(
                    sizeof(Serialization::SEALHeader) + Serialization::ComprSizeEstimate(raw, compr_mode));
            }
        };
        prefixed_word_struct st;
        st.inner = aligned;

        stringstream aligned_stream;
        auto aligned_size = Serialization::Save(
            bind(&word_struct::save_members, &aligned, _1), aligned.save_size(compr_mode_type::bitpack), aligned_stream,
            compr_mode_type::bitpack, false);

        stringstream prefixed_stream;
        auto prefixed_size = Serialization::Save(
            bind(&prefixed_word_struct::save_members, &st, _1), st.save_size(compr_mode_type::bitpack), prefixed_stream,
            compr_mode_type::bitpack, false);

        // The prefixed stream is 1 original byte longer and spans one more block; realignment costs at most the
        // per-block phase and tail verbatim bytes plus one extra block header, far below the 8 bits per word
        // (over 4,000 bytes here) that losing alignment would cost.
        ASSERT_LE(prefixed_size, aligned_size + 80);
    }

    // A width byte exceeding 64 is malformed and must be rejected cleanly.
    TEST(SerializationTest, BitPackTamperedWidthThrows)
    {
        using namespace placeholders;

        test_struct st{ 3, ~0, 3.14159 };
        stringstream ss;
        Serialization::Save(
            bind(&test_struct::save_members, &st, _1), st.save_size(compr_mode_type::bitpack), ss,
            compr_mode_type::bitpack, false);

        // The first block's width byte follows the SEALHeader (16 bytes), the original size (8 bytes), and the
        // block size (1 byte).
        string bytes = ss.str();
        bytes[25] = static_cast<char>(65);

        stringstream tampered(bytes);
        test_struct st2;
        ASSERT_ANY_THROW(Serialization::Load(bind(&test_struct::load_members, &st2, _1), tampered, false));
    }

    // A phase byte exceeding 7 is malformed and must be rejected cleanly.
    TEST(SerializationTest, BitPackTamperedPhaseThrows)
    {
        using namespace placeholders;

        test_struct st{ 3, ~0, 3.14159 };
        stringstream ss;
        Serialization::Save(
            bind(&test_struct::save_members, &st, _1), st.save_size(compr_mode_type::bitpack), ss,
            compr_mode_type::bitpack, false);

        // The first block's phase byte follows the SEALHeader (16 bytes), the original size (8 bytes), the block
        // size (1 byte), and the width byte.
        string bytes = ss.str();
        bytes[26] = static_cast<char>(8);

        stringstream tampered(bytes);
        test_struct st2;
        ASSERT_ANY_THROW(Serialization::Load(bind(&test_struct::load_members, &st2, _1), tampered, false));
    }

    // A block shorter than a word admits several equivalent encodings: any phase up to the block length splits
    // the bytes between the verbatim phase prefix and the verbatim tail, with zero packed words. The decoder must
    // accept all of them (an encoder is free to emit any) and must reject a phase beyond the block length, which
    // would underflow the word count.
    TEST(SerializationTest, BitPackTinyBlockPhases)
    {
        using namespace placeholders;

        for (unsigned phase = 0; phase <= 4; phase++)
        {
            // Hand-craft a stream holding the 3 original bytes { 0xAA, 0xBB, 0xCC } in a single tiny block
            Serialization::SEALHeader header;
            header.compr_mode = compr_mode_type::bitpack;
            header.size = 16 + 8 + 1 + 2 + 3;
            string blob(reinterpret_cast<const char *>(&header), sizeof(Serialization::SEALHeader));
            uint64_t original_size = 3;
            blob.append(reinterpret_cast<const char *>(&original_size), sizeof(uint64_t));
            blob.push_back(static_cast<char>(10)); // block size: 2^10 bytes
            blob.push_back(static_cast<char>(0)); // width
            blob.push_back(static_cast<char>(phase));
            blob.push_back(static_cast<char>(0xAA));
            blob.push_back(static_cast<char>(0xBB));
            blob.push_back(static_cast<char>(0xCC));

            stringstream stream(blob);
            unsigned char loaded[3]{};
            auto load_fn = [&](istream &in_stream, SEALVersion) {
                in_stream.read(reinterpret_cast<char *>(loaded), 3);
            };
            if (phase <= 3)
            {
                Serialization::Load(load_fn, stream, false);
                ASSERT_EQ(0xAA, loaded[0]);
                ASSERT_EQ(0xBB, loaded[1]);
                ASSERT_EQ(0xCC, loaded[2]);
            }
            else
            {
                ASSERT_ANY_THROW(Serialization::Load(load_fn, stream, false));
            }
        }
    }

    // A block size outside the accepted power-of-two range is malformed and must be rejected cleanly.
    TEST(SerializationTest, BitPackTamperedBlockSizeThrows)
    {
        using namespace placeholders;

        test_struct st{ 3, ~0, 3.14159 };
        stringstream ss;
        Serialization::Save(
            bind(&test_struct::save_members, &st, _1), st.save_size(compr_mode_type::bitpack), ss,
            compr_mode_type::bitpack, false);

        // The block size byte follows the SEALHeader (16 bytes) and the original size (8 bytes).
        string bytes = ss.str();
        bytes[24] = static_cast<char>(5);

        stringstream tampered(bytes);
        test_struct st2;
        ASSERT_ANY_THROW(Serialization::Load(bind(&test_struct::load_members, &st2, _1), tampered, false));

        bytes[24] = static_cast<char>(17);
        stringstream tampered2(bytes);
        ASSERT_ANY_THROW(Serialization::Load(bind(&test_struct::load_members, &st2, _1), tampered2, false));
    }

    // An understated original size makes the parser read past the end of the unpacked data and must be rejected
    // cleanly.
    TEST(SerializationTest, BitPackTamperedSizeThrows)
    {
        using namespace placeholders;

        test_struct st{ 3, ~0, 3.14159 };
        stringstream ss;
        Serialization::Save(
            bind(&test_struct::save_members, &st, _1), st.save_size(compr_mode_type::bitpack), ss,
            compr_mode_type::bitpack, false);

        // The original size is the 8 bytes following the SEALHeader; understate it below what load_members reads.
        string bytes = ss.str();
        uint64_t small_size = 8;
        memcpy(&bytes[16], &small_size, sizeof(uint64_t));

        stringstream tampered(bytes);
        test_struct st2;
        ASSERT_ANY_THROW(Serialization::Load(bind(&test_struct::load_members, &st2, _1), tampered, false));
    }

    // An overstated original size promises far more data than the (unmodified) SEALHeader.size can back. The
    // claimed size must act only as a bound on production -- never an allocation -- and the shortfall must be
    // rejected cleanly once the parser reads past what the real input provides.
    TEST(SerializationTest, BitPackOverstatedSizeThrows)
    {
        using namespace placeholders;

        // Three blocks (1024, 1024, 960 bytes); a decoder believing the overstated size parses the short final
        // block as a full one and runs out of input partway through it.
        large_struct st;
        st.data.resize(3000 - sizeof(uint64_t));
        for (size_t i = 0; i < st.data.size(); i++)
        {
            st.data[i] = static_cast<uint8_t>((i * 2654435761ULL) >> 16);
        }

        stringstream ss;
        Serialization::Save(
            bind(&large_struct::save_members, &st, _1), st.save_size(compr_mode_type::bitpack), ss,
            compr_mode_type::bitpack, false);

        // The original size is the 8 bytes following the SEALHeader; overstate it to 2^63.
        string bytes = ss.str();
        uint64_t huge_size = uint64_t(1) << 63;
        memcpy(&bytes[16], &huge_size, sizeof(uint64_t));

        stringstream tampered(bytes);
        large_struct st2;
        ASSERT_ANY_THROW(Serialization::Load(bind(&large_struct::load_members, &st2, _1), tampered, false));
    }
} // namespace sealtest
