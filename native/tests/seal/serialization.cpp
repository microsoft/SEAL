// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/serialization.h"
#include "seal/util/bitpack.h"
#include "seal/util/defines.h"
#include "seal/util/ztools.h"
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <functional>
#include <limits>
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

        struct byte_struct
        {
            std::vector<uint8_t> bytes;

            void save_members(ostream &stream)
            {
                stream.write(reinterpret_cast<const char *>(bytes.data()), static_cast<streamsize>(bytes.size()));
            }

            void load_members(istream &stream)
            {
                stream.read(reinterpret_cast<char *>(bytes.data()), static_cast<streamsize>(bytes.size()));
            }

            streamoff save_size(compr_mode_type compr_mode) const
            {
                return static_cast<streamoff>(
                    sizeof(Serialization::SEALHeader) + Serialization::ComprSizeEstimate(bytes.size(), compr_mode));
            }
        };

        // Wraps hand-crafted bit-packed blocks of a payload of original_size bytes in a SEALHeader and the 9-byte
        // prologue.
        string make_bitpack_stream(uint64_t original_size, const string &blocks)
        {
            Serialization::SEALHeader header;
            header.compr_mode = compr_mode_type::bitpack;
            header.version_minor = Serialization::format_version_minor_bitpack;
            header.size = sizeof(Serialization::SEALHeader) + 8 + 1 + blocks.size();
            string stream(reinterpret_cast<const char *>(&header), sizeof(Serialization::SEALHeader));
            unsigned char size_bytes[8]{};
            util::bitpack::store_uint64_le(size_bytes, original_size);
            stream.append(reinterpret_cast<const char *>(size_bytes), sizeof(size_bytes));
            stream.push_back(static_cast<char>(util::bitpack::bitpack_block_log2));
            stream += blocks;
            return stream;
        }

        // Loads the original bytes of a bit-packed stream
        vector<uint8_t> load_bitpack_stream(const string &stream, size_t original_size)
        {
            stringstream in(stream);
            vector<uint8_t> loaded(original_size);
            Serialization::Load(
                [&](istream &in_stream, SEALVersion) {
                    in_stream.read(reinterpret_cast<char *>(loaded.data()), static_cast<streamsize>(loaded.size()));
                },
                in, false);
            return loaded;
        }

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

        // Serializes a nested object under a compressed mode and keeps only the nested header and the first few bytes
        // of its compressed payload. Loading performs a nested Serialization::Load over the inflating stream, where
        // the nested header.size cannot be checked against the available input, so the nested decompressor runs out
        // of input inside the outer object.
        struct truncated_nested_struct
        {
            static constexpr size_t kept_payload_size = 4;
            test_struct inner{};
            compr_mode_type inner_mode = compr_mode_type::none;

            void save_members(ostream &stream)
            {
                using namespace std::placeholders;

                stringstream inner_ss;
                Serialization::Save(
                    std::bind(&test_struct::save_members, &inner, _1), inner.save_size(inner_mode), inner_ss,
                    inner_mode, false);
                string inner_bytes = inner_ss.str();
                size_t kept_size = sizeof(Serialization::SEALHeader) + kept_payload_size;
                ASSERT_GT(inner_bytes.size(), kept_size);
                inner_bytes.resize(kept_size);
                stream.write(inner_bytes.data(), static_cast<streamsize>(inner_bytes.size()));
            }

            void load_members(istream &stream)
            {
                using namespace std::placeholders;
                Serialization::Load(std::bind(&test_struct::load_members, &inner, _1), stream, false);
            }

            streamoff save_size(compr_mode_type compr_mode) const
            {
                size_t raw = static_cast<size_t>(inner.save_size(inner_mode));
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

        // The compression modes whose decoders reject the heavy corruption made by LoadCorruptCompressedThrows as
        // malformed data. Bit-packing has almost no redundancy and performs no integrity checking, so corrupted packed
        // bits mostly decode to wrong values rather than a detected error, like compr_mode_type::none.
        std::vector<compr_mode_type> corruption_detecting_compr_modes()
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
        for (uint8_t minor = 0; minor < Serialization::format_version_minor_bitpack; minor++)
        {
            invalid_header.version_minor = minor;
            ASSERT_FALSE(Serialization::IsValidHeader(invalid_header));
        }
        invalid_header.version_minor = Serialization::format_version_minor_bitpack;
        ASSERT_TRUE(Serialization::IsValidHeader(invalid_header));
        invalid_header.version_major = 3;
        ASSERT_FALSE(Serialization::IsValidHeader(invalid_header));
        invalid_header.version_major = SEAL_VERSION_MAJOR;
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
            ASSERT_EQ(Serialization::format_version_major, loaded_header.version_major);
            ASSERT_EQ(Serialization::format_version_minor, loaded_header.version_minor);
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
            ASSERT_EQ(Serialization::format_version_major, loaded_header.version_major);
            ASSERT_EQ(Serialization::format_version_minor, loaded_header.version_minor);
            ASSERT_EQ(Serialization::compr_mode_default, loaded_header.compr_mode);
            ASSERT_EQ(0x00, loaded_header.reserved);
            ASSERT_EQ(256, loaded_header.size);
        }
    }

    TEST(SerializationTest, SaveFormatVersion)
    {
        // Microsoft SEAL 4.0 accepts only version 4.0; Microsoft SEAL 4.4 accepts 4.0-4.4.
        ASSERT_EQ(4, Serialization::format_version_major);
        ASSERT_EQ(0, Serialization::format_version_minor);
        ASSERT_EQ(1, Serialization::format_version_minor_ntt_ciphertext);
        ASSERT_EQ(6, Serialization::format_version_minor_bitpack);
        Serialization::SEALHeader ntt_header;
        ntt_header.version_minor = Serialization::format_version_minor_ntt_ciphertext;
        ASSERT_TRUE(Serialization::IsValidHeader(ntt_header));

        test_struct source{ 3, ~0, 3.14159 };
        using namespace placeholders;
        auto save_members = bind(&test_struct::save_members, &source, _1);
        auto raw_size = source.save_size(compr_mode_type::none);

        auto header_of = [](const string &serialized) {
            Serialization::SEALHeader header;
            Serialization::LoadHeader(
                reinterpret_cast<const seal_byte *>(serialized.data()), serialized.size(), header);
            return header;
        };

        auto compr_modes = available_compr_modes();
        compr_modes.push_back(compr_mode_type::none);
        for (auto compr_mode : compr_modes)
        {
            stringstream stream;
            Serialization::Save(save_members, raw_size, stream, compr_mode, false);
            auto header = header_of(stream.str());
            ASSERT_EQ(Serialization::format_version_major, header.version_major);
            uint8_t default_minor = compr_mode == compr_mode_type::bitpack ? Serialization::format_version_minor_bitpack
                                                                           : Serialization::format_version_minor;
            ASSERT_EQ(default_minor, header.version_minor);

            for (int minor = 0; minor <= SEAL_VERSION_MINOR; minor++)
            {
                uint8_t expected_minor =
                    compr_mode == compr_mode_type::bitpack
                        ? max<uint8_t>(static_cast<uint8_t>(minor), Serialization::format_version_minor_bitpack)
                        : static_cast<uint8_t>(minor);
                stringstream minor_stream;
                Serialization::Save(
                    save_members, raw_size, minor_stream, compr_mode, false, static_cast<uint8_t>(minor));
                ASSERT_EQ(expected_minor, header_of(minor_stream.str()).version_minor);

                vector<seal_byte> buffer(static_cast<size_t>(source.save_size(compr_mode)));
                auto out_size = Serialization::Save(
                    save_members, raw_size, buffer.data(), buffer.size(), compr_mode, false,
                    static_cast<uint8_t>(minor));
                ASSERT_EQ(
                    expected_minor,
                    header_of(string(reinterpret_cast<const char *>(buffer.data()), static_cast<size_t>(out_size)))
                        .version_minor);

                test_struct loaded;
                Serialization::Load(bind(&test_struct::load_members, &loaded, _1), minor_stream, false);
                ASSERT_EQ(source.a, loaded.a);
                ASSERT_EQ(source.b, loaded.b);
                ASSERT_EQ(source.c, loaded.c);
            }

            // Writing a version this library would not accept is rejected
            stringstream bad_stream;
            ASSERT_THROW(
                Serialization::Save(
                    save_members, raw_size, bad_stream, compr_mode, false,
                    static_cast<uint8_t>(SEAL_VERSION_MINOR + 1)),
                invalid_argument);
            vector<seal_byte> bad_buffer(static_cast<size_t>(source.save_size(compr_mode)));
            ASSERT_THROW(
                Serialization::Save(
                    save_members, raw_size, bad_buffer.data(), bad_buffer.size(), compr_mode, false,
                    static_cast<uint8_t>(SEAL_VERSION_MINOR + 1)),
                invalid_argument);
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

        for (auto mode : corruption_detecting_compr_modes())
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
    // (the original size and the block size, then per block a width byte, a prefix byte, and the packed words) and
    // must round-trip.
    TEST(SerializationTest, BitPackSizeAndRoundTrip)
    {
        using namespace placeholders;

        // 1023 values of at most 36 significant bits; with the 8-byte count in front, the serialized stream is
        // exactly 8192 bytes, i.e. eight full 1024-byte blocks of 128 word-aligned words each (no prefix, no
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

        // 16 (SEALHeader) + 8 (original size) + 1 (block size) + 8 * (1 width byte + 1 prefix byte + 128 * 36 / 8)
        ASSERT_EQ(16 + 8 + 1 + 8 * (2 + 576), out_size);

        word_struct st2;
        auto in_size = Serialization::Load(bind(&word_struct::load_members, &st2, _1), stream, false);
        ASSERT_EQ(out_size, in_size);
        ASSERT_TRUE(st.words == st2.words);
    }

    // Words whose low-order bits are all zero must be packed without those bits: the block stores each word shifted
    // right by the number of low-order zero bits, and a shift byte. A leading word that is not like the others, here
    // the word count, is stored in a verbatim prefix instead.
    TEST(SerializationTest, BitPackLowZeroShift)
    {
        using namespace placeholders;

        // 1023 values with bits 7 to 35 significant and bits 0 to 6 zero; with the 8-byte count in front, the
        // serialized stream is exactly 8192 bytes, i.e. eight full blocks of 128 words each.
        word_struct st;
        st.words.resize(1023);
        uint64_t state = 1;
        for (size_t i = 0; i < st.words.size(); i++)
        {
            state = state * 6364136223846793005ULL + 1442695040888963407ULL;
            st.words[i] = (state >> 28) & ~((uint64_t(1) << 7) - 1);
        }

        // Pin the width and shift of every block to exactly 29 and 7. The stream words are the count followed by
        // the values, so block i (of 128 stream words each) starts at value index 128 * i - 1.
        st.words[0] |= (uint64_t(1) << 35) | (uint64_t(1) << 7);
        for (size_t block = 1; block < 8; block++)
        {
            st.words[128 * block - 1] |= (uint64_t(1) << 35) | (uint64_t(1) << 7);
        }

        stringstream stream;
        auto out_size = Serialization::Save(
            bind(&word_struct::save_members, &st, _1), st.save_size(compr_mode_type::bitpack), stream,
            compr_mode_type::bitpack, false);

        // 16 (SEALHeader) + 8 (original size) + 1 (block size); the first block: 3 header bytes, the count in an
        // 8-byte prefix, and 127 words at 29 bits; then seven blocks of 3 header bytes and 128 words at 29 bits
        ASSERT_EQ(16 + 8 + 1 + (3 + 8 + (127 * 29 + 7) / 8) + 7 * (3 + 128 * 29 / 8), out_size);

        // The first block has an equally small encoding with a 5-byte prefix: the words then start at the count's
        // three zero high-order bytes, which add 24 low-order zero bits to the shift, and those bytes become the
        // tail instead. Among equally small encodings the shortest prefix wins. The other blocks need no prefix.
        string bytes = stream.str();
        ASSERT_EQ(29 | 0x80, static_cast<uint8_t>(bytes[25]));
        ASSERT_EQ(5, static_cast<uint8_t>(bytes[26]));
        ASSERT_EQ(31, static_cast<uint8_t>(bytes[27]));
        size_t second_block = 25 + 3 + 8 + (127 * 29 + 7) / 8;
        ASSERT_EQ(29 | 0x80, static_cast<uint8_t>(bytes[second_block]));
        ASSERT_EQ(0, static_cast<uint8_t>(bytes[second_block + 1]));
        ASSERT_EQ(7, static_cast<uint8_t>(bytes[second_block + 2]));

        word_struct st2;
        auto in_size = Serialization::Load(bind(&word_struct::load_members, &st2, _1), stream, false);
        ASSERT_EQ(out_size, in_size);
        ASSERT_TRUE(st.words == st2.words);
    }

    // A block may begin with bytes that are not word data, such as the metadata of a ciphertext. They are stored in
    // a verbatim prefix of up to 255 bytes, so that they do not widen the words after them.
    TEST(SerializationTest, BitPackLongPrefix)
    {
        using namespace placeholders;

        uint64_t state = 0x0123456789ABCDEFULL;
        auto next = [&state]() {
            state = state * 6364136223846793005ULL + 1442695040888963407ULL;
            return state;
        };

        // Appends 30-bit odd words, the first with its top bit set, so that their width is 30 with no shift
        auto append_words = [&](byte_struct &st, size_t count) {
            for (size_t i = 0; i < count; i++)
            {
                uint64_t word = (next() >> 34) | 1 | (i ? 0 : uint64_t(1) << 29);
                size_t old_size = st.bytes.size();
                st.bytes.resize(old_size + 8);
                util::bitpack::store_uint64_le(st.bytes.data() + old_size, word);
            }
        };

        // The first block holds 100 bytes of metadata, 115 words, and 4 more bytes. The second block holds 300 bytes
        // of metadata, more than any prefix can hold, 90 words, and 4 more bytes.
        byte_struct st;
        for (size_t i = 0; i < 100; i++)
        {
            st.bytes.push_back(static_cast<uint8_t>(next() >> 56));
        }
        append_words(st, 115);
        st.bytes.insert(st.bytes.end(), { 0xA1, 0xA2, 0xA3, 0xA4 });
        st.bytes.insert(st.bytes.end(), 300, 0xFF);
        append_words(st, 90);
        st.bytes.insert(st.bytes.end(), { 0xB1, 0xB2, 0xB3, 0xB4 });
        ASSERT_EQ(size_t(2048), st.bytes.size());

        stringstream stream;
        auto out_size = Serialization::Save(
            bind(&byte_struct::save_members, &st, _1), st.save_size(compr_mode_type::bitpack), stream,
            compr_mode_type::bitpack, false);

        // 16 (SEALHeader) + 8 (original size) + 1 (block size); the first block: 2 header bytes, the 100-byte
        // prefix, 115 words at 30 bits, and the 4-byte tail; the second block: 2 header bytes and its 1024 bytes,
        // since every word on any grid with a prefix of at most 255 bytes includes metadata
        ASSERT_EQ(16 + 8 + 1 + (2 + 100 + (115 * 30 + 7) / 8 + 4) + (2 + 1024), out_size);
        string bytes = stream.str();
        ASSERT_EQ(30, static_cast<uint8_t>(bytes[25]));
        ASSERT_EQ(100, static_cast<uint8_t>(bytes[26]));
        size_t second_block = 25 + 2 + 100 + (115 * 30 + 7) / 8 + 4;
        ASSERT_EQ(64, static_cast<uint8_t>(bytes[second_block]));
        ASSERT_EQ(0, static_cast<uint8_t>(bytes[second_block + 1]));

        byte_struct loaded;
        loaded.bytes.resize(st.bytes.size());
        auto in_size = Serialization::Load(bind(&byte_struct::load_members, &loaded, _1), stream, false);
        ASSERT_EQ(out_size, in_size);
        ASSERT_EQ(st.bytes, loaded.bytes);
    }

    // Bit-packing must round-trip words of every shift and of various widths after prefixes of various lengths, and
    // must encode the first block with exactly that width, shift, and prefix.
    TEST(SerializationTest, BitPackRandomizedShiftAndPrefix)
    {
        using namespace placeholders;

        uint64_t state = 0x5A5A5A5AA5A5A5A5ULL;
        auto next = [&state]() {
            state = state * 6364136223846793005ULL + 1442695040888963407ULL;
            return state;
        };

        const size_t prefixes[]{ 0, 1, 7, 8, 9, 97, 128, 200, 254, 255 };
        size_t case_index = 0;
        for (int shift = 1; shift < 64; shift++)
        {
            for (int width : { 1, (65 - shift) / 2, 64 - shift })
            {
                size_t prefix = prefixes[case_index++ % (sizeof(prefixes) / sizeof(prefixes[0]))];

                // The prefix, 300 words of width bits shifted left by shift bits, the first with its top and bottom
                // bits set, and 3 more bytes
                byte_struct st;
                st.bytes.assign(prefix, 0xFF);
                for (size_t k = 0; k < 300; k++)
                {
                    uint64_t value = next() & ((uint64_t(1) << width) - 1);
                    if (!k)
                    {
                        value |= (uint64_t(1) << (width - 1)) | 1;
                    }
                    size_t old_size = st.bytes.size();
                    st.bytes.resize(old_size + 8);
                    util::bitpack::store_uint64_le(st.bytes.data() + old_size, value << shift);
                }
                for (size_t i = 0; i < 3; i++)
                {
                    st.bytes.push_back(static_cast<uint8_t>(next() >> 56));
                }

                stringstream stream;
                auto out_size = Serialization::Save(
                    bind(&byte_struct::save_members, &st, _1), st.save_size(compr_mode_type::bitpack), stream,
                    compr_mode_type::bitpack, false);
                ASSERT_LE(out_size, st.save_size(compr_mode_type::bitpack));
                string bytes = stream.str();

                // When the shift is a whole number of bytes, encodings with the words starting whole bytes later or
                // earlier, without a shift, can be as small or smaller, so only the round trip is checked then.
                if (shift % 8)
                {
                    ASSERT_EQ(width | 0x80, static_cast<uint8_t>(bytes[25]));
                    ASSERT_EQ(prefix, static_cast<uint8_t>(bytes[26]));
                    ASSERT_EQ(shift, static_cast<uint8_t>(bytes[27]));
                }

                byte_struct loaded;
                loaded.bytes.resize(st.bytes.size());
                auto in_size = Serialization::Load(bind(&byte_struct::load_members, &loaded, _1), stream, false);
                ASSERT_EQ(out_size, in_size);
                ASSERT_EQ(st.bytes, loaded.bytes);
            }
        }
    }

    // The encoder must find word data that does not fall on the stream's own word grid: values shifted off the
    // grid by a 1-byte prefix (as a seal_byte member does in real objects) must still pack at their bit width,
    // costing only the per-block prefix bytes relative to the aligned encoding.
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
        // per-block prefix and tail verbatim bytes plus one extra block header, far below the 8 bits per word
        // (over 4,000 bytes here) that losing alignment would cost.
        ASSERT_LE(prefixed_size, aligned_size + 80);
    }

    // The little-endian helpers must agree with byte-by-byte composition, which defines the wire format.
    TEST(SerializationTest, BitPackLittleEndianHelpers)
    {
        const unsigned char known[]{ 1, 2, 3, 4, 5, 6, 7, 8 };
        ASSERT_EQ(0x0807060504030201ULL, util::bitpack::load_uint64_le(known));

        uint64_t state = 0x123456789ABCDEF0ULL;
        for (size_t i = 0; i < 1000; i++)
        {
            state = state * 6364136223846793005ULL + 1442695040888963407ULL;
            unsigned char stored[8]{};
            util::bitpack::store_uint64_le(stored, state);
            for (int j = 0; j < 8; j++)
            {
                ASSERT_EQ(static_cast<unsigned char>(state >> (8 * j)), stored[j]);
            }
            ASSERT_EQ(state, util::bitpack::load_uint64_le(stored));
        }
    }

    // Bit-packing must round-trip buffers with sizes around block boundaries, holding runs of words of every width at
    // every alignment that continue across blocks, and the output must fit in the estimated size.
    TEST(SerializationTest, BitPackRandomizedRoundTrip)
    {
        using namespace placeholders;

        uint64_t state = 0xA5A5A5A55A5A5A5AULL;
        auto next = [&state]() {
            state = state * 6364136223846793005ULL + 1442695040888963407ULL;
            return state;
        };

        // Saves and loads st with bit-packing, and returns the bit-packed payload
        auto round_trip = [](byte_struct &st, string &payload) {
            stringstream stream;
            auto out_size = Serialization::Save(
                bind(&byte_struct::save_members, &st, _1), st.save_size(compr_mode_type::bitpack), stream,
                compr_mode_type::bitpack, false);
            ASSERT_LE(out_size, st.save_size(compr_mode_type::bitpack));
            payload = stream.str().substr(sizeof(Serialization::SEALHeader));

            byte_struct loaded;
            loaded.bytes.resize(st.bytes.size());
            auto in_size = Serialization::Load(bind(&byte_struct::load_members, &loaded, _1), stream, false);
            ASSERT_EQ(out_size, in_size);
            ASSERT_EQ(st.bytes, loaded.bytes);
        };

        // Arbitrary bytes, including sizes that leave no whole word or only part of a block
        const size_t short_sizes[]{ 0, 1, 7, 8, 9, 15, 16, 17, 1023 };
        for (size_t size : short_sizes)
        {
            byte_struct st;
            st.bytes.resize(size);
            for (auto &value : st.bytes)
            {
                value = static_cast<uint8_t>(next() >> 56);
            }
            string payload;
            round_trip(st, payload);
        }

        // For each width from 0 to 64, a run of words after a prefix of width % 8 bytes that continues across blocks
        // and switches to a second width from the third block on, followed by a partial word. The first word of each
        // block has the top bit of its width set, so the encoder must choose exactly this width and prefix.
        const size_t sizes[]{ 1024, 1025, 1031, 2047, 2048, 2049, 3071, 3072, 3073, 4097 };
        for (int width = 0; width <= 64; width++)
        {
            size_t prefix = static_cast<size_t>(width) % 8;
            int width2 = (width + 29) % 65;
            size_t size = sizes[static_cast<size_t>(width) % (sizeof(sizes) / sizeof(sizes[0]))];

            byte_struct st;
            st.bytes.resize(size);
            for (size_t i = 0; i < prefix; i++)
            {
                st.bytes[i] = static_cast<uint8_t>(0xF0 + i);
            }
            size_t word_count = (size - prefix) / 8;
            for (size_t k = 0; k < word_count; k++)
            {
                int word_width = k < 256 ? width : width2;
                uint64_t mask = word_width == 64 ? ~uint64_t(0) : ((uint64_t(1) << word_width) - 1);
                uint64_t word = next() & mask;
                if (word_width && k % 128 == 0)
                {
                    word |= uint64_t(1) << (word_width - 1);
                }
                util::bitpack::store_uint64_le(st.bytes.data() + prefix + 8 * k, word);
            }
            for (size_t i = prefix + 8 * word_count; i < size; i++)
            {
                st.bytes[i] = static_cast<uint8_t>(next() >> 56);
            }

            string payload;
            round_trip(st, payload);

            // The first block is full, so it must be encoded at exactly this width and prefix
            ASSERT_LT(size_t(10), payload.size());
            ASSERT_EQ(width, static_cast<int>(static_cast<uint8_t>(payload[9])));
            ASSERT_EQ(prefix, static_cast<size_t>(static_cast<uint8_t>(payload[10])));
        }
    }

    // Pins the wire format of a short single-block payload. The expected bytes were computed with an independent
    // bit-by-bit reference encoder.
    TEST(SerializationTest, BitPackGoldenVector)
    {
        using namespace placeholders;

        byte_struct st;
        st.bytes = { 0xAA, 0xBB, 0xCC };
        for (auto word : { 0x0000000012345678ULL, 0x0000000030ABCDEFULL, 0x000000002AAAAAAAULL })
        {
            size_t old_size = st.bytes.size();
            st.bytes.resize(old_size + 8);
            util::bitpack::store_uint64_le(st.bytes.data() + old_size, word);
        }
        st.bytes.insert(st.bytes.end(), { 0xDD, 0xEE, 0xFF, 0x11 });

        const vector<uint8_t> expected_payload{ 0x1F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x1E,
                                                0x03, 0xAA, 0xBB, 0xCC, 0x78, 0x56, 0x34, 0xD2, 0x7B, 0xF3,
                                                0x2A, 0xAC, 0xAA, 0xAA, 0xAA, 0x02, 0xDD, 0xEE, 0xFF, 0x11 };

        stringstream stream;
        Serialization::Save(
            bind(&byte_struct::save_members, &st, _1), st.save_size(compr_mode_type::bitpack), stream,
            compr_mode_type::bitpack, false);
        string bytes = stream.str();
        ASSERT_EQ(expected_payload.size(), bytes.size() - sizeof(Serialization::SEALHeader));
        ASSERT_TRUE(equal(
            expected_payload.begin(), expected_payload.end(),
            reinterpret_cast<const uint8_t *>(bytes.data() + sizeof(Serialization::SEALHeader))));

        byte_struct loaded;
        loaded.bytes.resize(st.bytes.size());
        Serialization::Load(bind(&byte_struct::load_members, &loaded, _1), stream, false);
        ASSERT_EQ(st.bytes, loaded.bytes);
    }

    // Pins the wire format of a multi-block payload: a 5-byte prefix followed by 61-bit words (with bits spilling
    // into a ninth byte), an all-zero block (width 0), and a partial block of random bytes (width 64). The
    // expected length and FNV-1a hash were computed with an independent bit-by-bit reference encoder.
    TEST(SerializationTest, BitPackGoldenVectorMultiBlock)
    {
        using namespace placeholders;

        uint64_t state = 0x0123456789ABCDEFULL;
        auto splitmix64 = [&state]() {
            state += 0x9E3779B97F4A7C15ULL;
            uint64_t z = state;
            z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
            z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
            return z ^ (z >> 31);
        };

        byte_struct st;
        st.bytes = { 0x11, 0x22, 0x33, 0x44, 0x55 };
        for (size_t i = 0; i < 127; i++)
        {
            uint64_t word = splitmix64() & ((uint64_t(1) << 61) - 1);
            if (i == 0)
            {
                word |= uint64_t(1) << 60;
            }
            size_t old_size = st.bytes.size();
            st.bytes.resize(old_size + 8);
            util::bitpack::store_uint64_le(st.bytes.data() + old_size, word);
        }
        st.bytes.insert(st.bytes.end(), { 0xA1, 0xA2, 0xA3 });
        ASSERT_EQ(size_t(1024), st.bytes.size());
        st.bytes.resize(2048, 0);
        while (st.bytes.size() < 2500)
        {
            st.bytes.push_back(static_cast<uint8_t>(splitmix64()));
        }

        stringstream stream;
        Serialization::Save(
            bind(&byte_struct::save_members, &st, _1), st.save_size(compr_mode_type::bitpack), stream,
            compr_mode_type::bitpack, false);
        string payload = stream.str().substr(sizeof(Serialization::SEALHeader));
        ASSERT_EQ(size_t(1444), payload.size());

        // Width and prefix of each block
        ASSERT_EQ(61, static_cast<uint8_t>(payload[9]));
        ASSERT_EQ(5, static_cast<uint8_t>(payload[10]));
        ASSERT_EQ(0, static_cast<uint8_t>(payload[988]));
        ASSERT_EQ(0, static_cast<uint8_t>(payload[989]));
        ASSERT_EQ(64, static_cast<uint8_t>(payload[990]));
        ASSERT_EQ(0, static_cast<uint8_t>(payload[991]));

        uint64_t hash = 0xCBF29CE484222325ULL;
        for (char c : payload)
        {
            hash ^= static_cast<uint8_t>(c);
            hash *= 0x100000001B3ULL;
        }
        ASSERT_EQ(0x6D76F2CA1F37F06CULL, hash);

        byte_struct loaded;
        loaded.bytes.resize(st.bytes.size());
        Serialization::Load(bind(&byte_struct::load_members, &loaded, _1), stream, false);
        ASSERT_EQ(st.bytes, loaded.bytes);
    }

    // Pins the wire format of single blocks whose words have low-order zero bits, and the encoder's choice of
    // whether to shift them out: it must shift only when that makes the block strictly smaller. Each case also has
    // an equally valid encoding that the encoder must not emit (shifted where the expected one is not, and vice
    // versa), which must decode to the same bytes. The expected bytes were computed with an independent bit-by-bit
    // reference encoder.
    TEST(SerializationTest, BitPackGoldenVectorShift)
    {
        using namespace placeholders;

        struct golden_case
        {
            vector<uint8_t> original;
            vector<uint8_t> expected_payload;
            vector<uint8_t> alternative_blocks;
        };
        auto make_original = [](const vector<uint8_t> &prefix, const vector<uint64_t> &words,
                                const vector<uint8_t> &tail) {
            vector<uint8_t> result = prefix;
            for (auto word : words)
            {
                size_t old_size = result.size();
                result.resize(old_size + 8);
                util::bitpack::store_uint64_le(result.data() + old_size, word);
            }
            result.insert(result.end(), tail.begin(), tail.end());
            return result;
        };

        vector<golden_case> cases{
            // The words of BitPackGoldenVector shifted left by 9 bits: with the shift (width 30, prefix 3, shift 9),
            // they pack into the same bytes as there. Without it (width 39), the block is 2 bytes larger.
            { make_original(
                  { 0xAA, 0xBB, 0xCC }, { 0x12345678ULL << 9, 0x30ABCDEFULL << 9, 0x2AAAAAAAULL << 9 },
                  { 0xDD, 0xEE, 0xFF, 0x11 }),
              { 0x1F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x9E, 0x03, 0x09, 0xAA, 0xBB, 0xCC, 0x78,
                0x56, 0x34, 0xD2, 0x7B, 0xF3, 0x2A, 0xAC, 0xAA, 0xAA, 0xAA, 0x02, 0xDD, 0xEE, 0xFF, 0x11 },
              { 0x27, 0x03, 0xAA, 0xBB, 0xCC, 0x00, 0xF0, 0xAC, 0x68, 0x24, 0x00, 0xEF,
                0xCD, 0xAB, 0x30, 0x00, 0x55, 0x55, 0x55, 0x15, 0xDD, 0xEE, 0xFF, 0x11 } },

            // The words 2 and 4: without the shift (width 3), they pack into one byte. With it (width 2, shift 1),
            // they still need one byte, so the shift byte would make the block larger.
            { make_original({}, { 2, 4 }, {}),
              { 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x03, 0x00, 0x22 },
              { 0x82, 0x00, 0x01, 0x09 } },

            // Words with exactly one low-order zero bit: the shift saves one packed byte (width 12 instead of 13),
            // which only pays for the shift byte, so the encoder does not shift.
            { make_original({ 0xC3 }, { 0x1236, 0x0A4E, 0x1FFE, 0x0B5A }, { 0x5A }),
              { 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x0D,
                0x01, 0xC3, 0x36, 0xD2, 0x49, 0xF9, 0x7F, 0xAD, 0x05, 0x5A },
              { 0x8C, 0x01, 0x01, 0xC3, 0x1B, 0x79, 0x52, 0xFF, 0xDF, 0x5A, 0x5A } }
        };

        for (const auto &c : cases)
        {
            byte_struct st;
            st.bytes = c.original;
            stringstream stream;
            Serialization::Save(
                bind(&byte_struct::save_members, &st, _1), st.save_size(compr_mode_type::bitpack), stream,
                compr_mode_type::bitpack, false);
            string bytes = stream.str();
            ASSERT_EQ(c.expected_payload.size(), bytes.size() - sizeof(Serialization::SEALHeader));
            ASSERT_TRUE(equal(
                c.expected_payload.begin(), c.expected_payload.end(),
                reinterpret_cast<const uint8_t *>(bytes.data() + sizeof(Serialization::SEALHeader))));

            byte_struct loaded;
            loaded.bytes.resize(st.bytes.size());
            Serialization::Load(bind(&byte_struct::load_members, &loaded, _1), stream, false);
            ASSERT_EQ(st.bytes, loaded.bytes);

            string alternative(c.alternative_blocks.begin(), c.alternative_blocks.end());
            ASSERT_EQ(
                c.original,
                load_bitpack_stream(make_bitpack_stream(c.original.size(), alternative), c.original.size()));
        }
    }

    // Pins the wire format of a multi-block payload with low-order zero bits: 100 random bytes followed by 31-bit
    // words with 5 low-order zero bits (prefix 100, shift 5); a block starting in the middle of a word, where the
    // prefixes 1 to 4 tie and the smallest wins (shift 29); and a partial block where random bytes interrupt the
    // words (width 64). The expected length and FNV-1a hash were computed with an independent bit-by-bit reference
    // encoder.
    TEST(SerializationTest, BitPackGoldenVectorShiftMultiBlock)
    {
        using namespace placeholders;

        uint64_t state = 0x0123456789ABCDEFULL;
        auto splitmix64 = [&state]() {
            state += 0x9E3779B97F4A7C15ULL;
            uint64_t z = state;
            z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
            z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
            return z ^ (z >> 31);
        };

        byte_struct st;
        auto append_bytes = [&](size_t count) {
            for (size_t i = 0; i < count; i++)
            {
                st.bytes.push_back(static_cast<uint8_t>(splitmix64()));
            }
        };
        auto append_words = [&](size_t count) {
            for (size_t i = 0; i < count; i++)
            {
                size_t old_size = st.bytes.size();
                st.bytes.resize(old_size + 8);
                util::bitpack::store_uint64_le(
                    st.bytes.data() + old_size, (splitmix64() & ((uint64_t(1) << 31) - 1)) << 5);
            }
        };
        append_bytes(100);
        append_words(250);
        append_bytes(260);
        append_words(40);
        st.bytes.insert(st.bytes.end(), { 0xA1, 0xA2, 0xA3 });
        ASSERT_EQ(size_t(2683), st.bytes.size());

        stringstream stream;
        Serialization::Save(
            bind(&byte_struct::save_members, &st, _1), st.save_size(compr_mode_type::bitpack), stream,
            compr_mode_type::bitpack, false);
        string payload = stream.str().substr(sizeof(Serialization::SEALHeader));
        ASSERT_EQ(size_t(1703), payload.size());

        // Width byte, prefix, and shift of each block
        ASSERT_EQ(0x9F, static_cast<uint8_t>(payload[9]));
        ASSERT_EQ(100, static_cast<uint8_t>(payload[10]));
        ASSERT_EQ(5, static_cast<uint8_t>(payload[11]));
        ASSERT_EQ(0x9F, static_cast<uint8_t>(payload[562]));
        ASSERT_EQ(1, static_cast<uint8_t>(payload[563]));
        ASSERT_EQ(29, static_cast<uint8_t>(payload[564]));
        ASSERT_EQ(64, static_cast<uint8_t>(payload[1066]));
        ASSERT_EQ(0, static_cast<uint8_t>(payload[1067]));

        uint64_t hash = 0xCBF29CE484222325ULL;
        for (char c : payload)
        {
            hash ^= static_cast<uint8_t>(c);
            hash *= 0x100000001B3ULL;
        }
        ASSERT_EQ(0x2B583A7F2A4A9DD1ULL, hash);

        byte_struct loaded;
        loaded.bytes.resize(st.bytes.size());
        Serialization::Load(bind(&byte_struct::load_members, &loaded, _1), stream, false);
        ASSERT_EQ(st.bytes, loaded.bytes);
    }

    // Bit-packed data with a format version older than 4.6 must be rejected.
    TEST(SerializationTest, BitPackMinorVersionGate)
    {
        using namespace placeholders;

        test_struct st{ 3, ~0, 3.14159 };
        stringstream ss;
        Serialization::Save(
            bind(&test_struct::save_members, &st, _1), st.save_size(compr_mode_type::bitpack), ss,
            compr_mode_type::bitpack, false);

        string bytes = ss.str();
        ASSERT_EQ(static_cast<char>(Serialization::format_version_minor_bitpack), bytes[4]);
        bytes[4] = static_cast<char>(Serialization::format_version_minor_bitpack - 1);

        stringstream downgraded(bytes);
        test_struct st2;
        ASSERT_ANY_THROW(Serialization::Load(bind(&test_struct::load_members, &st2, _1), downgraded, false));
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
        uint64_t size = 0;
        memcpy(&size, &bytes[8], sizeof(uint64_t));
        size++;
        memcpy(&bytes[8], &size, sizeof(uint64_t));
        bytes.push_back(0);

        stringstream tampered(bytes);
        test_struct st2;
        ASSERT_ANY_THROW(Serialization::Load(bind(&test_struct::load_members, &st2, _1), tampered, false));
    }

    // A prefix longer than its block is malformed and must be rejected cleanly. The stream carries enough bytes
    // for the longer prefix and the tail that an unchecked word count would imply, so that only the prefix check,
    // not a shortage of input, can reject it.
    TEST(SerializationTest, BitPackTamperedPrefixThrows)
    {
        // A 16-byte block of two zero-width words: a 16-byte prefix is valid, a 17-byte one is not
        string valid_block{ static_cast<char>(0), static_cast<char>(16) };
        valid_block.append(16, static_cast<char>(0x5A));
        auto loaded = load_bitpack_stream(make_bitpack_stream(16, valid_block), 16);
        ASSERT_EQ(vector<uint8_t>(16, 0x5A), loaded);

        string long_block{ static_cast<char>(0), static_cast<char>(17) };
        long_block.append(24, static_cast<char>(0x5A));
        ASSERT_ANY_THROW(load_bitpack_stream(make_bitpack_stream(16, long_block), 16));
    }

    // A shift byte must be nonzero, may only follow a nonzero width, and the shifted words must fit in 64 bits.
    // Each tampered block below would otherwise decode, so only the targeted check can reject it.
    TEST(SerializationTest, BitPackTamperedShiftThrows)
    {
        // Two words, 0x30 and 0x10: width 2 and shift 4, packed as the 2-bit values 3 and 1 in the byte 0x07
        const vector<uint8_t> original{ 0x30, 0, 0, 0, 0, 0, 0, 0, 0x10, 0, 0, 0, 0, 0, 0, 0 };
        auto block = [](unsigned char width_byte, unsigned char shift, bool packed) {
            string result{ static_cast<char>(width_byte), static_cast<char>(0), static_cast<char>(shift) };
            if (packed)
            {
                result.push_back(static_cast<char>(0x07));
            }
            return result;
        };
        ASSERT_EQ(original, load_bitpack_stream(make_bitpack_stream(16, block(0x82, 4, true)), 16));

        // Shift of zero
        ASSERT_ANY_THROW(load_bitpack_stream(make_bitpack_stream(16, block(0x82, 0, true)), 16));

        // Width of zero
        ASSERT_ANY_THROW(load_bitpack_stream(make_bitpack_stream(16, block(0x80, 4, false)), 16));

        // Width plus shift exceeding 64
        ASSERT_ANY_THROW(load_bitpack_stream(make_bitpack_stream(16, block(0x82, 63, true)), 16));

        // Missing shift byte
        ASSERT_ANY_THROW(load_bitpack_stream(make_bitpack_stream(16, string{ static_cast<char>(0x82), 0 }), 16));
    }

    // A block shorter than a word admits several equivalent encodings: any prefix up to the block length splits
    // the bytes between the verbatim prefix and the verbatim tail, with zero packed words. The decoder must
    // accept all of them (an encoder is free to emit any) and must reject a prefix beyond the block length, which
    // would underflow the word count.
    TEST(SerializationTest, BitPackTinyBlockPrefixes)
    {
        using namespace placeholders;

        for (unsigned prefix = 0; prefix <= 4; prefix++)
        {
            // Hand-craft a stream holding the 3 original bytes { 0xAA, 0xBB, 0xCC } in a single tiny block. The
            // rejected prefix is padded so that only the prefix check, not a shortage of input, can reject it.
            string body{ static_cast<char>(0xAA), static_cast<char>(0xBB), static_cast<char>(0xCC) };
            if (prefix > 3)
            {
                body.append(8, '\0');
            }
            Serialization::SEALHeader header;
            header.compr_mode = compr_mode_type::bitpack;
            header.version_minor = Serialization::format_version_minor_bitpack;
            header.size = sizeof(Serialization::SEALHeader) + 8 + 1 + 2 + body.size();
            string blob(reinterpret_cast<const char *>(&header), sizeof(Serialization::SEALHeader));
            unsigned char original_size[8]{};
            util::bitpack::store_uint64_le(original_size, 3);
            blob.append(reinterpret_cast<const char *>(original_size), sizeof(original_size));
            blob.push_back(static_cast<char>(util::bitpack::bitpack_block_log2));
            blob.push_back(static_cast<char>(0)); // width
            blob.push_back(static_cast<char>(prefix));
            blob += body;

            stringstream stream(blob);
            unsigned char loaded[3]{};
            auto load_fn = [&](istream &in_stream, SEALVersion) {
                in_stream.read(reinterpret_cast<char *>(loaded), 3);
            };
            if (prefix <= 3)
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

    // A block size other than 2^10 is malformed and must be rejected cleanly.
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
        for (int block_log2 : { 9, 11 })
        {
            bytes[24] = static_cast<char>(block_log2);

            stringstream tampered(bytes);
            test_struct st2;
            ASSERT_ANY_THROW(Serialization::Load(bind(&test_struct::load_members, &st2, _1), tampered, false));
        }
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
        util::bitpack::store_uint64_le(reinterpret_cast<unsigned char *>(&bytes[16]), small_size);

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
        util::bitpack::store_uint64_le(reinterpret_cast<unsigned char *>(&bytes[16]), huge_size);

        stringstream tampered(bytes);
        large_struct st2;
        ASSERT_ANY_THROW(Serialization::Load(bind(&large_struct::load_members, &st2, _1), tampered, false));
    }

    // The original size must be representable as a stream offset and fit in the blocks that the packed bytes can
    // hold. Frames claiming more must be rejected, even if the parser reads only a prefix.
    TEST(SerializationTest, BitPackPrologueSizeBounds)
    {
        auto make_zero_blocks = [](uint64_t original_size, size_t block_count) {
            Serialization::SEALHeader header;
            header.compr_mode = compr_mode_type::bitpack;
            header.version_minor = Serialization::format_version_minor_bitpack;
            header.size = static_cast<uint64_t>(sizeof(Serialization::SEALHeader) + 8 + 1 + 2 * block_count);
            string blob(reinterpret_cast<const char *>(&header), sizeof(Serialization::SEALHeader));
            unsigned char size_bytes[8]{};
            util::bitpack::store_uint64_le(size_bytes, original_size);
            blob.append(reinterpret_cast<const char *>(size_bytes), sizeof(size_bytes));
            blob.push_back(static_cast<char>(util::bitpack::bitpack_block_log2));
            for (size_t i = 0; i < block_count; i++)
            {
                blob.push_back(0);
                blob.push_back(0);
            }
            return blob;
        };

        constexpr size_t block_count = 3;
        byte_struct loaded;
        loaded.bytes.resize(block_count * util::bitpack::bitpack_block_bytes);
        string valid = make_zero_blocks(loaded.bytes.size(), block_count);
        stringstream valid_stream(valid);
        Serialization::Load(bind(&byte_struct::load_members, &loaded, placeholders::_1), valid_stream, false);
        ASSERT_TRUE(all_of(loaded.bytes.begin(), loaded.bytes.end(), [](uint8_t value) { return value == 0; }));

        // Read only a prefix, so that only the size checks, not a shortage of input, can reject the frame
        auto read_one = [](istream &stream, SEALVersion) {
            char value = 0;
            stream.read(&value, 1);
        };

        // One byte more than the blocks can hold needs a partial fourth block
        string too_many_blocks = make_zero_blocks(block_count * util::bitpack::bitpack_block_bytes + 1, block_count);
        stringstream too_many_stream(too_many_blocks);
        ASSERT_ANY_THROW(Serialization::Load(read_one, too_many_stream, false));

        loaded.bytes.resize(1);
        string huge = make_zero_blocks(numeric_limits<uint64_t>::max(), block_count);
        stringstream huge_stream(huge);
        ASSERT_ANY_THROW(
            Serialization::Load(bind(&byte_struct::load_members, &loaded, placeholders::_1), huge_stream, false));

        string impossible = make_zero_blocks((block_count + 1) * util::bitpack::bitpack_block_bytes, block_count);
        stringstream impossible_stream(impossible);
        ASSERT_ANY_THROW(Serialization::Load(read_one, impossible_stream, false));

        string direct;
        unsigned char size_bytes[8]{};
        util::bitpack::store_uint64_le(
            size_bytes, static_cast<uint64_t>(numeric_limits<streamoff>::max()) + uint64_t(1));
        direct.append(reinterpret_cast<const char *>(size_bytes), sizeof(size_bytes));
        direct.push_back(static_cast<char>(util::bitpack::bitpack_block_log2));
        direct.push_back(0);
        direct.push_back(0);
        stringstream direct_stream(direct);
        auto unpack_buffer = util::bitpack::make_bitpack_unpack_buffer(
            direct_stream, numeric_limits<streamoff>::max(), MemoryManager::GetPool());
        istream unpacked(unpack_buffer.get());
        char value = 0;
        unpacked.read(&value, 1);
        ASSERT_TRUE(unpack_buffer->failed());
    }

    // On a non-seekable stream header.size cannot be checked against the available input, so truncated compressed
    // input is detected only when the decompressor runs out of input. The load must throw rather than terminate, and
    // must restore the stream's exception mask.
    TEST(SerializationTest, NonSeekableStreamTruncatedCompressedThrows)
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
            stringstream ss;
            Serialization::Save(bind(&large_struct::save_members, &st, _1), st.save_size(mode), ss, mode, false);

            string bytes = ss.str();
            ASSERT_GT(bytes.size(), sizeof(Serialization::SEALHeader) + 64);
            bytes.resize(bytes.size() / 2); // drop the second half of the compressed payload

            NonSeekableBuffer buf(std::move(bytes));
            istream in(&buf);

            large_struct st2;
            ASSERT_ANY_THROW(Serialization::Load(bind(&large_struct::load_members, &st2, _1), in, false));
            ASSERT_TRUE(in.exceptions() == ios_base::goodbit);
        }
    }

    // On a non-seekable stream, input that ends before the compressed size in header.size must be rejected even if
    // the parser does not need the missing bytes, such as a trailing checksum.
    TEST(SerializationTest, NonSeekableStreamTruncatedTrailerThrows)
    {
        using namespace placeholders;

        for (auto mode : available_compr_modes())
        {
            test_struct st{ 5, ~7, 1.25 };
            stringstream ss;
            Serialization::Save(bind(&test_struct::save_members, &st, _1), st.save_size(mode), ss, mode, false);
            string bytes = ss.str();

            // Drop the last 4 bytes, which for zlib are the Adler-32 checksum
            {
                NonSeekableBuffer buf(bytes.substr(0, bytes.size() - 4));
                istream in(&buf);
                test_struct st2;
                ASSERT_ANY_THROW(Serialization::Load(bind(&test_struct::load_members, &st2, _1), in, false));
            }

            // Overstate header.size (offset 8, 8 bytes) by one byte, with no trailing data. Bit-packing reads exactly
            // the bytes the parser needs, so like an uncompressed object it cannot detect this on a non-seekable
            // stream.
            if (mode != compr_mode_type::bitpack)
            {
                string overstated = bytes;
                uint64_t size = 0;
                memcpy(&size, &overstated[8], sizeof(uint64_t));
                size++;
                memcpy(&overstated[8], &size, sizeof(uint64_t));
                NonSeekableBuffer buf(std::move(overstated));
                istream in(&buf);
                test_struct st2;
                ASSERT_ANY_THROW(Serialization::Load(bind(&test_struct::load_members, &st2, _1), in, false));
            }
        }
    }

    // A truncated compressed frame nested in a compressed object runs out of input inside the outer inflating
    // stream, where its header.size cannot be checked against the available input, even if the outer stream is
    // seekable. The load must throw rather than terminate, and must restore the stream's exception mask.
    TEST(SerializationTest, CompressedNestedTruncatedThrows)
    {
        using namespace placeholders;

        for (auto outer_mode : available_compr_modes())
        {
            for (auto inner_mode : available_compr_modes())
            {
                truncated_nested_struct outer;
                outer.inner = test_struct{ 4, ~6, 0.5 };
                outer.inner_mode = inner_mode;

                stringstream ss;
                Serialization::Save(
                    bind(&truncated_nested_struct::save_members, &outer, _1), outer.save_size(outer_mode), ss,
                    outer_mode, false);

                truncated_nested_struct loaded;
                ASSERT_ANY_THROW(
                    Serialization::Load(bind(&truncated_nested_struct::load_members, &loaded, _1), ss, false));
                ASSERT_TRUE(ss.exceptions() == ios_base::goodbit);
            }
        }
    }
} // namespace sealtest
