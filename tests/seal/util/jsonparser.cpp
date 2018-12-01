// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "CppUnitTest.h"
#include "seal/util/jsonparser.h"
#include <string>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
using namespace seal::util;
using namespace std;

namespace SEALTest
{
    namespace util
    {
        TEST_CLASS(JsonParser)
        {
        public:
            TEST_METHOD(StripWhitespace)
            {
                string json(" { \"name1\" : \"value1\", \"name2\" : \"value2\", \"array1\" : [ \"hello\", \"world\" ], \"object1\" : { \"subname1\" : \"subvalue1\" } } ");
                string expected("{\"name1\":\"value1\",\"name2\":\"value2\",\"array1\":[\"hello\",\"world\"],\"object1\":{\"subname1\":\"subvalue1\"}}");
                Assert::AreEqual(expected, stripWhitespace(json));
            }

            TEST_METHOD(JsonParse)
            {
                string json("{\"name1\":\"value1\",\"name2\":\"value2\",\"array1\":[\"hello\",\"world\"],\"object1\":{\"subname1\":\"subvalue1\"}}");
                auto result = parseJSON(json);
            }
        };
    }
}
