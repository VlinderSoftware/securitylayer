/* Copyright 2020  Ronald Landheer-Cieslak
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License. */
#include "catch.hpp"
#include "deterministicrandomnumbergenerator.hpp"
#include "../details/intermediatebufferadapter.hpp"

static_assert(DNP3SAV6_PROFILE_HPP_INCLUDED, "profile.hpp should be pre-included in CMakeLists.txt");

using namespace boost::asio;
using namespace DNP3SAv6::Details;
using namespace DNP3SAv6::Tests;

template < size_t buffer_size__, size_t output_size__, size_t input_size__ >
struct TestBuffers
{
    unsigned char buffer_[buffer_size__] = { 0 };
    unsigned char output_[output_size__] = { 0 };
    unsigned char input_[input_size__] = { 0 };
};

TEST_CASE( "IntermediateBufferAdapter: straight-forward pipe-through (1)", "[intermediatebufferadapter]" ) {
    TestBuffers< 32, 32, 64 > test_buffers;

    DeterministicRandomNumberGenerator rng;
    rng.generate(mutable_buffer(test_buffers.input_, sizeof(test_buffers.input_)));

    IntermediateBufferAdapter intermediate_buffer_adapter(mutable_buffer(test_buffers.buffer_, sizeof(test_buffers.buffer_)));
    REQUIRE( intermediate_buffer_adapter.push(mutable_buffer(test_buffers.output_, sizeof(test_buffers.output_)), const_buffer(test_buffers.input_, sizeof(test_buffers.input_))) == sizeof(test_buffers.output_) );
    REQUIRE( memcmp(test_buffers.input_, test_buffers.output_, sizeof(test_buffers.output_)) == 0 );
    REQUIRE( memcmp(test_buffers.input_ + sizeof(test_buffers.output_), test_buffers.buffer_, sizeof(test_buffers.buffer_)) == 0 );
}

TEST_CASE( "IntermediateBufferAdapter: straight-forward pipe-through (2)", "[intermediatebufferadapter]" ) {
    TestBuffers< 16, 48, 64 > test_buffers;

    DeterministicRandomNumberGenerator rng;
    rng.generate(mutable_buffer(test_buffers.input_, sizeof(test_buffers.input_)));

    IntermediateBufferAdapter intermediate_buffer_adapter(mutable_buffer(test_buffers.buffer_, sizeof(test_buffers.buffer_)));
    REQUIRE( intermediate_buffer_adapter.push(mutable_buffer(test_buffers.output_, sizeof(test_buffers.output_)), const_buffer(test_buffers.input_, sizeof(test_buffers.input_))) == sizeof(test_buffers.output_) );
    REQUIRE( memcmp(test_buffers.input_, test_buffers.output_, sizeof(test_buffers.output_)) == 0 );
    REQUIRE( memcmp(test_buffers.input_ + sizeof(test_buffers.output_), test_buffers.buffer_, sizeof(test_buffers.buffer_)) == 0 );
}

TEST_CASE( "IntermediateBufferAdapter: straight-forward pipe-through (3)", "[intermediatebufferadapter]" ) {
    TestBuffers< 8, 56, 64 > test_buffers;

    DeterministicRandomNumberGenerator rng;
    rng.generate(mutable_buffer(test_buffers.input_, sizeof(test_buffers.input_)));

    IntermediateBufferAdapter intermediate_buffer_adapter(mutable_buffer(test_buffers.buffer_, sizeof(test_buffers.buffer_)));
    REQUIRE( intermediate_buffer_adapter.push(mutable_buffer(test_buffers.output_, sizeof(test_buffers.output_)), const_buffer(test_buffers.input_, sizeof(test_buffers.input_))) == sizeof(test_buffers.output_) );
    REQUIRE( memcmp(test_buffers.input_, test_buffers.output_, sizeof(test_buffers.output_)) == 0 );
    REQUIRE( memcmp(test_buffers.input_ + sizeof(test_buffers.output_), test_buffers.buffer_, sizeof(test_buffers.buffer_)) == 0 );
}


TEST_CASE( "IntermediateBufferAdapter: partial pipe-through (1)", "[intermediatebufferadapter]" ) {
    TestBuffers< 8, 56, 64 > test_buffers;

    //DeterministicRandomNumberGenerator rng;
    //rng.generate(mutable_buffer(test_buffers.input_, sizeof(test_buffers.input_)));

    for (unsigned int i(0); i < 64; ++i)
    {
        test_buffers.input_[i] = (unsigned char)i;
    }

    IntermediateBufferAdapter intermediate_buffer_adapter(mutable_buffer(test_buffers.buffer_, sizeof(test_buffers.buffer_)));

    REQUIRE( intermediate_buffer_adapter.push(mutable_buffer(test_buffers.output_, sizeof(test_buffers.output_)), const_buffer(test_buffers.input_ + 0, 3)) == 0 );
    REQUIRE( intermediate_buffer_adapter.push(mutable_buffer(test_buffers.output_, sizeof(test_buffers.output_)), const_buffer(test_buffers.input_ + 3, 3)) == 0 );
    REQUIRE( intermediate_buffer_adapter.push(mutable_buffer(test_buffers.output_, sizeof(test_buffers.output_)), const_buffer(test_buffers.input_ + 6, 3)) == 1 );

    for (unsigned int i(0); i < (64 - 9) / 3; ++i)
    {
        REQUIRE( intermediate_buffer_adapter.push(mutable_buffer(test_buffers.output_ + 1 + (3 * i), sizeof(test_buffers.output_) - 1 - (3 * i)), const_buffer(test_buffers.input_ + 9 + (3 * i), 3)) == 3 );
    }
    REQUIRE( intermediate_buffer_adapter.push(mutable_buffer(test_buffers.output_ + 55, 1), const_buffer(test_buffers.input_ + 63, 1)) == 1 );

    REQUIRE( memcmp(test_buffers.input_, test_buffers.output_, sizeof(test_buffers.output_)) == 0 );
    REQUIRE( memcmp(test_buffers.input_ + sizeof(test_buffers.output_), test_buffers.buffer_, sizeof(test_buffers.buffer_)) == 0 );
}

