/* Copyright 2019  Ronald Landheer-Cieslak
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
#include "../details/pbkdf2.hpp"

static_assert(DNP3SAV6_PROFILE_HPP_INCLUDED, "profile.hpp should be pre-included in CMakeLists.txt");

using namespace std;
using namespace DNP3SAv6::Details;

TEST_CASE( "PBKDF2: create a key", "[pbkdf2]" ) {
    string password("Just a bunch of random digits");
    PBKDF2 kdf(password);
    auto key(kdf(32));

    REQUIRE(key.size() == 32);
    unsigned char const expected_key[] = {
          0xbe, 0x1e, 0xcc, 0x90, 0xe9, 0xd9, 0xc9, 0x65, 0xef, 0x8d, 0xf5, 0x0d, 0x03, 0x51, 0xd2, 0xdb
        , 0x4c, 0x7e, 0x84, 0xd4, 0xb5, 0x4f, 0x90, 0x27, 0x1c, 0x35, 0x54, 0x40, 0x59, 0x63, 0x26, 0x78
        };
    REQUIRE(equal(begin(expected_key), end(expected_key), key.begin()));
}
