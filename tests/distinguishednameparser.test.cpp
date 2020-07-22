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
#include "../details/distinguishednameparser.hpp"

using namespace DNP3SAv6::Details;

TEST_CASE( "Distinguished name parser (1)", "[distinguishednameparser]" ) {
    auto parse_result(parse(""));
    REQUIRE(!parse_result.second);
}

TEST_CASE( "Distinguished name parser (2)", "[distinguishednameparser]" ) {
    auto parse_result(parse("/CN=Device name"));
    REQUIRE(parse_result.second);
    REQUIRE(parse_result.first.elements_.size() == 1);
    REQUIRE(parse_result.first.elements_[0].type_ == "CN");
    REQUIRE(parse_result.first.elements_[0].value_ == "Device name");
}

TEST_CASE( "Distinguished name parser (3)", "[distinguishednameparser]" ) {
    auto parse_result(parse("/CN=Device name/Potato=Potato"));
    REQUIRE(parse_result.second);
    REQUIRE(parse_result.first.elements_.size() == 2);
    REQUIRE(parse_result.first.elements_[0].type_ == "CN");
    REQUIRE(parse_result.first.elements_[0].value_ == "Device name");
    REQUIRE(parse_result.first.elements_[1].type_ == "Potato");
    REQUIRE(parse_result.first.elements_[1].value_ == "Potato");
}
