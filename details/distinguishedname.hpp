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
#ifndef dnp3sav6_details_distinguishedname_hpp
#define dnp3sav6_details_distinguishedname_hpp

#include <string>
#include <vector>
#include <ostream>

namespace DNP3SAv6 { namespace Details { 
struct DistinguishedName
{
    struct Element
    {
        Element() = default;
        Element(std::string const &type, std::string const &value)
            : type_(type)
            , value_(value)
        { /* no-op */ }

        std::string type_;
        std::string value_;
    };
    std::vector< Element > elements_;
};
bool operator==(DistinguishedName const &lhs, DistinguishedName const &rhs);
bool operator!=(DistinguishedName const &lhs, DistinguishedName const &rhs);
bool operator<(DistinguishedName const &lhs, DistinguishedName const &rhs);
bool operator<=(DistinguishedName const &lhs, DistinguishedName const &rhs);
bool operator>(DistinguishedName const &lhs, DistinguishedName const &rhs);
bool operator>=(DistinguishedName const &lhs, DistinguishedName const &rhs);
}}
namespace std {
ostream& operator<<(ostream &os, DNP3SAv6::Details::DistinguishedName const &dn);
}
#endif


