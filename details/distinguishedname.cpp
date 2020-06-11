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
#include "distinguishedname.hpp"
#include <sstream>

using namespace std;

namespace DNP3SAv6 { namespace Details { 
namespace {
    int compare(DistinguishedName const &lhs, DistinguishedName const &rhs)
    {
        stringstream lhs_ss;
        lhs_ss << lhs;
        stringstream rhs_ss;
        rhs_ss << rhs;
        return lhs_ss.str().compare(rhs_ss.str());
    }
}
bool operator==(DistinguishedName const &lhs, DistinguishedName const &rhs) { return compare(lhs, rhs) == 0; }
bool operator!=(DistinguishedName const &lhs, DistinguishedName const &rhs) { return compare(lhs, rhs) != 0; }
bool operator< (DistinguishedName const &lhs, DistinguishedName const &rhs) { return compare(lhs, rhs) <  0; }
bool operator<=(DistinguishedName const &lhs, DistinguishedName const &rhs) { return compare(lhs, rhs) <= 0; }
bool operator> (DistinguishedName const &lhs, DistinguishedName const &rhs) { return compare(lhs, rhs) >  0; }
bool operator>=(DistinguishedName const &lhs, DistinguishedName const &rhs) { return compare(lhs, rhs) >= 0; }
}}
namespace std {
ostream& operator<<(ostream &os, DNP3SAv6::Details::DistinguishedName const &dn)
{
    for (auto element : dn.elements_)
    {
        os << '/' << element.type_ << '=' << element.value_;
    }
    return os;
}
}



