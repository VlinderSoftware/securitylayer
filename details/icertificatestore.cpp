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
#include "icertificatestore.hpp"
#include "distinguishednameparser.hpp"

namespace DNP3SAv6 { namespace Details {
/*virtual */void ICertificateStore::remove(std::string const &name)
{
    auto distinguished_name(parse(name));
    if (!distinguished_name.second)
    {
        throw "Failed to parse distinguished name";
    }
    else
    { /* all is well */ }
    remove(distinguished_name.first);
}
}}
