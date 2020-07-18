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
#ifndef dnp3sav6_details_opaque_hpp
#define dnp3sav6_details_opaque_hpp

namespace DNP3SAv6 { namespace Details { 
    class Opaque
    {
    public :
        Opaque(std::vector< unsigned char > const &data)
            : data_(data)
        { /* no-op */ }

    private :
        std::uint16_t length_;
        std::vector< unsigned char > data_;
        std::vector< unsigned char > encoding_;
    };

}}

#endif
