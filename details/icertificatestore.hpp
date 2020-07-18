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
#ifndef dnp3sav6_details_icertificatestore_hpp
#define dnp3sav6_details_icertificatestore_hpp

#include "distinguishedname.hpp"

namespace DNP3SAv6 { namespace Details {
    class Certificate;
	class ICertificateStore
	{
	public :
        ICertificateStore() = default;
		virtual ~ICertificateStore() = default;

        ICertificateStore(ICertificateStore const&) = delete;
		ICertificateStore(ICertificateStore &&other) = delete;
		ICertificateStore& operator=(ICertificateStore const&) = delete;
		ICertificateStore& operator=(ICertificateStore &&other) = delete;

        virtual size_t count() const = 0;
        virtual void add(Certificate const &certificate) = 0;
        virtual void remove(std::string const &name);
        virtual void remove(DistinguishedName const &name) = 0;
        virtual bool verify(Certificate const &certificate) const = 0;

		virtual std::vector< unsigned char > encode(DistinguishedName const &certificate_name, bool encode_chain) const = 0;

	private :
	};
}}

#endif
