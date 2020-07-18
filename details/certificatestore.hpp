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
#ifndef dnp3sav6_details_certificatestore_hpp
#define dnp3sav6_details_certificatestore_hpp

#include "icertificatestore.hpp"
#include <vector>
#include <memory>

namespace DNP3SAv6 { namespace Details {
	class CertificateStore : public ICertificateStore
	{
	public :
        CertificateStore() = default;
		virtual ~CertificateStore() = default;

        CertificateStore(ICertificateStore const&) = delete;
		CertificateStore(ICertificateStore &&other) = delete;
		CertificateStore& operator=(ICertificateStore const&) = delete;
		CertificateStore& operator=(ICertificateStore &&other) = delete;

        /*virtual */size_t count() const override/* = 0*/;
        /*virtual */void add(Certificate const &certificate) override/* = 0*/;
        /*virtual */void remove(DistinguishedName const &name) override/* = 0*/;
        /*virtual */void remove(std::string const &name) override/* = 0*/;
        /*virtual */bool verify(Certificate const &certificate) const override/* = 0*/;

		/*virtual */std::vector< unsigned char > encode(Details::DistinguishedName const &certificate_name, bool encode_chain) const/* = 0*/;

	private :
        typedef std::vector< Certificate > Certificates;

		Certificates::const_iterator find(DistinguishedName const &name) const;
		Certificates::iterator find(DistinguishedName const &name);

        Certificates certificates_;
	};
}}

#endif
