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
#include "certificatestorestub.hpp"

namespace DNP3SAv6 { namespace Tests {
/*virtual */size_t CertificateStoreStub::count() const/* = 0*/
{
    return 0;
}
/*virtual */void CertificateStoreStub::add(Details::Certificate const &certificate)/* = 0*/
{
}
/*virtual */void CertificateStoreStub::remove(Details::DistinguishedName const &name)/* = 0*/
{
}
/*virtual */bool CertificateStoreStub::verify(Details::Certificate const &certificate) const/* = 0*/
{
    return false;
}
/*virtual */std::vector< unsigned char > CertificateStoreStub::encode(Details::DistinguishedName const &certificate_name, bool encode_chain) const/* = 0*/
{
    return encoded_certificates_;
}

void CertificateStoreStub::setEncodedCertificates(std::vector< unsigned char > const &encoded_certificates)
{
    encoded_certificates_ = encoded_certificates;
}
}}
