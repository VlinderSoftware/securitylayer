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
#ifndef dnp3sav6_tests_updatekeystorestub_hpp
#define dnp3sav6_tests_updatekeystorestub_hpp

#include "../details/iupdatekeystore.hpp"

namespace DNP3SAv6 { namespace Tests {
class UpdateKeyStoreStub : public Details::IUpdateKeyStore
{
public :
	UpdateKeyStoreStub() = default;
	virtual ~UpdateKeyStoreStub() = default;

	UpdateKeyStoreStub(UpdateKeyStoreStub const&) = delete;
	UpdateKeyStoreStub& operator=(UpdateKeyStoreStub const&) = delete;
	UpdateKeyStoreStub(UpdateKeyStoreStub&&) = default;
	UpdateKeyStoreStub& operator=(UpdateKeyStoreStub&&) = default;

    /*virtual */boost::asio::const_buffer getUpdateKey(Details::MasterOutstationAssociationName const &master_outstation_association_name) const override/* = 0*/;

private :
};
}}

#endif


