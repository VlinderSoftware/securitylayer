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
#include "updatekeystorestub.hpp"

using namespace boost::asio;

namespace DNP3SAv6 { namespace Tests {
/*virtual */const_buffer UpdateKeyStoreStub::getUpdateKey(Details::MasterOutstationAssociationName const &master_outstation_association_name) const/* override = 0*/
{
	if (master_outstation_association_name.association_id_ == 1)
	{
		static unsigned char const update_key__[] = {
			  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
			, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
			};
		return const_buffer(update_key__, sizeof(update_key__));
	}
	else
	{
		return const_buffer();
	}
}
}}
