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
#ifndef dnp3sav6_associationbuilder_hpp
#define dnp3sav6_associationbuilder_hpp

#include <cstdint>
#include <boost/asio.hpp>
#include "config.hpp"

static_assert(DNP3SAV6_PROFILE_HPP_INCLUDED, "profile.hpp should be pre-included in CMakeLists.txt");

namespace DNP3SAv6 {
class AssociationBuilder
{
public :
	AssociationBuilder();
	~AssociationBuilder() = default;
	
	AssociationBuilder(AssociationBuilder &&other) noexcept = default;
	AssociationBuilder& operator=(AssociationBuilder &&other) noexcept = default;
	AssociationBuilder(AssociationBuilder const&) = delete;
	AssociationBuilder& operator=(AssociationBuilder const&) = delete;

	void reset() noexcept;

    std::uint32_t getSEQ() const noexcept;
    void setSEQ(std::uint32_t seq) noexcept;

	void setAssociationRequest(boost::asio::const_buffer const &association_request);
	boost::asio::const_buffer getAssociationRequest() const;
	void setAssociationResponse(boost::asio::const_buffer const &association_request);
	boost::asio::const_buffer getAssociationResponse() const;

	void setOutstationCertificate(boost::asio::const_buffer const &incoming_outstation_certificate);
	void setOutstationRandomData(boost::asio::const_buffer const &incoming_outstation_random_data);

private :
	std::uint32_t seq_ = 0;

	unsigned char association_request_message_[Config::max_spdu_size__];
	unsigned int association_request_message_size_ = 0;
	unsigned char association_response_message_[Config::max_spdu_size__];
	unsigned int association_response_message_size_ = 0;
	unsigned char master_random_data_[Config::max_nonce_size__];
	unsigned int master_random_data_size_ = 0;
	unsigned char outstation_random_data_[Config::max_nonce_size__];
	unsigned int outstation_random_data_size_ = 0;
};
}

#endif
