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
#ifndef dnp3sav6_outstation_hpp
#define dnp3sav6_outstation_hpp

static_assert(DNP3SAV6_PROFILE_HPP_INCLUDED, "profile.hpp should be pre-included in CMakeLists.txt");

#include "securitylayer.hpp"
#include "keywrapalgorithm.hpp"
#include "aeadalgorithm.hpp"
#include "sessionbuilder.hpp"

namespace DNP3SAv6 {
class Outstation : public SecurityLayer
{
public :
	Outstation(
		  boost::asio::io_context &io_context
        , std::uint16_t association_id
		, Config config
		, Details::IRandomNumberGenerator &random_number_generator
		);
	virtual ~Outstation() = default;
	
	Outstation(Outstation &&other) noexcept = default;
	Outstation& operator=(Outstation &&other) noexcept = default;
	Outstation(Outstation const&) = delete;
	Outstation& operator=(Outstation const&) = delete;

protected :
    virtual Details::Direction getIncomingDirection() const noexcept override { return Details::Direction::control__; };

	virtual void reset() noexcept override;
	virtual void onPostAPDU(boost::asio::const_buffer const &apdu) noexcept override;

	virtual void rxSessionStartRequest(std::uint32_t incoming_seq, Messages::SessionStartRequest const &incoming_ssr, boost::asio::const_buffer const &spdu) noexcept override;
    virtual void rxSessionKeyChangeRequest(std::uint32_t incoming_seq, Messages::SessionKeyChangeRequest const& incoming_skcr, boost::asio::const_buffer const& incoming_key_wrap_data, boost::asio::const_buffer const& spdu) noexcept override;

private :
	void sendSessionInitiation() noexcept;

	unsigned char buffer_[Config::max_spdu_size__];
	unsigned char nonce_[Config::max_nonce_size__];
	SessionBuilder session_builder_;
};
}

#endif



