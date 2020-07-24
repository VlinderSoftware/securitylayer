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
#include "associationbuilder.hpp"
#include "exceptions/contract.hpp"

namespace DNP3SAv6 {
AssociationBuilder::AssociationBuilder()
{ /* no-op (for now) */ }

void AssociationBuilder::reset() noexcept
{
    *this = AssociationBuilder();
}

std::uint32_t AssociationBuilder::getSEQ() const noexcept
{
    return seq_;
}

void AssociationBuilder::setSEQ(std::uint32_t seq) noexcept
{
    seq_ = seq;
}
void AssociationBuilder::setAssociationRequest(boost::asio::const_buffer const& association_request)
{
    pre_condition(association_request.size() <= sizeof(association_request_message_));
    memcpy(association_request_message_, association_request.data(), association_request.size());
    association_request_message_size_ = association_request.size();
}
boost::asio::const_buffer AssociationBuilder::getAssociationRequest() const
{
    return boost::asio::const_buffer(association_request_message_, association_request_message_size_);
}
void AssociationBuilder::setAssociationResponse(boost::asio::const_buffer const& association_response)
{
    pre_condition(association_response.size() <= sizeof(association_response_message_));
    memcpy(association_response_message_, association_response.data(), association_response.size());
    association_response_message_size_ = association_response.size();
}
boost::asio::const_buffer AssociationBuilder::getAssociationResponse() const
{
    return boost::asio::const_buffer(association_response_message_, association_response_message_size_);
}
void AssociationBuilder::setOutstationCertificate(boost::asio::const_buffer const &incoming_outstation_certificate)
{
    //TODO parse!
}
void AssociationBuilder::setOutstationRandomData(boost::asio::const_buffer const& incoming_outstation_random_data)
{
    pre_condition(incoming_outstation_random_data.size() <= sizeof(outstation_random_data_));
    memcpy(outstation_random_data_, incoming_outstation_random_data.data(), incoming_outstation_random_data.size());
    outstation_random_data_size_ = incoming_outstation_random_data.size();
}
}

