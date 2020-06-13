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
#ifndef dnp3sav6_details_masteroutstationassociationname_hpp
#define dnp3sav6_details_masteroutstationassociationname_hpp

#include <string>

namespace DNP3SAv6 { namespace Details {
struct MasterOutstationAssociationName
{
    MasterOutstationAssociationName() = default;
    MasterOutstationAssociationName(
          std::string const &master_name
        , std::string const &outstation_name
        , std::uint16_t association_id
        )
        : master_name_(master_name)
        , outstation_name_(outstation_name)
        , association_id_(association_id)
    { /* no-op */ }

    virtual ~MasterOutstationAssociationName() = default;
    MasterOutstationAssociationName(MasterOutstationAssociationName const&) = default;
    MasterOutstationAssociationName(MasterOutstationAssociationName &&) = default;
    MasterOutstationAssociationName& operator=(MasterOutstationAssociationName const&) = default;
    MasterOutstationAssociationName& operator=(MasterOutstationAssociationName &&) = default;

    std::string master_name_;
    std::string outstation_name_;
    std::uint16_t association_id_ = 0;
};
}}

#endif
