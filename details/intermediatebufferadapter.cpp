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
#include "intermediatebufferadapter.hpp"
#include <algorithm>
#include "../exceptions/contract.hpp"

using namespace std;

namespace DNP3SAv6 { namespace Details { 
size_t IntermediateBufferAdapter::push(boost::asio::mutable_buffer out, boost::asio::const_buffer in)
{
    // if we already have data in the buffer, that should count toward our total input data
    // everything except the last N bytes of the input data should be forwarded to the output data
    // we return the amount of data we output

    size_t const data_in_buffer(distance(begin_, curr_));
    size_t const total_input_data_length(data_in_buffer + in.size());
    size_t const data_to_output(max(total_input_data_length, buffer_.size()) - buffer_.size());
    size_t remaining_to_output(data_to_output);

    unsigned char *const out_begin(static_cast< unsigned char* >(out.data()));
    unsigned char *out_curr(out_begin);
    unsigned char *const out_end(out_curr + out.size());
    unsigned char const *in_curr(static_cast< unsigned char const* >(in.data()));
    unsigned char const *const in_end(in_curr + in.size());

    size_t const data_in_buffer_to_output(min(data_in_buffer, remaining_to_output));
    remaining_to_output -= data_in_buffer_to_output;
    unsigned char *const end_of_data_in_buffer_to_output(begin_ + data_in_buffer_to_output);
    out_curr = copy(begin_, end_of_data_in_buffer_to_output, out_curr);
    curr_ = copy(end_of_data_in_buffer_to_output, curr_, begin_);

    assert(size_t(distance(out_curr, out_end)) >= remaining_to_output);
    out_curr = copy(in_curr, in_curr + remaining_to_output, out_curr);
    in_curr += remaining_to_output;

    assert(distance(in_curr, in_end) <= distance(curr_, end_));
    curr_ = copy(in_curr, in_end, curr_);

    return distance(out_begin, out_curr);
}
}}
