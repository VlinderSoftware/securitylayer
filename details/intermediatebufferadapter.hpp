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
#ifndef dnp3sav6_details_intermediatebufferadapter_hpp
#define dnp3sav6_details_intermediatebufferadapter_hpp

#include <boost/asio.hpp>

namespace DNP3SAv6 { namespace Details { 
/* This buffer inserts itself between an input and output as an output iterator, pushing the input into an output 
 * iterator through a buffer such that the buffer contains the last N bytes of the input buffer, that don't go 
 * into the output buffer */
class IntermediateBufferAdapter
{
public :
    IntermediateBufferAdapter(boost::asio::mutable_buffer buffer)
        : buffer_(buffer)
        , begin_(static_cast< unsigned char* >(buffer_.data()))
        , curr_(begin_)
        , end_(begin_ + buffer_.size())
    { /* no-op */ }

    ~IntermediateBufferAdapter()
    { /* no-op */ }

    IntermediateBufferAdapter(IntermediateBufferAdapter const &other) = delete;
    IntermediateBufferAdapter(IntermediateBufferAdapter &&other) = default;
    IntermediateBufferAdapter& operator=(IntermediateBufferAdapter const &other) = delete;
    IntermediateBufferAdapter& operator=(IntermediateBufferAdapter &&other) = default;

    size_t push(boost::asio::mutable_buffer out, boost::asio::const_buffer in);

private :
    boost::asio::mutable_buffer buffer_;
    unsigned char *begin_ = nullptr;
    unsigned char *curr_ = nullptr;
    unsigned char *end_ = nullptr;
};
}}

#endif
