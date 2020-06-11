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
#include "distinguishednameparser.hpp"
#include <boost/spirit/home/qi.hpp>

namespace qi = boost::spirit::qi;

namespace DNP3SAv6 { namespace Details { 
// the grammar for the subject is /type0=value0/type1=value1/..., so, in BNF:
// subject-distinguished-name ::= subject-distinguished-name-element+
// subject-distinguished-name-element ::= '/' type-name '=' value
// type-name ::= escaped-string
// value ::= escaped-string
// escaped-string ::= ([^/=] | escaped-character)+
// escaped-character ::= (('\' '/') | ('\' '=') | ('\' '\'))
template < typename Iterator >
struct DistinguishedNameElementParser : qi::grammar< Iterator, DistinguishedName::Element() >
{
    DistinguishedNameElementParser()
        : DistinguishedNameElementParser::base_type(start_)
    {
        using qi::char_;
        using qi::lexeme;
        using qi::debug;

        start_ %= type_ >> '=' >> value_;

        escaped_character_ = '\\' >> char_("\\/=");
        escaped_string_ = lexeme [ +(~char_("\\/=") | escaped_character_) ];
        value_ = escaped_string_;
        type_ = escaped_string_;

        //debug(escaped_character_);
        //debug(escaped_string_);
        //debug(value_);
        //debug(type_);
        //debug(start_);
    }

    qi::rule< Iterator, char() > escaped_character_;
    qi::rule< Iterator, std::string() > escaped_string_;
    qi::rule< Iterator, std::string() > value_;
    qi::rule< Iterator, std::string() > type_;
    qi::rule< Iterator, DistinguishedName::Element() > start_;
};

template < typename Iterator >
struct DistinguishedNameParser : qi::grammar< Iterator, DistinguishedName() >
{
    DistinguishedNameParser()
        : DistinguishedNameParser::base_type(start_)
    {
        using qi::debug;

        start_ %= elements_;
        elements_ = +( '/' >> element_ );

        //debug(start_);
        //debug(elements_);
    }

    DistinguishedNameElementParser< Iterator > element_;
    qi::rule< Iterator, std::vector< DistinguishedName::Element >() > elements_;
    qi::rule< Iterator, DistinguishedName() > start_;
};

std::pair< DistinguishedName, bool > parse(std::string const &subject_distinguished_name)
{
    typedef std::string::const_iterator Iterator;

    DistinguishedNameParser< Iterator > g;
    DistinguishedName distinguished_name;
    Iterator iter(subject_distinguished_name.begin());
    bool result(parse(iter, subject_distinguished_name.end(), g, distinguished_name));

    return std::make_pair(distinguished_name, result);
}
}}

BOOST_FUSION_ADAPT_STRUCT(
    DNP3SAv6::Details::DistinguishedName::Element,
    (std::string, type_)
    (std::string, value_)
    )
BOOST_FUSION_ADAPT_STRUCT(
    DNP3SAv6::Details::DistinguishedName,
    (std::vector< DNP3SAv6::Details::DistinguishedName::Element >, elements_)
    )



