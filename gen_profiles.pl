#!/usr/bin/perl -w
# Copyright 2019  Ronald Landheer-Cieslak
#
# Licensed under the Apache License, Version 2.0 (the "License"); 
# you may not use this file except in compliance with the License. 
# You may obtain a copy of the License at 
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software 
# distributed under the License is distributed on an "AS IS" BASIS, 
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
# See the License for the specific language governing permissions and 
# limitations under the License.
use strict;
use warnings;

for my $OPTION_IGNORE_OUTSTATION_SEQ_ON_REQUEST_SESSION_INITIATION   (0, 1) {
for my $OPTION_MASTER_SETS_KWA_AND_MAL                               (0, 1) {
for my $OPTION_DNP_AUTHORITY_SETS_PERMISSIBLE_KWA_AND_MAL_ALGORITHMS (0, 1) {
for my $OPTION_INCLUDE_BROADCAST_KEY                                 (0, 1) {
	my $binary
		= $OPTION_IGNORE_OUTSTATION_SEQ_ON_REQUEST_SESSION_INITIATION
		. $OPTION_MASTER_SETS_KWA_AND_MAL
		. $OPTION_DNP_AUTHORITY_SETS_PERMISSIBLE_KWA_AND_MAL_ALGORITHMS
		. $OPTION_INCLUDE_BROADCAST_KEY
		. $OPTION_INCLUDE_ASSOCIATION_ID_IN_SESSION_MESSAGES
		;
	my $filename = "profile-" . unpack("N", pack("B32", substr("0" x 32 . $binary, -32))) . ".hpp";
	
	unless(open FILE, '>'.$filename) {
		die "\nUnable to create $filename\n";
	}

	print FILE <<EOF
#ifndef DNP3SAV6_PROFILE_HPP_INCLUDED
#define DNP3SAV6_PROFILE_HPP_INCLUDED 1

#define OPTION_IGNORE_OUTSTATION_SEQ_ON_REQUEST_SESSION_INITIATION $OPTION_IGNORE_OUTSTATION_SEQ_ON_REQUEST_SESSION_INITIATION
#define OPTION_DNP_AUTHORITY_SETS_PERMISSIBLE_KWA_AND_MAL_ALGORITHMS $OPTION_DNP_AUTHORITY_SETS_PERMISSIBLE_KWA_AND_MAL_ALGORITHMS
#define OPTION_INCLUDE_BROADCAST_KEY $OPTION_INCLUDE_BROADCAST_KEY

#endif
EOF

}}}}

