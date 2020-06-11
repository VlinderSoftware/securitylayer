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
#ifndef dnp3sav6_details_constants_hpp
#define dnp3sav6_details_constants_hpp

// NOTE: as there is no consensus within the SATF at the moment to (2020-04-18) encode these ECDH public keys as X.509 extensions, we're using 
//       a Vlinder Software OID to encode it.
// DNP3 SAv6 ECDH key { iso(1) org(3) dod(6) internet(1) private(4) enterprise(1) vlinder-software(49974) security(0) protocols(0) dnp3-secure-authentication(2) version(6) ecdh-key(0) }
#define DNP3_ECDH_EXTENSION_OID "1.3.6.1.4.1.49974.0.0.2.6.0"

#endif
