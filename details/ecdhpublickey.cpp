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
#include "ecdhpublickey.hpp"

ASN1_SEQUENCE(AlgorithmIdentifier) = {
    ASN1_SIMPLE(AlgorithmIdentifier, algorithm, ASN1_OBJECT),
    ASN1_OPT(AlgorithmIdentifier, parameters, ECPARAMETERS)
} ASN1_SEQUENCE_END(AlgorithmIdentifier);
IMPLEMENT_ASN1_FUNCTIONS(AlgorithmIdentifier);

ASN1_SEQUENCE(ECDHPublicKey) = {
    ASN1_SIMPLE(ECDHPublicKey, algorithm, AlgorithmIdentifier),
    ASN1_SIMPLE(ECDHPublicKey, publicKey, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(ECDHPublicKey);
IMPLEMENT_ASN1_FUNCTIONS(ECDHPublicKey);

