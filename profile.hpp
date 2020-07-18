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
#ifndef DNP3SAV6_PROFILE_HPP_INCLUDED
#define DNP3SAV6_PROFILE_HPP_INCLUDED 1

// DISCUSSED:  the sequence number from the Outstation is basically ignored in the
//             RequestSessionInitiation message. The alternative is that we use the
//             sequence number from the Outstation if it's greater than the sequence
//             number the Master is using when the RequestSessionInitiation message
//             arrives
//             SATF decided to ignore the outstation sequence number for 
//             RequestSessionInitiation on 2019-05-24
#define OPTION_IGNORE_OUTSTATION_SEQ_ON_REQUEST_SESSION_INITIATION 1
// DISCUSSED:  SAv5 has the Outstation determine the key-wrap algorithm and the 
//             MAC algorithm, whereas my strawman proposal moves that responsibility
//             to the Master. The reasoning for moving it to the Master is that the
//             Master is more likely to know the user's intent, although the Outstation
//             is likely more difficult to update.
//             If the Outstation sets the KWA and MAL, the Master can refuse to start
//             the session if the KWA or MAL are inadequate. Alternatively, we could
//             use one of the SessionStartRequest message flags to indicate 
//             alternatives are available, so we could have the Master send a "hint" 
//             and have the Outstation decide whether it agrees with the hint.
//             The SATF decided the Master would provide the KWA and the MAL to the Outstation 
//             on 2019-05-24.
//             It was confirmed at the 2019-10-16 sync-up meeting between the SATF and WG15
//             It was reaffirmed at the SATF meeting at the same date
#define OPTION_MASTER_SETS_KWA_AND_MAL 1
// DISCUSSED:  Making the KWA and the MAL provided  by the Master hints allows the Outstation
//             to decide, as it did in SAv5. With iteration, it also allows the algorithms to
//             be negotiated. 
//             This is what the SATF arrived at on 2019-05-24
//             WG15 disagreed. At the sync-up meeting on 2019-10-16, it was agreed that it is 
//             at least simpler for the Master to always decide.
//             At the SATF meeting on 2019-10-16, this was agreed to provided that the DNP 
//             Device Profile specify which algorithms are supported by the Outstation, and 
//             the Outstation shall return an error message if it receives a 
//             SessionStartRequest message that asks for an algorithm that is not supported 
//             by the Outstation.
#define OPTION_MASTER_KWA_AND_MAL_ARE_HINTS 0
#define OPTION_ITERATE_KWA_AND_MAL 0
// SUGGESTION: The DNP Authority should be able to set permissible algorithms
#define OPTION_DNP_AUTHORITY_SETS_PERMISSIBLE_KWA_AND_MAL_ALGORITHMS 1
// TO DISCUSS: The Master could send an extra Session key, for broadcast messages. If we allow 
//             this, it un-breaks broadcast for SA, but it also means that the Application Layer 
//             should be more careful with broadcast messages, as they could in theory come from 
//             any of the Outstations on the shared network (whatever the Master broadcasts to).
#define OPTION_INCLUDE_BROADCAST_KEY 1 //TODO
// TO DISCUSS: Broadcast messages could be done using asymmetric keys, as discussed by the SATF
//             on 2019-06-26.
#undef OPTION_IMPLEMENT_ASYMMETRIC_BROADCAST
// TO DISCUSS: 
#undef OPTION_PERMIT_NO_CERTIFICATE_IN_ASSOCIATION_RESPONSE

#define OPTION_MAX_SESSION_KEY_CHANGE_COUNT 32767

#endif
