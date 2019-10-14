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
#define OPTION_MASTER_SETS_KWA_AND_MAL 1	/* This is what the SATF decided on 2019-05-24 */
#define OPTION_MASTER_KWA_AND_MAL_ARE_HINTS 1	/* This is what the SATF decided on 2019-05-24 */
// DISCUSSION: As discussed on the 2019-05-24 SATF telecon, the Master can iterate through
//             available algorithms if the Outstation does not support the suggested algorithms.
#define OPTION_ITERATE_KWA_AND_MAL 1
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
// REJECTED BY DNP: My initial strawman proposal from 2017 contained an association ID in the 
//             SessionStartRequest and SessionStartResponse messages. This ID made it into the
//             IEC TC57 WG15 working document presented by Marco Grechi at the San Francisco 
//             meeting in May 2019, but had since been removed from DNP3 by means of 
//             TB2019-001, in which multi-user support was deprecated, the Master-Outstation 
//             Association was defined and the association ID was thus no longer necessary.
//             The Association ID was intended to be an identifier for use by the Master and 
//             Outstation to allow them to choose which Update Key should be used for 
//             autentication. When provided by the Master, it could never be more than a hint 
//             because the value of the identifier was owned by the Outstation and not 
//             guaranteed to be constant and/or non-volatile. In any case, it was a numeric value.
//             In recent (time of writing: June 2019 discussions in the DNP Cybersecurity and Secure 
//             Authentication Task Force, the Master-Outstation Association is uniquely identified 
//             by a system-wide unique name, but that name does not need to be communicated because, 
//             over the link, the identifying information as described in TB2019-001 is sufficient.
// =========== This code does not implement this option
#undef OPTION_INCLUDE_ASSOCIATION_ID_IN_SESSION_MESSAGES

#endif