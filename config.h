// TO DISCUSS: the sequence number from the Outstation is basically ignored in the
//             RequestSessionInitiation message. The alternative is that we use the
//             sequence number from the Outstation if it's greater than the sequence
//             number the Master is using when the RequestSessionInitiation message
//             arrives
#define OPTION_IGNORE_OUTSTATION_SEQ_ON_REQUEST_SESSION_INITIATION
// TO DISCUSS: SAv5 has the Outstation determine the key-wrap algorithm and the 
//             MAC algorithm, whereas my strawman proposal moves that responsibility
//             to the Master. The reasoning for moving it to the Master is that the
//             Master is more likely to know the user's intent, although the Outstation
//             is likely more difficult to update.
//             If the Outstation sets the KWA and MAL, the Master can refuse to start
//             the session if the KWA or MAL are inadequate. Alternatively, we could
//             use one of the SessionStartRequest message flags to indicate 
//             alternatives are available, so we could have the Master send a "hint" 
//             and have the Outstation decide whether it agrees with the hint.
#define OPTION_MASTER_SETS_KWA_AND_MAL
#define OPTION_MASTER_KWA_AND_MAL_ARE_HINTS
// TO DISCUSS: sending the session key status at the end of the key exchange doesn't make
//             much sense: it's always going to be OK. So, what are the cases going to be
//             that you'd want to get a KeyStatus message from the Outstation? If it's
//             anything other than OK, there's no way to authenticate the message, so
//             you won't be able to take any decisions based on it if those decisions 
//             change any state.
//             At the end of the session key exchange, a SessionKeyChangeConfirmation 
//             message, which would basically be a MAC of the header calculated with the
//             monitoring direction session key, should be enough.
#define OPTION_REMOVE_KEY_STATUS_MESSAGE