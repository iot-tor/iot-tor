#pragma once

/** Cell commands (unsigned int = 4 bytes in link protocol 4+ or 2 bytes in link protocol version 3-) */
enum cell_command_t : unsigned int {
  // Fixed size cells commands

  PADDING = 0 ,				// PADDING     (Padding)                 (See Sec 7.2)
  CREATE = 1 ,				// CREATE      (Create a circuit)        (See Sec 5.1)
  CREATED = 2 , 				// CREATED     (Acknowledge create)      (See Sec 5.1)
  RELAY = 3 , 				// RELAY       (End-to-end data)         (See Sec 5.5 and 6)
  DESTROY = 4 , 				// DESTROY     (Stop using a circuit)    (See Sec 5.4)
  CREATE_FAST = 5 , 			// CREATE_FAST (Create a circuit, no PK) (See Sec 5.1)
  CREATED_FAST = 6 , 			// CREATED_FAST (Circuit created, no PK) (See Sec 5.1)
  NETINFO = 8 , 				// NETINFO     (Time and address info)   (See Sec 4.5)
  RELAY_EARLY = 9 , 			// RELAY_EARLY (End-to-end data; limited)(See Sec 5.6)
  CREATE2 = 10 , 				// CREATE2    (Extended CREATE cell)    (See Sec 5.1)
  CREATED2 = 11 , 			// CREATED2   (Extended CREATED cell)    (See Sec 5.1)
  PADDING_NEGOTIATE = 12 , 	// PADDING_NEGOTIATE   (Padding negotiation)    (See Sec 7.2)


  
  // Variable-length command values are:
  VERSIONS = 7 , 				// VERSIONS    (Negotiate proto version) (See Sec 4)
  VPADDING = 128 , 			// VPADDING  (Variable-length padding) (See Sec 7.2)
  CERTS = 129 , 				// CERTS     (Certificates)            (See Sec 4.2)
  AUTH_CHALLENGE = 130 , 		// AUTH_CHALLENGE (Challenge value)    (See Sec 4.3)
  AUTHENTICATE = 131 , 		// AUTHENTICATE (Client authentication)(See Sec 4.5)
  AUTHORIZE = 132  			// AUTHORIZE (Client authorization)    (Not yet used)
};

const char *cell_command_str(const cell_command_t& command) {
  if (command==cell_command_t::PADDING) return "PADDING";
  if (command==cell_command_t::CREATE) return "CREATE";
  if (command==cell_command_t::CREATED) return "CREATED";
  if (command==cell_command_t::RELAY) return "RELAY";
  if (command==cell_command_t::DESTROY) return "DESTROY";
  if (command==cell_command_t::CREATE_FAST) return "CREATE_FAST";
  if (command==cell_command_t::CREATED_FAST) return "CREATED_FAST";
  if (command==cell_command_t::NETINFO) return "NETINFO";
  if (command==cell_command_t::RELAY_EARLY) return "RELAY_EARLY";
  if (command==cell_command_t::CREATE2) return "CREATE2";
  if (command==cell_command_t::CREATED2) return "CREATED2";
  if (command==cell_command_t::PADDING_NEGOTIATE) return "PADDING_NEGOTIATE";
  if (command==cell_command_t::VERSIONS) return "VERSIONS";
  if (command==cell_command_t::VPADDING) return "VPADDING";
  if (command==cell_command_t::CERTS) return "CERTS";
  if (command==cell_command_t::AUTH_CHALLENGE) return "AUTH_CHALLENGE";
  if (command==cell_command_t::AUTHENTICATE) return "AUTHENTICATE";
  if (command==cell_command_t::AUTHORIZE) return "AUTHORIZE";

  return "UNKNOWN";
}





/** Circuit destroy reason (or RELAY_TRUNCATED reason) */
enum destroy_reason_t : unsigned char {
  NONE = 0, 				// -- NONE            (No reason given.)
  PROTOCOL = 1, 			// -- PROTOCOL        (Tor protocol violation.)
  INTERNAL = 2, 			// -- INTERNAL        (Internal error.)
  REQUESTED = 3, 			// -- REQUESTED       (A client sent a TRUNCATE command.)
  HIBERNATING = 4, 		// -- HIBERNATING     (Not currently operating; trying to save bandwidth.)
  RESOURCELIMIT = 5, 		// -- RESOURCELIMIT   (Out of memory, sockets, or circuit IDs.)
  CONNECTFAILED = 6, 		// -- CONNECTFAILED   (Unable to reach relay.)
  OR_IDENTITY = 7, 		// -- OR_IDENTITY     (Connected to relay, but its OR identity was not as expected.)
  CHANNEL_CLOSED = 8, 	// -- CHANNEL_CLOSED  (The OR connection that was carrying this circuit died.)
  FINISHED = 9, 			// -- FINISHED        (The circuit has expired for being dirty or old.)
  TIMEOUT = 10, 			// -- TIMEOUT         (Circuit construction took too long)
  DESTROYED = 11, 		// -- DESTROYED       (The circuit was destroyed w/o client TRUNCATE)
  NOSUCHSERVICE = 12, 	// -- NOSUCHSERVICE   (Request for unknown hidden service)
};


const char *relay_truncated_reason_str(const destroy_reason_t& reason) {
  if (reason==destroy_reason_t::CHANNEL_CLOSED) return "CHANNEL_CLOSED";
  if (reason==destroy_reason_t::CONNECTFAILED) return "CONNECTFAILED";
  if (reason==destroy_reason_t::DESTROYED) return "DESTROYED";
  if (reason==destroy_reason_t::FINISHED) return "FINISHED";
  if (reason==destroy_reason_t::HIBERNATING) return "HIBERNATING";
  if (reason==destroy_reason_t::INTERNAL) return "INTERNAL";
  if (reason==destroy_reason_t::NONE) return "NONE";
  if (reason==destroy_reason_t::NOSUCHSERVICE) return "NOSUCHSERVICE";
  if (reason==destroy_reason_t::OR_IDENTITY) return "OR_IDENTITY";
  if (reason==destroy_reason_t::PROTOCOL) return "PROTOCOL";
  if (reason==destroy_reason_t::REQUESTED) return "REQUESTED";
  if (reason==destroy_reason_t::RESOURCELIMIT) return "RESOURCELIMIT";
  if (reason==destroy_reason_t::TIMEOUT) return "TIMEOUT";

  return "UNKNOWN";
}

/** RELAY Cell commands */
enum cell_relay_command_t : unsigned char {
  RELAY_BEGIN = 1, 		// 1 -- RELAY_BEGIN     [forward]
  RELAY_DATA = 2, 		// 2 -- RELAY_DATA      [forward or backward]
  RELAY_END = 3, 			// 3 -- RELAY_END       [forward or backward]
  RELAY_CONNECTED = 4, 	// 4 -- RELAY_CONNECTED [backward]
  RELAY_SENDME = 5, 		// 5 -- RELAY_SENDME    [forward or backward] [sometimes control]
  RELAY_EXTEND = 6, 		// 6 -- RELAY_EXTEND    [forward]             [control]
  RELAY_EXTENDED = 7, 	// 7 -- RELAY_EXTENDED  [backward]            [control]
  RELAY_TRUNCATE = 8, 	// 8 -- RELAY_TRUNCATE  [forward]             [control]
  RELAY_TRUNCATED = 9, 	// 9 -- RELAY_TRUNCATED [backward]            [control]
  RELAY_DROP = 10, 		// 10 -- RELAY_DROP      [forward or backward] [control]
  RELAY_RESOLVE = 11, 	// 11 -- RELAY_RESOLVE   [forward]
  RELAY_RESOLVED = 12, 	// 12 -- RELAY_RESOLVED  [backward]
  RELAY_BEGIN_DIR = 13, 	// 13 -- RELAY_BEGIN_DIR [forward]
  RELAY_EXTEND2 = 14, 	// 14 -- RELAY_EXTEND2   [forward]             [control]
  RELAY_EXTENDED2 = 15, 	// 15 -- RELAY_EXTENDED2 [backward]            [control]

  // 32..40 -- Used for hidden services; see rend-spec-{v2,v3}.txt.

  RELAY_COMMAND_ESTABLISH_INTRO =32,
  // Sent from hidden service host to introduction point;
  // establishes introduction point. Discussed in
  // [REG_INTRO_POINT].
  RELAY_COMMAND_ESTABLISH_RENDEZVOUS=33,
  // Sent from client to rendezvous point; creates rendezvous
  // point. Discussed in [EST_REND_POINT].
  RELAY_COMMAND_INTRODUCE1=34,
  // Sent from client to introduction point; requests
  // introduction. Discussed in [SEND_INTRO1]
  RELAY_COMMAND_INTRODUCE2=35,
  // Sent from introduction point to hidden service host; requests
  // introduction. Same format as INTRODUCE1. Discussed in
  // [FMT_INTRO1] and [PROCESS_INTRO2]
  RELAY_COMMAND_RENDEZVOUS1=36,
  // Sent from hidden service host to rendezvous point;
  // attempts to join host's circuit to
  // client's circuit. Discussed in [JOIN_REND]
  RELAY_COMMAND_RENDEZVOUS2=37,
  // Sent from rendezvous point to client;
  // reports join of host's circuit to
  // client's circuit. Discussed in [JOIN_REND]
  RELAY_COMMAND_INTRO_ESTABLISHED=38,
  // Sent from introduction point to hidden service host;
  // reports status of attempt to establish introduction
  // point. Discussed in [INTRO_ESTABLISHED]
  RELAY_COMMAND_RENDEZVOUS_ESTABLISHED=39,
  // Sent from rendezvous point to client; acknowledges
  // receipt of ESTABLISH_RENDEZVOUS cell. Discussed in
  // [EST_REND_POINT]
  RELAY_COMMAND_INTRODUCE_ACK=40,
  // Sent from introduction point to client; acknowledges
  // receipt of INTRODUCE1 cell and reports success/failure.
  // Discussed in [INTRO_ACK]
  
  
  // 41..42 -- Used for circuit padding; see Section 3 of padding-spec.txt.
};        

const char *relay_cell_command_str(const cell_relay_command_t& command) {
  if (command==cell_relay_command_t::RELAY_BEGIN) return "RELAY_BEGIN";
  if (command==cell_relay_command_t::RELAY_BEGIN_DIR) return "RELAY_BEGIN_DIR";
  if (command==cell_relay_command_t::RELAY_CONNECTED) return "RELAY_CONNECTED";
  if (command==cell_relay_command_t::RELAY_DATA) return "RELAY_DATA";
  if (command==cell_relay_command_t::RELAY_DROP) return "RELAY_DROP";
  if (command==cell_relay_command_t::RELAY_END) return "RELAY_END";
  if (command==cell_relay_command_t::RELAY_EXTEND2) return "RELAY_EXTEND2";
  if (command==cell_relay_command_t::RELAY_EXTEND) return "RELAY_EXTEND";
  if (command==cell_relay_command_t::RELAY_EXTENDED2) return "RELAY_EXTENDED2";
  if (command==cell_relay_command_t::RELAY_EXTENDED) return "RELAY_EXTENDED";
  if (command==cell_relay_command_t::RELAY_RESOLVE) return "RELAY_RESOLVE";
  if (command==cell_relay_command_t::RELAY_RESOLVED) return "RELAY_RESOLVED";
  if (command==cell_relay_command_t::RELAY_SENDME) return "RELAY_SENDME";
  if (command==cell_relay_command_t::RELAY_TRUNCATE) return "RELAY_TRUNCATE";
  if (command==cell_relay_command_t::RELAY_TRUNCATED) return "RELAY_TRUNCATED";

  if (command==cell_relay_command_t::RELAY_COMMAND_ESTABLISH_INTRO) return "RELAY_COMMAND_ESTABLISH_INTRO";
  if (command==cell_relay_command_t::RELAY_COMMAND_ESTABLISH_RENDEZVOUS) return "RELAY_COMMAND_ESTABLISH_RENDEZVOUS";
  if (command==cell_relay_command_t::RELAY_COMMAND_INTRODUCE1) return "RELAY_COMMAND_INTRODUCE1";
  if (command==cell_relay_command_t::RELAY_COMMAND_INTRODUCE2) return "RELAY_COMMAND_INTRODUCE2";
  if (command==cell_relay_command_t::RELAY_COMMAND_RENDEZVOUS2) return "RELAY_COMMAND_RENDEZVOUS2";
  if (command==cell_relay_command_t::RELAY_COMMAND_INTRO_ESTABLISHED) return "RELAY_COMMAND_INTRO_ESTABLISHED";
  if (command==cell_relay_command_t::RELAY_COMMAND_RENDEZVOUS_ESTABLISHED) return "RELAY_COMMAND_RENDEZVOUS_ESTABLISHED";
  if (command==cell_relay_command_t::RELAY_COMMAND_INTRODUCE_ACK) return "RELAY_COMMAND_INTRODUCE_ACK";

  
  return "UNKNOWN";
}


/** Enums reasons for RELAY_END cells */
enum relay_end_reason_t : unsigned char {
  REASON_MISC = 1,
  REASON_RESOLVEFAILED = 2,
  REASON_CONNECTREFUSED = 3,
  REASON_EXITPOLICY = 4,
  REASON_DESTROY = 5,
  REASON_DONE = 6,
  REASON_TIMEOUT = 7,
  REASON_NOROUTE = 8,
  REASON_HIBERNATING = 9,
  REASON_INTERNAL = 10,
  REASON_RESOURCELIMIT = 11,
  REASON_CONNRESET = 12,
  REASON_TORPROTOCOL = 13,
  REASON_NOTDIRECTORY = 14
};


const char *relay_end_reason_str(const relay_end_reason_t& reason) {
  if (reason==relay_end_reason_t::REASON_MISC) return "REASON_MISC";
  if (reason==relay_end_reason_t::REASON_RESOLVEFAILED) return "REASON_RESOLVEFAILED";
  if (reason==relay_end_reason_t::REASON_CONNECTREFUSED) return "REASON_CONNECTREFUSED";
  if (reason==relay_end_reason_t::REASON_EXITPOLICY) return "REASON_EXITPOLICY";
  if (reason==relay_end_reason_t::REASON_DESTROY) return "REASON_DESTROY";
  if (reason==relay_end_reason_t::REASON_DONE) return "REASON_DONE";
  if (reason==relay_end_reason_t::REASON_TIMEOUT) return "REASON_TIMEOUT";
  if (reason==relay_end_reason_t::REASON_NOROUTE) return "REASON_NOROUTE";
  if (reason==relay_end_reason_t::REASON_HIBERNATING) return "REASON_HIBERNATING";
  if (reason==relay_end_reason_t::REASON_INTERNAL) return "REASON_INTERNAL";
  if (reason==relay_end_reason_t::REASON_RESOURCELIMIT) return "REASON_RESOURCELIMIT";
  if (reason==relay_end_reason_t::REASON_CONNRESET) return "REASON_CONNRESET";
  if (reason==relay_end_reason_t::REASON_TORPROTOCOL) return "REASON_TORPROTOCOL";
  if (reason==relay_end_reason_t::REASON_NOTDIRECTORY) return "REASON_NOTDIRECTORY";

  return "UNK";
}


