#pragma once
#include "dir.hpp"
#include "cell.hpp"
#include <map>
#include <list>
#include "defines.hpp"
#include <functional>

#define CONNECT_TIMEOUT 5000   //timeout in build circuit phase, in ms

enum cb_t {
  CB_NOTHING,

  CB_CIRCUIT_BUILT_FAIL,
  CB_CIRCUIT_BUILT_OK,

  CB_RELAY_BEGIN,
  CB_RELAY_END,

  CB_INTRO2,

  CB_DESTROY,
};

struct intro_material_t {
  unsigned char public_key[32]; //aka X
  unsigned char rdvc[20];
  info_node_t node;
  
  intro_keys_t *intro_keys=NULL;

  ~intro_material_t() {
    if(intro_keys)
      delete intro_keys;
  }
};



struct rdv_material_t {
  unsigned char rdvc[20]; //rendez vous cookie

  unsigned char private_key[32]; //x  
  unsigned char public_key[32]; //X = EXP([9],x)

  unsigned char B[32]; // encryption public key from introduction
  unsigned char AUTH_KEY[32]; 

  //generated keys for symetric cipher and digests
  unsigned char Df[32],Db[32],Kf[32],Kb[32];

  skin_ctx_t skin;
  
  void init_sym() {
    skin.init_v3(Df,Db,Kf,Kb);
  }

};


struct circuit_t {
#ifdef MEMDBG
  void * operator new(size_t size)
  {
    void * p = malloc(size);
    _mn[p]=size;
    printf("*** circuit_t::new %p size=%d\n",p,int(size));
    return p;
  }
    
  void operator delete(void * p)
  {
    auto size=_mn[p];
    printf("*** circuit_t::delete %p size=%d\n",p,int(size));
    memset(p,0x43,size);
    _mn.erase(p);
    //free(p);
  }
#endif
  
protected:
  short dbg_=DBGBASE;
  sockcell_t sock;

  void log(const char *file,const char *fn,int line,int lvl, const char* format, ... )
  {
    if(lvl>dbg_) return;
    va_list arglist;
    
    printf("[%s][circuit %p :: %s:%d ][cid:%x] ",loglvlstr[lvl],this,fn,line,circuit_id);
    va_start( arglist, format );
    vprintf( format, arglist );
    va_end( arglist );
  }

  string name="noname";

public:

  int Nnodes=3;
  vector<relay_t*> nodes;
  bool firstconnection=0;
  
protected:
  unsigned short link_protocol_version; 	// the version of this circuit
  unsigned int circuit_id;					// the circuit_id of this circuit

  short window;				// the current (backward) circuit window. Each 100 RELAY_DATA cells are exchanged a RELAY_SENDME is needed
  short window_out;				// the forward circuit window

  vector<unsigned char> last_digest;	// the latest stream *sent* RELAY_DATA cell digest (used by RELAY_SENDME)

#ifndef NOTORCHECKS
  list<vector<unsigned char> > digests;
#endif
  
public:
  long long lastcell=0; //time of last rcv cell
  long long last_sent_padding=0;

  bool check_alive() {
    if(build_status==BS_FAIL || build_status==BS_DESTROYED|| build_status==BS_DESTROY) return 0;
    if(get_unix_time()-lastcell>120) {
      //if no cell in 2 minutes, suppose dead
      printf("circuit %x is silent: dead it\n",circuit_id);
      set_status(BS_DESTROY);
    }
    return build_status==BS_BUILT;
  }

  typedef std::function<void(cb_t)> callback_t;
  typedef std::function<void(const unsigned char *,int l)> stream_callback_t;
  
  callback_t ncb=NULL;

  void set_ncb(callback_t ncb_) {
    LOG_INFO("set callback %p\n",ncb_);
    cb_lock();
    ncb=ncb_;
    cb_unlock();
  }

  struct stream_t {
    short dbg_=DBGBASE;
    void log(const char *file,const char *fn,int line,int lvl, const char* format, ... )
    {
      if(lvl>dbg_) return;
      va_list arglist;
      
      printf("[%s][circuit %p stream %p :: %s:%d ][cid:%x][sid:%x] ",loglvlstr[lvl],circuit,this,fn,line,circuit->circuit_id,stream_id);
      va_start( arglist, format );
      vprintf( format, arglist );
      va_end( arglist );
    }


    circuit_t *circuit=NULL;
  
    unsigned short stream_id=0;
    short window=0;			// the backward stream window. Each 50 RELAY_DATA cells are exchanged a RELAY_SENDME is needed
    short window_out=0;			// the forward stream window.
    bool finished=0;
    bool connected=0;
    volatile bool got_resolved=0;
    volatile bool resolve_ok=0;
    in_addr resolved;
    
    stream_callback_t ncb_data;

    void set_ncb(stream_callback_t c) {
      ncb_data=c;
    }

    stream_t() {
      stream_id=0;
    }

    void init(circuit_t *c,int a) {
      window = 500;
      window_out = 500;
      stream_id=a;
      circuit=c;
      memset(&resolved,0,sizeof(resolved));
    }
    
    void send_sendme() { //sends a stream sendme
      vector<unsigned char> empty;

      if (!circuit->write_data(cell_relay_command_t::RELAY_SENDME,empty,stream_id)) {
	LOG_WARN(" RELAY_SENDME cell NOT sent (errors). Circuit will be torn down.\n");
	circuit->destroy_circuit();
	return;
      }

      LOG_INFOVV("RELAY_SENDME sent for stream.\n");
    
      window += 50;
    }

    void check_sendme() { // Check if a new RELAY_SENDME (Stream-level) is required
      if (window <= 450) {
	send_sendme();
      }
    }

    void relay_begin() {
      //handle cell_relay_command_t::RELAY_BEGIN
      LOG_WARN("RELAY_BEGIN stream_id=%x.\n",stream_id);

      connected=1;
      if(ncb_data) ncb_data(NULL,CB_RELAY_BEGIN);
      
      vector<unsigned char> payload;
      circuit->write_data(cell_relay_command_t::RELAY_CONNECTED, payload,stream_id);
    }
    
    void start(const vector<unsigned char> &payload) {
      if (!circuit->write_data(cell_relay_command_t::RELAY_BEGIN,payload, stream_id)) {
	LOG_WARN("error on writing request.\n");
      }
    }

    bool send(const unsigned char *data,int len) {
      if(finished || !connected) {
	LOG_WARN("send error: circuit not streaming (missing start()? not built?).\n");
	return false;
      }

      
      LOG_INFOVV("send sending data forward to circuit with StreamID %hu.\n", stream_id);

      window_out--;
      return circuit->write_data(cell_relay_command_t::RELAY_DATA, data,len,stream_id);
    }

    bool process_cell(cell_t *cell) {
      LOG_DEBUG("stream(%x)::process_cell.... \n",stream_id);
      assert(cell!=NULL);
    
      if (cell->command == cell_command_t::RELAY) {
	int sid=cell->stream_id;
	assert(sid==stream_id);
	  
	if (cell->relay_command == cell_relay_command_t::RELAY_TRUNCATE || cell->relay_command == cell_relay_command_t::RELAY_TRUNCATED) { 
	  LOG_WARN("Read received RELAY_TRUNCATE / RELAY_TRUNCATED, reason = %s. StreamID is %04X, Stream Window is %hu, Circ Window is %hu\n", relay_truncated_reason_str((destroy_reason_t)(cell->payload(0))), stream_id, window, circuit->window);

	  never_here();
	  
	  finished=1;

	  if(ncb_data)
	    ncb_data(NULL,CB_RELAY_END);

	  delete cell;
	  return false;
	}
      
	if (cell->relay_command == cell_relay_command_t::RELAY_END) {
	
	  LOG_INFO("Read received RELAY_END (cause: %s payload=%s). Finished.\n",relay_end_reason_str((relay_end_reason_t)cell->payload(0)),to_str(cell->const_payload(),cell->size).c_str());
	  
	  finished=1;

	  if(ncb_data)
	    ncb_data(NULL,CB_RELAY_END);

	  delete cell;
	  return true;
	}

      
	if (cell->relay_command == cell_relay_command_t::RELAY_SENDME) {
	  LOG_INFOVV("received RELAY_SENDME.\n");

	  window_out+=50;

	  delete cell;
	  return true;
	}

	if (cell->relay_command == cell_relay_command_t::RELAY_CONNECTED) {
	  LOG_INFOVV("stream %x connected\n", stream_id);
	  LOG_INFOVV("relay_connected payload ",cell->const_payload(),cell->size);

	  connected=1;
	  if(ncb_data) ncb_data(NULL,CB_RELAY_BEGIN);

	  delete cell;
	  return true;
	}

	if (cell->relay_command == cell_relay_command_t::RELAY_RESOLVED) {
	  /*
	    The OR replies with a RELAY_RESOLVED cell containing any number of answers. Each answer is of the form:

	    Type   (1 octet)
	    Length (1 octet)
	    Value  (variable-width)
	    TTL    (4 octets)
	    "Length" is the length of the Value field.
	    "Type" is one of:

	    0x00 -- Hostname
	    0x04 -- IPv4 address
	    0x06 -- IPv6 address
	    0xF0 -- Error, transient
	    0xF1 -- Error, nontransient

	    IP addresses are given in network order.
	    Hostnames are given in standard DNS order ("www.example.com") and not NUL-terminated.
	    The content of Errors is currently ignored.
	    For backward compatibility, if there are any IPv4 answers, one of those must be given as the first answer.
	  */

	  // Only IPv4 supported at the moment.

	  unsigned short i = 0;
		
	  while (i < cell->size) {
	    unsigned char type = cell->payload(i);
	    if (type == 0xF0 || type == 0xF1) {
	      // Error.
	      LOG_WARN("resolve: host could not be resolved, error code = %02X\n", type);
	      break;
	    } else if (type != 0x04) {
	      i++; // go to the length field
	      i += 1 + cell->payload(i) + 4; // skip TTL and the length, add 1 to point the next information
	    } else {
	      i += 1; // go to the length field
	      resolved.s_addr += cell->payload(i+1);
	      resolved.s_addr += cell->payload(i+2) << 8;
	      resolved.s_addr += cell->payload(i+3) << 16;
	      resolved.s_addr += cell->payload(i+4) << 24;
	      printf("[cid:%08X] Found IPv4 address: 0x%08X / %s\n", circuit->circuit_id, resolved.s_addr, ipv4_to_string(resolved).c_str());
	      resolve_ok=1;
	      break;
	    }
	  }
	  
	  got_resolved=1;
	  delete cell;
	  return true;
	}

	if (cell->relay_command == cell_relay_command_t::RELAY_DATA) {
	  LOG_DEBUG("stream %x : got data size=%d\n", sid,cell->size);

	  if(ncb_data)
	    ncb_data(cell->const_payload(),cell->size);

	  
	  delete cell;

	  window--;
	  circuit->window--;
	  check_sendme();
	  circuit->check_sendme();

	  return true;
	}
      
	LOG_WARN("stream %x : RELAY Command %s not handled\n",sid,relay_cell_command_str(cell->relay_command));
	delete cell;
	return false;
      }

      LOG_WARN("Command %s not handled\n",cell->command_str());
      never_here();
      delete cell;
      return false;
    }

  
    bool finish() {
      if(connected && !finished) {
	// send a single cell with reason REASON_MISC (see tor specs 6.3)
	// Tors SHOULD NOT send any reason except REASON_MISC for a stream that they have originated.
      
	vector<unsigned char> payload;
	payload.push_back(relay_end_reason_t::REASON_MISC);

	assert(circuit);
	
	// send the RELAY_END cell, do not check for any response or success
	circuit->write_data(cell_relay_command_t::RELAY_END, payload,stream_id);

	LOG_INFOVV("RELAY_END sent for StreamID %04X.\n", stream_id);
      }
      finished=1;
    
      return true;
    }


  };

  map<int,stream_t> streams;

  
  bool hs_circuit=0;
  char rendezvous_ok=0;
  char intro_ok=0;
  protected_list<intro_material_t*> intro2_ok;

  rdv_material_t *rdv_material=NULL;
  
  bool hs_circuit_built() const {
    return hs_circuit;
  }

  relay_t* get_exit_node() {
    return nodes[Nnodes-1];
  }

  bool has_intro2() {
    return !intro2_ok.empty();
  }
  
  intro_material_t* get_intro2() {
    auto r=intro2_ok.pop();
    return r;
  }
  
  circuit_t(string x="") {
    int n=3;
    name=x;
    Nnodes=n;
    nodes.resize(n,NULL);
    
    circuit_id=0;
    link_protocol_version = 0;
    window = 1000;
    window_out = 1000;
  }

  void destroy_circuit(destroy_reason_t reason = destroy_reason_t::NONE ) {
    LOG_INFOV("Sending DESTROY cell to Guard with reason %u\n", int(reason));
    if(build_status==BS_DESTROYED) {
      LOG_INFOV("already DESTROYed\n");
      return;
    }
    
    auto cell = new cell_t_small(link_protocol_version, circuit_id, cell_command_t::DESTROY);
    
    cell->push_back(int(reason));
    cell->send_cell(sock);
    
    sock.disconnect();

    LOG_INFOVV("Circuit destroy success.\n");
    set_status(BS_DESTROYED);
    if(ncb)
      ncb(CB_DESTROY);
  }

  ~circuit_t() {
    LOG_DEBUG("~circuit_t\n");

    if(build_status!=BS_FAIL && build_status!=BS_DESTROYED)
      destroy_circuit();

    sock.disconnect();

    for(int i=0;i<Nnodes;i++)
      if (nodes[i] != NULL) delete nodes[i];

    if(intro_keys)
      delete intro_keys;

    while(!intro2_ok.empty()) {
      auto it=intro2_ok.pop();
      delete it;
    }

    if(rdv_material) delete rdv_material;
  }

  bool process_cert_cell(relay_t & node,const unsigned char *p, int s)
  {
    //node.print_info();
    bool ok=1;
    if(s<1) return false;
    unsigned char nb=p[0];
    p++;s--;
    unsigned char sig_key_25519[32];

    /*
      1: Link key certificate certified by RSA1024 identity
      2: RSA1024 Identity certificate, self-signed.
      3: RSA1024 AUTHENTICATE cell link certificate, signed with RSA1024 key.
      4: Ed25519 signing key, signed with identity key.
      5: TLS link certificate, signed with ed25519 signing key.
      6: Ed25519 AUTHENTICATE cell key, signed with ed25519 signing key.
      7: Ed25519 identity, signed with RSA identity.
    */

    vector<unsigned char> cert1,cert2,cert3;
    const unsigned char *cert[8];
    int szc[8];
    memset(cert,0,sizeof(cert));
    memset(szc,0,sizeof(szc));
    
    cert_ed25519_t c4,c5,c6;
    cert_cross_rsa_ed_t c7;

    //node.print_info();
    
    for(unsigned short u=0;u<nb;u++) {
      if(s<3) return false;
      unsigned char type=p[0];
      unsigned short l=toshort(p+1);
      p+=3;s-=3;
      if(s<l) return false;

      if(type>0 && type<8) {
	cert[type]=p;
	szc[type]=l;
      }
      switch(type) {
      case 1:
	append(cert1,p,l);
	break;
      case 2:
	append(cert2,p,l);
	if(!X509_verif(cert2,cert2)) {
	  printf("cert type 2 not valid\n");
	  ok=0;
	}
	break;
      case 3:
	//TODO
	append(cert3,p,l);
	break;

      case 4:
	if(!c4.init(p,l,node.id25519)) {
	  printf("error in cert4\n");
	  ok=0;
	} else
	  memcpy(sig_key_25519,c4.cert_key,32);
	//c4.print_info();
	break;
      case 6:
	//TODO ?
	printf("got cert 6 !\n");
	if(!c6.init(p,s,sig_key_25519))
	  ok=0;
	c6.print_info();
	break;
      case 7:
	{}
      }
      p+=l;s-=l;
    }
    
    if(!X509_verif(cert1,cert2)) {
      printf("Cert1 not valid\n");
      ok=0;
    }

    if(cert[5]==NULL || !c5.init(cert[5],szc[5],sig_key_25519)) {
      printf("problem in Cert5\n");
      ok=0;
    }

    unsigned char d[32];
    SHA256(d,cert1.data(),cert1.size());
    if(!match(d,c5.cert_key,32)) {
      printf("Cert5 does not certify hash of cert1\n");
      ok=0;
    }

    if(!cert[7] || !c7.init(cert[7],szc[7],cert2)) {
      printf("problem in Cert7 \n");
      ok=0;
    }
    
    if(!match(c7.ed25519,node.id25519,32)) {
      printf("Cert7 does not certify id25519 !\n");
      ok=0;
    }

    //todo cert 3 and cert 6
    if(cert3.size()) {
      //TODO
      print("cert3 ",cert3.data(),cert3.size());
      SHA256(d,cert3.data(),cert3.size());
      print("#cert3 ",d,32);
      if(!X509_verif(cert3,cert2)) {
	printf("cert type 3 not valid\n");
	ok=0;
      } else 
	printf("cert3 - valid\n");
    }

    return ok;
  }
  /*============ build2 ============*/

  enum build_status_t {
    BS_NONE,

    BS_START_CONNECT, 
    BS_CONNECT, //TODO async
    BS_PROTO_START,
    BS_PROTO_VERSION,
    BS_PROTO_CERTS,
    BS_PROTO_AUTH,
    BS_PROTO_NETINFO,
    BS_PROTO_DONE,
    BS_CREATE2,
    BS_WAIT_CREATED2,
    BS_CREATED2,

    BS_EXTEND2,
    BS_WAIT_EXTENDED2,
    BS_EXTENDED2,
    
    BS_BUILT,

    BS_DESTROY,
    BS_DESTROYED,

    BS_FAIL,
  } build_status=BS_NONE ;

  int build_hops=0;
  barrier_t bar_build;

  void set_status(build_status_t i)
  {
    if(i==BS_FAIL) {
      build_status=i;
    } else if(i==BS_DESTROYED) {
      if(build_status!=BS_FAIL)
	build_status=i;
    } else if(i==BS_DESTROY) {
      if(build_status<=BS_BUILT)
	build_status=i;
    } else {
      never_here();
    }
  }
  
  bool start_in_protocol_with_guard(cell_t *cell=NULL) {
    if(build_status==BS_PROTO_START) {
      if(cell)
	LOG_SEVERE("cell should be null!\n");

      // Choose a first, random CircID (does not matter here, see CREATE2)
      // The first VERSIONS cell, and any cells sent before the first VERSIONS cell, always have circuit_id_LEN == 2 for backward compatibility.
    
      circuit_id=random_short();
      LOG_INFOV("start_in_protocol_with_guard start.  temp CircID = 0x%04X\n", circuit_id);
    
      /*
	When the in-protocol handshake is used, the initiator sends a
	VERSIONS cell to indicate that it will not be renegotiating.  The
	responder sends a VERSIONS cell, a CERTS cell (4.2 below) to give the
	initiator the certificates it needs to learn the responder's
	identity, an AUTH_CHALLENGE cell (4.3) that the initiator must include
	as part of its answer if it chooses to authenticate, and a NETINFO
	cell (4.5).  As soon as it gets the CERTS cell, the initiator knows
	whether the responder is correctly authenticated.  At this point the
	initiator behaves differently depending on whether it wants to
	authenticate or not. If it does not want to authenticate, it MUST
	send a NETINFO cell.  If it does want to authenticate, it MUST send a
	CERTS cell, an AUTHENTICATE cell (4.4), and a NETINFO.  When this
	handshake is in use, the first cell must be VERSIONS, VPADDING, or
	AUTHORIZE, and no other cell type is allowed to intervene besides
	those specified, except for VPADDING cells.
      */
    
      // Start with VERSIONS (+CERTS +AUTH_CHALLENGE +NETINFO) and authenticate myself (not for now, TODO )
    
      /*
	The payload in a VERSIONS cell is a series of big-endian two-byte
	integers.  Both parties MUST select as the link protocol version the
	highest number contained both in the VERSIONS cell they sent and in the
	versions cell they received.  If they have no such version in common,
	they cannot communicate and MUST close the connection.  Either party MUST
	close the connection if the versions cell is not well-formed (for example,
	if it contains an odd number of bytes).
      */
      
      LOG_DEBUG("start_in_protocol_with_guard : send VERSIONS");
      cell_t *cell= new cell_t_small(0, circuit_id, cell_command_t::VERSIONS);
	
      // I can handle version 4 and 5
      cell->push_back_short(4);
      cell->push_back_short(5);
	
      cell->send_cell(sock);
      build_status=BS_PROTO_VERSION;
      LOG_DEBUG("start_in_protocol_with_guard : wait VERSIONS");
      return 1;
    }

    if (cell==NULL) {
      LOG_WARN("cell==NULL\n");
      return false;
    }

    if(build_status==BS_PROTO_VERSION) {
      if (cell->command != cell_command_t::VERSIONS) {
	LOG_WARN(" expected VERSIONS cell but received %s.\n", cell->command_str());
	delete cell;
	return false;
      }

      link_protocol_version=sock.linkversion;
      
      if (link_protocol_version < 4) {
	LOG_WARN(" Guard has an old link protocol (version %d but required >= 4).\n", link_protocol_version);
	delete cell;
	return false;
      }

      delete cell;

      build_status=BS_PROTO_CERTS;
      LOG_DEBUG("start_in_protocol_with_guard : wait CERTS");

      return 1;
    }

    if(build_status==BS_PROTO_CERTS) {
      if (cell->command != cell_command_t::CERTS) {
	LOG_WARN("expected CERTS cell but received %s.\n", cell->command_str());
	delete cell;
	return false;
      }

      if (!process_cert_cell(*nodes[0],cell->const_payload(),cell->size)) {
	LOG_WARN("problem with CERTS\n");
	delete cell;
	return false;
      }

      delete cell;

      build_status=BS_PROTO_AUTH;
      LOG_DEBUG("start_in_protocol_with_guard : wait AUTH_CHANLLENGE");
      return 1;
    }
    
    if(build_status==BS_PROTO_AUTH) {
      if (cell->command != cell_command_t::AUTH_CHALLENGE) {
	LOG_WARN("expected AUTH_CHALLENGE cell but received %s.\n", cell->command_str());
	delete cell;
	return false;
      }
      
      LOG_DEBUG("WARNING: AUTH_CHALLENGE cell is not handled at moment from this version.\n");
      // TODO dont't mind for now..

      delete cell;
      LOG_DEBUG("start_in_protocol_with_guard : wait NETINFO");
      build_status=BS_PROTO_NETINFO;
      return 1;
    }

    if(build_status==BS_PROTO_NETINFO) {
      if (cell->command != cell_command_t::NETINFO) {
	LOG_WARN("expected NETINFO cell but received %s.\n", cell->command_str());
	delete cell;
	return false;
      }
      
      LOG_DEBUG("Info: this version do not check or handle incoming NETINFO cell.\n");
      
      delete cell;

      LOG_DEBUG("start_in_protocol_with_guard : send NETINFO");

      cell_t * cell = new cell_t_small( link_protocol_version, circuit_id, cell_command_t::NETINFO );
      struct in_addr public_ip;
      inet_aton(get_public_ip().c_str(), &public_ip);
      cell->create_netinfo(public_ip);
      cell->send_cell(sock); 
      
      build_status=BS_PROTO_DONE;
      
      return true;
    }

    never_here();
  }


  bool continue_build_circuit(cell_t *cell,int time=0) {
    LOG_INFOV("continue_build_circuit build_status=%d cell=%p\n",int(build_status),cell);

    if(cell==NULL) {
      LOG_INFO("timelimit %d ms: FAIL build\n",time);
      return 0;
    }
    
    if(build_status>=BS_PROTO_START && build_status<BS_PROTO_DONE) {
      int r=start_in_protocol_with_guard(cell);
      if(!r) return 0;
      if(build_status!=BS_PROTO_DONE) return 1;
    }
	     
    if(build_status==BS_PROTO_DONE) {
      // If the relay do not have an Ed25519 identity, the CREATE2 will fail.
      // This version does not support old CREATE.

      LOG_INFOVV("All information complete. Starting creating the circuit with CREATE2.\n");

      // Re-setup CircID with 4 bytes (link protocol >=4)

      // TODO / do not understand:
      // To prevent CircID collisions, when one node sends a CREATE/CREATE2
      // cell to another, it chooses from only one half of the possible
      // values based on the ORs' public identity keys.

      circuit_id=random_int();

      // However looking at tor sources this seems much more important:

      /*
	In link protocol version 4 or higher, whichever node initiated the
	connection sets its MSB to 1, and whichever node didn't initiate the
	connection sets its MSB to 0
      */

      // So it's clear, my circid must have MSB to 1
      circuit_id = circuit_id | 0x80000000;

      LOG_INFOVV("NEW CircID: 0x%08X \n", circuit_id);

      build_status=BS_CREATE2;
      if (!create2(nodes[0])) {
	LOG_WARN("Failed to start CREATE2 with guard.\n");
	destroy_circuit();
	return false;
      }
      return 1;
    }

    if(build_status==BS_WAIT_CREATED2) {
      int r=create2(nodes[0],cell);
      cell=NULL;
      if(!r) return 0;
      assert(build_status==BS_CREATED2);
      build_hops=1;
    }

    if(build_status==BS_WAIT_EXTENDED2) {
      int r=extend2(build_hops,cell);
      cell=NULL;
      if(!r) {
	destroy_circuit();
	return 0;
      }
      assert(build_status==BS_EXTENDED2);
      build_hops++;
    }
    
    if(build_status==BS_CREATED2 || build_status==BS_EXTENDED2) {
      if(build_hops==Nnodes) {
	LOG_INFOVV("EXTEND2 with Exit success. All done!!\n");
	
	print_circuit_info();
	
	lastcell=get_unix_time();
	
	build_status=BS_BUILT;
	bar_build.kill();
	return 1;
      }
      
      build_status=BS_EXTEND2;
      assert(cell==NULL);
      int r=extend2(build_hops);
      if(!r)
	destroy_circuit();
      return r;
    }
    never_here();
  }
  
  bool build_circuit() {
    return sync_build_circuit();
  }

  bool sync_build_circuit() {
    auto r=async_build_circuit();
    LOG_INFOV("async_build_circuit rets %d\n",r);
    if(!r) return false;
    bar_build.wait();
    bool ok=(build_status==BS_BUILT);
    LOG_INFO("circuit_built finished. ok=%d\n",ok);
    return ok;
  }

  bool async_build_circuit() {
    // If it was previously created or a tentative was in place, tear down the previous.
    LOG_DEBUG("async build circuit...");
    assert(build_status==BS_NONE);


    for(int i=0;i<Nnodes;i++) {
      if(nodes[i]==NULL)
	return 0;
    }

    build_status = BS_START_CONNECT;

    auto client = new socket_tls_t();
    client->set_timeout(3000+42,5000+42);
    //client->blocking=0;
    sock.client=client;

    build_status = BS_CONNECT;

    LOG_INFOV("connect to guard %s\n",ipv4_to_string(*(in_addr*)(nodes[0]->ipv4)).c_str());
    if (1 != client->connect(ipv4_to_string(*(in_addr*)(nodes[0]->ipv4)), nodes[0]->port ) ) {
      LOG_WARN("Failed to connect to Guard.\n");
      return false;
    }

    firstconnection=1;

    LOG_INFOVV("Connected to guard node.\n");

    char tmp[100];
    snprintf(tmp,99," circuit=%p",this);
    sock.launch_th(name+string(tmp));      
    //sock.timeout=something;
      
    nodes[0]->allocate_temp();
    
    sock.set_callback(std::bind(&circuit_t::cb_cell,this,std::placeholders::_1,std::placeholders::_2,std::placeholders::_3));

    build_status =BS_PROTO_START;

    // Here I will use the IN-PROTOCOL HANDSHAKE

    LOG_DEBUG("start_in_protocol_with_guard...");

    if (!start_in_protocol_with_guard()) {
      LOG_WARN("Failed to start InProtocol with guard.\n");
      return false;
    }

    return 1;
  }

  bool create2(relay_t *relay,cell_t *cell=NULL) {
    if(build_status==BS_CREATE2) {
      if(cell)
	LOG_SEVERE("cell should be null!\n");
      
      auto cell = new cell_t_small(link_protocol_version, circuit_id, cell_command_t::CREATE2);
      
      if (!cell->create_create2(*relay)) {
	LOG_WARN("Failed on building cell CREATE2.\n");
	return false;
      }
      
      cell->send_cell(sock);

      build_status=BS_WAIT_CREATED2;
      return 1;
    }

    assert(cell);
	       
    if(build_status==BS_WAIT_CREATED2) {
      if (cell->command == cell_command_t::DESTROY) {
	LOG_WARN("DESTROY received! Reason = 0x%02X (%s)\n", cell->payload(0), relay_truncated_reason_str((destroy_reason_t)(cell->payload(0))));
	delete cell;
	return false;
      }
      
      if (cell->command != cell_command_t::CREATED2) {
	LOG_WARN("response contains %s cell instead of CREATED2. Failure.\n", cell->command_str());
	if (cell->command == cell_command_t::DESTROY)
	  LOG_WARN("DESTROY received! Reason = 0x%02X (%s)\n", cell->payload(0), relay_truncated_reason_str((destroy_reason_t)(cell->payload(0))));
	delete cell;
	return false;
      }
      LOG_DEBUG("CREATED2");
      
      if (!relay->finish_handshake(cell->const_payload(),cell->size)) {
	LOG_WARN("Error on concluding handshake!\n");
	// From now... always destroy
	destroy_circuit();
	delete cell;
	return false;
      }
      
      delete cell;
      
      build_status=BS_CREATED2;
      return true;
    }
    never_here();
  }

  
  bool extend2(int num,cell_t *cell=NULL) {
    if(build_status==BS_EXTEND2) {
      LOG_INFOVV("Sending EXTEND2 cell (num=%d).\n",num);
      if(cell)
	LOG_SEVERE("cell should be null!\n");

      // EXTEND2 is a RELAY cell! (RELAY_EARLY since link protocol v2)
      auto cell = new cell_t_small(link_protocol_version, circuit_id, cell_command_t::RELAY_EARLY);
		
      if (!cell->create_extend2(*(this->nodes[num]))) {
	LOG_WARN("Failed on building cell EXTEND2 to exit.\n");
	return 0;
      }

      // After building the main contents, prepare it as a relay cell
      vector<unsigned char> d;
      cell->prepare_relaycell(cell_relay_command_t::RELAY_EXTEND2, 0,d,nodes[num-1]->skin);

      for(int u=num-1;u>=0;u--)
	cell->encrypt(nodes[u]->skin);

      cell->send_cell(sock);
      build_status=BS_WAIT_EXTENDED2;
      
      return 1;
    }
    if(build_status==BS_WAIT_EXTENDED2) {
      if(cell==NULL) {
	LOG_WARN("Error NULL\n");
	return 0;
      }
      
      if (cell->command != cell_command_t::RELAY) {
	LOG_WARN("response contains %s cell instead of RELAY. Failure.\n", cell->command_str());
	if (cell->command == cell_command_t::DESTROY)
	  LOG_WARN("DESTROY received! Reason = 0x%02X (%s)\n", cell->payload(0), relay_truncated_reason_str((destroy_reason_t)(cell->payload(0))));
	delete cell;
	return 0;
      }

      //Decrypt payload of received cell
      for(int i=0;i<num;i++) {
	cell->decrypt(nodes[i]->skin);

	if(i<num-1) {
	  auto ret = cell->is_recognized(nodes[i]->skin);
	  if(ret==1) {
	    LOG_WARN("RECOGNISED node %d\n",i);
	    if (!cell->build_relaycell_from_payload(last_digest,nodes[i]->skin)) {
	      LOG_WARN("ReadData error on rebuilding RELAY cell informations from exit node, invalid response cell.\n");
	      delete cell;
	      return 0;
	    }
	    LOG_INFOVV("Command %s streamid:%x\n", cell->command_str(),cell->stream_id);
	    LOG_INFOVV("RELAY Command %s \n",relay_cell_command_str(cell->relay_command));

	    if (cell->relay_command == cell_relay_command_t::RELAY_TRUNCATE || cell->relay_command == cell_relay_command_t::RELAY_TRUNCATED) { 
	      LOG_WARN("Read received RELAY_TRUNCATE / RELAY_TRUNCATED, reason = %s\n", relay_truncated_reason_str((destroy_reason_t)(cell->payload(0))));
	      delete cell;
	      return 0;
	    }
	    
	  }
	}
      }
      
      {
	auto ret = cell->is_recognized(nodes[num-1]->skin);
	if (ret!=1) {
	  LOG_WARN("Cell has not been recognized, failure.\n");
	  delete cell;
	  return 0;
	}
      }

      skin_ctx_t *skin=&(nodes[num-1]->skin);
      
      // Verification passed, now build cell informations
      if (!cell->build_relaycell_from_payload(last_digest,*skin)) {
	LOG_WARN("Error on rebuilding RELAY cell informations from exit node, invalid cell.\n");
	delete cell;
	return 0;
      }

      if (cell->relay_command != cell_relay_command_t::RELAY_EXTENDED2) {
	LOG_WARN("Expected EXTENDED2 but received %s\n", relay_cell_command_str(cell->relay_command));
	delete cell;
	return 0;
      }

      LOG_INFOVV("EXTENDED2 %d\n",num);

      /* The payload of an EXTENDED2 cell is the same as the payload of a CREATED2 cell */
      if (!nodes[num]->finish_handshake(cell->const_payload(),cell->size)) {
	LOG_WARN("Error on concluding EXTENDED2 handshake with exit!\n");
	// Always destroy if fails
	delete cell;
	return 0;
      }

      LOG_INFOVV("EXTENDED2 Success, circuit has now a new hop\n");

      delete cell;
      build_status=BS_EXTENDED2;
	
      return 1;
	
    }
    
    return true;
  }
  
  /**** end new build *****/

protected:
  void cb_cell_build(cell_t *cell,int time)
  {
    int r=continue_build_circuit(cell,time);
    if(r==0) {
      LOG_WARN("continue_build_circuit failed\n");
      set_status(BS_FAIL);
      destroy_circuit();
      bar_build.kill();
      if(ncb)
	ncb(CB_CIRCUIT_BUILT_FAIL);
    }
    if(build_status==BS_BUILT) {
      if(ncb)
	ncb(CB_CIRCUIT_BUILT_OK);
    }
  }

  rec_mutex_t cb_mutex;
  void cb_lock() {
    cb_mutex.lock();
  }

  void cb_unlock() {
    cb_mutex.unlock();
  }
  
public:
  void cb_cell(cell_t *c,cb_type_t type,int time)
  {
    cb_lock();
    if(type==MCBT_START) {
      LOG_INFO("CB CELL START\n");
      //assert(build_status==BS_START_CONNECT);

      cb_unlock();
      return;
    } 

    if(type==MCBT_PING) {
      LOG_DEBUGV("ping time=%d ms\n",time);
    } 

    if(build_status==BS_FAIL) {
      if(c)
	delete c;
      cb_unlock();
      return;
    }
    
    if(build_status>=BS_PROTO_START && build_status<BS_BUILT) {
      cb_cell_build(c,time);
      cb_unlock();
      return;
    }

    if(c)
      process_cell(c);

    cb_unlock();
  }


  bool write_data(const cell_relay_command_t& command, const vector<unsigned char>& data,int sid=0) {
    return write_data(command,data.data(),data.size(),sid);

  }
  
  mutex_t send_mutex;

  bool write_data(const cell_relay_command_t& command, const unsigned char *data,int len,int sid=0) {
    auto cell = new cell_t_small(link_protocol_version, circuit_id, cell_command_t::RELAY);
    
    if (!cell->push_back(data,len)) {
      LOG_SEVERE("write_data called with too large payload.\n");
      return false;
    }

    send_mutex.lock();

    vector<unsigned char> digest;

    skin_ctx_t *skin=&(nodes[2]->skin);
    if(hs_circuit) {
      assert(rdv_material);
      skin=&(rdv_material->skin);
    }
    
    cell->prepare_relaycell(command, sid,digest,*skin);
#ifndef NOTORCHECKS
    if(command==cell_relay_command_t::RELAY_DATA) {
      window_out--;
      if(window_out%100==0) {
	digests.push_back(digest);
      }
      if(window_out<0) {
	printf("window_out <0 : destroy !!!\n");
	destroy_circuit();
      }
    }
#endif
    
    if(hs_circuit) {
      cell->encrypt(rdv_material->skin);
    }

    for(int i=Nnodes-1;i>=0;i--) {
      cell->encrypt(nodes[i]->skin);
    }
    
    cell->send_cell(sock);

    send_mutex.unlock();

    return true;
  }

  int stream_start(const in_addr& ipv4, const short& port,stream_callback_t cb=NULL) {
    return stream_start(ipv4_to_string(ipv4), port,cb);
  }

  void remove_stream(unsigned int s)
  {
    LOG_INFOVV("streams.erase(%x)\n",s);
    streams.erase(s);
  }

  void cleanup_stream()
  {
    list<unsigned int> s;
    for(auto &it:streams)
      if(it.second.finished)
	s.push_back(it.first);
    for(auto &it:s)
      remove_stream(it);
  }

  unsigned int new_stream_id() {
    int r=random_short()%30000;
    for(int i=0;i<30000;i++) {
      if(streams.find(r)==streams.end()) return r;
      r=r+1;
      if(r==30000) r=1;
    }
    return 0;
  }

  int stream_start(const string& hostname, const short& port,stream_callback_t cb) {
    int stream_id=new_stream_id();

    if(stream_id==0) {
      return 0;
    }

    streams[stream_id].init(this,stream_id);
    if(cb)
      streams[stream_id].set_ncb(cb);
    
    LOG_INFOV("start StreamID is %04X.\n", stream_id);

    /*
      To open a new anonymized TCP connection, the OP chooses an open
      circuit to an exit that may be able to connect to the destination
      address, selects an arbitrary StreamID not yet used on that circuit,
      and constructs a RELAY_BEGIN cell with a payload encoding the address
      and port of the destination host.  The payload format is:

      ADDRPORT [nul-terminated string]
      FLAGS    [4 bytes]

      ADDRPORT is made of ADDRESS | ':' | PORT | [00]

      where  ADDRESS can be a DNS hostname, or an IPv4 address in
      dotted-quad format, or an IPv6 address surrounded by square brackets;
      and where PORT is a decimal integer between 1 and 65535, inclusive.

    */

    vector<unsigned char> payload;

    for (const char& c : hostname) {
      payload.push_back(c);
    }
    payload.push_back(':');

    for (auto & pc: std::to_string(port)) payload.push_back(pc);

    payload.push_back(0x00);

    /*
      The FLAGS value has one or more of the following bits set, where
      "bit 1" is the LSB of the 32-bit value, and "bit 32" is the MSB.
      (Remember that all values in Tor are big-endian (see 0.1.1 above), so
      the MSB of a 4-byte value is the MSB of the first byte, and the LSB
      of a 4-byte value is the LSB of its last byte.)

      bit   meaning
      1 -- IPv6 okay.  We support learning about IPv6 addresses and
      connecting to IPv6 addresses.
      2 -- IPv4 not okay.  We don't want to learn about IPv4 addresses
      or connect to them.
      3 -- IPv6 preferred.  If there are both IPv4 and IPv6 addresses,
      we want to connect to the IPv6 one.  (By default, we connect
      to the IPv4 address.)
      4..32 -- Reserved. Current clients MUST NOT set these. Servers
      MUST ignore them.
		
    */

    append_int(payload,0); // IPv4 only

    // Send the request and wait for a RELAY_CONNECTED
    streams[stream_id].start(payload);
    
    return stream_id;
  }


  void send_sendme() {
    vector<unsigned char> payload;

    payload.push_back(0x01); // version 1 authenticated cell

    payload.push_back(0); // size. sends 20 bytes, even if the hash is sha3, with 32 bytes digest, otherwise tor is not happy...
    payload.push_back(20);
      
    append(payload,last_digest.data(),20); 

    if (!write_data(cell_relay_command_t::RELAY_SENDME, payload)) {
      LOG_WARN("RELAY_SENDME cell NOT sent (errors). Circuit will be torn down.\n");
      destroy_circuit();
      return;
    }

    LOG_INFOVV("RELAY_SENDME sent.\n");
    window += 100;
  }

  void check_sendme() {
    if (window <= 900)  {
      send_sendme();
    }
  }

  void send_padding() {
    if (build_status==BS_BUILT && last_sent_padding + 10 < get_unix_time()) { //send padd every 10 secs
      auto cell = new cell_t_small(link_protocol_version, circuit_id, cell_command_t::PADDING);
      cell->send_cell(sock);
      
      last_sent_padding = get_unix_time();
    }
  }

  mutex_t mut_relay_begin;
  
  struct relay_begin_t {
    unsigned short stream_id;
    string host;
    int port;
  };
  
  list<relay_begin_t*> relay_begins;
  condvar_t condvar_relay_begin;
  
  void push_relay_begin(unsigned short sid,const char* host,int port) {
    mut_relay_begin.lock();
    relay_begin_t *r=new relay_begin_t;
    r->stream_id=sid;
    r->host=host;
    r->port=port;
    relay_begins.push_back(r);
    condvar_relay_begin.broadcast();
    mut_relay_begin.unlock();
  }
  
  const relay_begin_t* listen(int timeout=1000) {
    mut_relay_begin.lock();

    if(build_status!=BS_BUILT)
      LOG_WARN("build_status!=BS_BUILT\n");
    
    while(build_status==BS_BUILT) {
      if(!relay_begins.empty()) {
	auto r=relay_begins.front();
	mut_relay_begin.unlock();
	return r;
      }
      int r=condvar_relay_begin.timedwait(mut_relay_begin,timeout);
      if(r==false)
	break;
    }
    mut_relay_begin.unlock();
    return NULL;
  }


  void relay_end(int sid,int reason=0) {
    vector<unsigned char> pay;
    pay.push_back(reason);
    write_data(cell_relay_command_t::RELAY_END,pay, sid);
    
    /*
      1 -- REASON_MISC           (catch-all for unlisted reasons)
      2 -- REASON_RESOLVEFAILED  (couldn't look up hostname)
      3 -- REASON_CONNECTREFUSED (remote host refused connection) [*]
      4 -- REASON_EXITPOLICY     (OR refuses to connect to host or port)
      5 -- REASON_DESTROY        (Circuit is being destroyed)
      6 -- REASON_DONE           (Anonymized TCP connection was closed)
      7 -- REASON_TIMEOUT        (Connection timed out, or OR timed out
      while connecting)
      8 -- REASON_NOROUTE        (Routing error while attempting to
      contact destination)
      9 -- REASON_HIBERNATING    (OR is temporarily hibernating)
      10 -- REASON_INTERNAL       (Internal error at the OR)
      11 -- REASON_RESOURCELIMIT  (OR has no resources to fulfill request)
      12 -- REASON_CONNRESET      (Connection was unexpectedly reset)
      13 -- REASON_TORPROTOCOL    (Sent when closing connection because of
      Tor protocol violations.)
      14 -- REASON_NOTDIRECTORY   (Client sent RELAY_BEGIN_DIR to a
      non-directory relay.)
    */
  }
  
  int accept(stream_callback_t cb=NULL) {
    mut_relay_begin.lock();
    assert(!relay_begins.empty());
    auto r=relay_begins.front();
    relay_begins.pop_front();
    mut_relay_begin.unlock();
    auto stream_id=r->stream_id;
    delete r;
    if(cb) {
      streams[stream_id].init(this,stream_id);
      streams[stream_id].set_ncb(cb);
      streams[stream_id].relay_begin();
      return stream_id;
    } else {
      relay_end(stream_id,3);
    }
    return -1;
  }

  void reject() {
    accept();
  }
  
  
  bool process_cell(cell_t *cell)
  {
    send_padding();
    lastcell=get_unix_time();
    
    assert(cell!=NULL);
    LOG_INFOVV("main procescell Command %s \n",cell->command_str());

    if (cell->command == cell_command_t::PADDING) {
      goto process_cell_ok;
    }

    if (cell->circuit_id != circuit_id) {
      LOG_WARN("ignore cell because of circuit_id %x != %x\n",cell->circuit_id,circuit_id);
      LOG_WARN("Command is %s \n",cell->command_str());
      goto process_cell_ok;
    }

    if (cell->command == cell_command_t::DESTROY) {
      LOG_WARN("DESTROY received! Reason = 0x%02X (%s)\n", cell->payload(0), relay_truncated_reason_str((destroy_reason_t)(cell->payload(0))));
      set_status(BS_DESTROY);
      goto process_cell_destroy;
    }

    if (cell->command == cell_command_t::RELAY) {

      // If RELAY cell but command is TRUNCATE => error


      int rec=0;
      for(int i=0;i<Nnodes;i++) {
	cell->decrypt(nodes[i]->skin);
	rec = cell->is_recognized(nodes[i]->skin);
	
	if(i<2 || hs_circuit) {
	  if(rec==1) {	    
	    LOG_WARN("RECOGNISED node %d\n",i);
	    if (!cell->build_relaycell_from_payload(last_digest,nodes[i]->skin)) {
	      LOG_WARN("ReadData error on rebuilding RELAY cell informations from exit node, invalid response cell.\n");
	      goto process_cell_ko;
	    }
	    LOG_INFOVV("Command %s streamid:%x\n", cell->command_str(),cell->stream_id);
	    LOG_INFOVV("RELAY Command %s \n",relay_cell_command_str(cell->relay_command));

	    if (cell->relay_command == cell_relay_command_t::RELAY_TRUNCATE || cell->relay_command == cell_relay_command_t::RELAY_TRUNCATED) { 
	      LOG_WARN("Read received RELAY_TRUNCATE / RELAY_TRUNCATED, reason = %s. Circ Window is %hu\n", relay_truncated_reason_str((destroy_reason_t)(cell->payload(0))),  window);
	      set_status(BS_DESTROY);
	    }

	    goto process_cell_destroy;
	  }
	}
      }

      if(hs_circuit) {
	assert(rdv_material);
      	cell->decrypt(rdv_material->skin);
	rec = cell->is_recognized(rdv_material->skin);
      } 
      
      // If is NOT recognized here, an error occoured.
      if(rec!=1) {
	LOG_WARN("unrecognized cell from exit node.\n");
	
	goto process_cell_ko;
      }

      skin_ctx_t *skin=&(nodes[2]->skin);
      if(hs_circuit)
	skin=&(rdv_material->skin);
      
      // Build informations (decrypted payload etc.)
      if (!cell->build_relaycell_from_payload(last_digest,*skin)) {
	LOG_WARN("ReadData error on rebuilding RELAY cell informations from exit node, invalid response cell.\n");
	goto process_cell_ko;
      }

      if (cell->relay_command == cell_relay_command_t::RELAY_TRUNCATE || cell->relay_command == cell_relay_command_t::RELAY_TRUNCATED) { 
	LOG_WARN("Read received RELAY_TRUNCATE / RELAY_TRUNCATED, reason = %s. Circ Window is %hu\n", relay_truncated_reason_str((destroy_reason_t)(cell->payload(0))),  window);
	set_status(BS_DESTROY);
      }
      
      

      int sid=cell->stream_id;
      if(sid>0) {
	auto it=streams.find(sid);
	
	if(it==streams.end()) {
	  if(cell->relay_command == cell_relay_command_t::RELAY_BEGIN) {
	    bool ok=1;
	    int l=strnlen((const char*)cell->const_payload(),cell->size);
	    if(cell->const_payload()[l]!=0)
	      ok=0;
	    else {
	      l++;
	      char tmp[l];
	      memcpy(tmp,(const char*)cell->const_payload(),l);
	      LOG_INFOV("got relay_begin %x '%s'\n",sid,tmp);
	      string host;
	      int port=-1;
	      for(int i=0;i<l;i++)
		if(tmp[i]==':') {
		  tmp[i]=0;
		  host=tmp;
		  port=atoi(tmp+i+1);
		  break;
		}
	      if(port<0)
		ok=0;
	      else
		push_relay_begin(sid,host.c_str(),port);
	    }
	    if(!ok) {
	      LOG_WARN("problem in RELAY_BEGIN stream_id=%x\n",sid);
	      goto process_cell_ko;
	    } else {
	      goto process_cell_ok;
	    }
	  } else {
	    LOG_WARN("stream %x not found. Command %s / %s \n",sid,cell->command_str(),relay_cell_command_str(cell->relay_command));
	    goto process_cell_ko;
	  }
	} else 
	  return it->second.process_cell(cell);
      } else {
	if (cell->relay_command == cell_relay_command_t::RELAY_COMMAND_INTRODUCE_ACK) {
	  
	  LOG_INFOV("INTRODUCE_ACK Reason = %02X %02X\n", int(cell->payload(0)), int(cell->payload(1)));
	  
	  //TODO
	  goto process_cell_ok;
	}

	if (cell->relay_command == cell_relay_command_t::RELAY_COMMAND_INTRODUCE2) {
	  
	  //print("payload: ",cell->const_payload(),cell->size);
	  if(intro_ok) {
	    auto r=process_introduce2(cell->const_payload(),cell->size);
	    if(r) {
	      intro2_ok.push_back(r);
	      //TODO callback
	    }
	    else
	      printf("error in process introduce2\n");
	  } else {
	    printf("I am not a intro circuit !\n");
	  }
	  
	  goto process_cell_ok;
	}

	// If RELAY_SENDME then can ignore, return true.
	if (cell->relay_command == cell_relay_command_t::RELAY_SENDME) {
	  LOG_INFOVV("got sendme \n");

#ifndef NOTORCHECKS
	  window_out +=100;

	  auto p=cell->const_payload();
	  int s=cell->size;

	  //print("payload sendme: ",p,s);
	  
	  if(s<3) {
	    LOG_WARN("pb sendme \n");
	    goto process_cell_destroy;
	  }

	  if(digests.empty()) {
	    LOG_WARN("pb sendme digests.empty()\n");
	    goto process_cell_destroy;
	  }
	  auto r=digests.front();
	  digests.pop_front();
	  //print("my digest ",r.data(),r.size());
	  
	  if(memcmp(r.data(),p+3,20)) {
	    LOG_WARN("pb sendme \n");
	    goto process_cell_destroy;
	  }
#endif
	  
	  goto process_cell_ok;
	}

	if (cell->relay_command == cell_relay_command_t::RELAY_COMMAND_RENDEZVOUS_ESTABLISHED) {
	  rendezvous_ok=1;
	  goto process_cell_ok;
	}

	if (cell->relay_command == cell_relay_command_t::RELAY_COMMAND_INTRO_ESTABLISHED) {
	  LOG_INFOV("RELAY_COMMAND_INTRO_ESTABLISHED\n");
	  intro_ok=1;
	  goto process_cell_ok;
	}

	if (cell->relay_command == cell_relay_command_t::RELAY_COMMAND_RENDEZVOUS2) {
	  rendezvous_ok=2;
	  print(cell->const_payload(),cell->size);
	  if(rdv_material) {
	    int r=finish_hs_handshake(*rdv_material,cell->const_payload(),cell->size);
	    printf("finish_hs_handshake returns %d\n",r);
	    if(r)
	      hs_circuit=1;
	  } else {
	    LOG_SEVERE("no material for hs handshake !\n");
	  }
	  goto process_cell_ok;
	}
	
	LOG_WARN("stream %x : RELAY Command %s not handled\n",sid,relay_cell_command_str(cell->relay_command));
	goto process_cell_ko;
      }
  }
    LOG_WARN("Command %s not handled\n",cell->command_str());
    goto process_cell_ko;
    
  process_cell_destroy:
    destroy_circuit();
  process_cell_ko:
    delete cell;
    return false;
  process_cell_ok:
    delete cell;
    return true;
  }
    
  bool stream_send(int id,const vector<unsigned char> &data) {
    return stream_send(id,data.data(),data.size());
  }

  bool stream_send(int id,const unsigned char *data,int len) {
    auto it=streams.find(id);
    if(it==streams.end()) return false;
    if(it->second.finished) return false;
    return it->second.send(data,len);
  }

  bool stream_end(int id) {
    auto it=streams.find(id);
    if(it==streams.end()) return false;
    if(it->second.finished) return true;
    it->second.finish();
    return true;
  }

  bool stream_is_closed(int id) {
    auto it=streams.find(id);
    if(it==streams.end()) return true;
    return it->second.finished;
  }


  void establish_intro(const intro_keys_t &keys) {
    /*
      3.1.1. Extensible ESTABLISH_INTRO protocol. [EST_INTRO]

      When a hidden service is establishing a new introduction point, it
      sends an ESTABLISH_INTRO cell with the following contents:

      AUTH_KEY_TYPE    [1 byte] //       [02] -- Ed25519; SHA3-256.
      AUTH_KEY_LEN     [2 bytes] //32
      AUTH_KEY         [AUTH_KEY_LEN bytes] //auth key
      N_EXTENSIONS     [1 byte] //0
      N_EXTENSIONS times:
      EXT_FIELD_TYPE [1 byte]
      EXT_FIELD_LEN  [1 byte]
      EXT_FIELD      [EXT_FIELD_LEN bytes]
      HANDSHAKE_AUTH   [MAC_LEN bytes]
      SIG_LEN          [2 bytes]
      SIG              [SIG_LEN bytes]
    
   The HANDSHAKE_AUTH field contains the MAC of all earlier fields in
   the cell using as its key the shared per-circuit material ("KH")
   generated during the circuit extension protocol; see tor-spec.txt
   section 5.2, "Setting circuit keys". It prevents replays of
   ESTABLISH_INTRO cells.

   SIG_LEN is the length of the signature.

   SIG is a signature, using AUTH_KEY, of all contents of the cell, up
   to but not including SIG. These contents are prefixed with the string
   "Tor establish-intro cell v1".

   * Instantiate MAC(key=k, message=m) with H(k_len | k | m),
   where k_len is htonll(len(k)).

    */

    //memcpy(intro_material->auth_key_sec,keys.auth.secret_key,64);
    //memcpy(intro_material->auth_key,keys.auth.public_key,32);
    //intro_material->intro_keys=&keys;

    intro_keys=new intro_keys_t;
    (*intro_keys)=keys;

    vector<unsigned char> payload;
    payload.push_back(2);
    payload.push_back(0);
    payload.push_back(32);

    append(payload,keys.auth.public_key,32);
    payload.push_back(0);

    unsigned char mac[32];

    MAC_SHA3(mac,nodes[Nnodes-1]->skin.KH,20,payload.data(),payload.size());

    //print("M K ",nodes[Nnodes-1]->skin.KH,20);
    //print("M m  ",payload.data(),payload.size());
    //print("M mac ",mac,32);

    append(payload,mac,32);

    
    const char *pref="Tor establish-intro cell v1";
    vector<unsigned char> m;
    append(m,(unsigned char*)pref,strlen(pref));
    append(m,payload);

    //print("S AK ",keys.auth.public_key,32);
    //print("S m  ",m.data(),m.size());
    
    unsigned char sig[64];
    edsign_sign_expanded(sig, keys.auth.public_key, keys.auth.secret_key, m.data(),m.size());

    payload.push_back(0);
    payload.push_back(64);
    append(payload,sig,64);

    //print("Ssig  ",sig,64);

    //int stream_id=new_stream_id();
    write_data(cell_relay_command_t::RELAY_COMMAND_ESTABLISH_INTRO,payload, 0);

    LOG_INFOV("intro1 sent\n");
  }

  intro_keys_t *intro_keys=NULL;

  intro_material_t *process_introduce2(const unsigned char *pp,int ss)
  {
    //printf("process_intro2...\n");
    if(intro_keys==NULL) return NULL;
    intro_material_t *mat=new intro_material_t;
    mat->intro_keys=new intro_keys_t;
    *(mat->intro_keys)=*intro_keys;
    
    auto p=pp;
    auto s=ss;

    int nbext=0;
    vector<unsigned char> enc;
    unsigned char mac[32];

    if(s<20 || !isnull(p,20))
      goto p_intro2_err;
    s-=20;p+=20;
    if(s<1 || p[0]!=2)
      goto p_intro2_err;
    s--;p++;
    if(s<2 || p[0]!=0 || p[1]!=32) 
      goto p_intro2_err;
    s-=2;p+=2;

    if(s<32)
      goto p_intro2_err;

    //assert(match(mat->auth_key,p,32));
    //memcpy(mat->auth_key,p,32);
    if(!match(p,intro_keys->auth.public_key,32)) goto p_intro2_err;
    
    s-=32;p+=32;

    if(s<1)
      goto p_intro2_err;
    nbext=p[0];
    s--;p++;

    for(int i=0;i<nbext;i++) {
      if(s<2)
	goto p_intro2_err;
      int l=p[1];
      s-=2+l;p+=2+l;
    }

    //encrypted part:

    if(s<32) 
      goto p_intro2_err;

    
    memcpy(mat->public_key,p,32);
    s-=32;p+=32;
    
    if(s<32) 
      goto p_intro2_err;


    mbedtls_cipher_context_t cipher_ctx;
    
    {
      enc.resize(s-32);
      memcpy(enc.data(),p,s-32);
      memcpy(mac,p+s-32,32);
      
      LOG_DEBUG("process intro2 mac ",mac,32);

      const char *protoid="tor-hs-ntor-curve25519-sha3-256-1";
      
      const char *t_hsenc_    = ":hs_key_extract";
      //const char *t_hsverify_ = ":hs_verify";
      //const char *t_hsmac_    = ":hs_mac";
      const char *m_hsexpand_ = ":hs_key_expand";

      //x=(rdv_material.)private_key
      //B=exp([9],b)
      //EXP(B,x)==exp([9],b*x) == exp(public_key,b)

      //hs_keys = KDF(intro_secret_hs_input | t_hsenc | info, S_KEY_LEN+MAC_LEN)
      //intro_secret_hs_input = EXP(B,x) | AUTH_KEY | X | B | PROTOID
      //info = m_hsexpand | subcredential

      vector<unsigned char> secret_hs_input;
      unsigned char tmp[32];

      //public_key=exp([9],x);  
      //EXP(B,x) = exp(public_key,b);
      LOG_DEBUG("public_key ",mat->public_key, 32);

      c25519_smult(tmp, mat->public_key, mat->intro_keys->enc.secret_key);

      append(secret_hs_input,tmp,32);

      //assert(match(mat->auth_key,mat->intro_keys->auth.public_key,32));
      append(secret_hs_input,intro_keys->auth.public_key,32);
      append(secret_hs_input,mat->public_key,32); // X

      //append(secret_hs_input,mat->intro_node->enc_key_c, 32); //B
      c25519_smult(tmp, c25519_base_x, intro_keys->enc.secret_key);
      append(secret_hs_input,tmp, 32); //B

      append(secret_hs_input, protoid);

      append(secret_hs_input, protoid);
      append(secret_hs_input, t_hsenc_);
      append(secret_hs_input, protoid);

      append(secret_hs_input, m_hsexpand_);
      append(secret_hs_input, intro_keys->subcred,32);

      //int dl=64;//S_KEY_LEN+MAC_LEN;

    
      sha3_ctx_t ctx;
      shake256_init(&ctx);

      LOG_DEBUG("secret_hs_input : ",secret_hs_input.data(),secret_hs_input.size());

      shake_update(&ctx,secret_hs_input.data(),secret_hs_input.size());

      shake_xof(&ctx);               // switch to extensible output

      unsigned char derived[64];
      shake_out(&ctx, derived, 64); 

      LOG_DEBUG("derived keys : ",derived,64);

      unsigned char ENC_KEY[32];
      unsigned char MAC_KEY[32];
      memcpy(ENC_KEY,derived,32);
      memcpy(MAC_KEY,derived+32,32);

      //unsigned char MAC[32];
      unsigned char cmac[32];
      
      MAC_SHA3(cmac,MAC_KEY,32,pp,ss-32);
      
      LOG_DEBUG("comp MAC ",cmac,32);

    
      mbedtls_cipher_init( &cipher_ctx );
      auto cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CTR);
      assert(cipher_info);

      if(!match(mac,cmac,32)) goto p_intro2_err;

      
      int r=0;
      r=r || mbedtls_cipher_setup( &cipher_ctx, cipher_info);
      r=r || mbedtls_cipher_setkey( &cipher_ctx,ENC_KEY,256,MBEDTLS_ENCRYPT);
    
      unsigned char zeroiv[16];
      memset(zeroiv,0,16);
      r=r || mbedtls_cipher_set_iv( &cipher_ctx, zeroiv, 16 );

      size_t ol=enc.size();
      int k=0;
      while(enc.size()%16) {k++;enc.push_back(0);}
      if(k) printf("added %d pad bytes before decrypt\n",k);
      auto rr=mbedtls_cipher_update( &cipher_ctx, enc.data(), enc.size(), enc.data(), &ol );
      if(r && rr) {
	char bf[128];
	mbedtls_strerror(rr, bf, 127);
	LOG_WARN("mbedtls error %s\n",bf);
      }
      r=r || rr;
      assert(ol==enc.size());
      while(k>0) {k--;enc.pop_back();}

      /*
	RENDEZVOUS_COOKIE                          [20 bytes]
	N_EXTENSIONS                               [1 byte]
	N_EXTENSIONS times:
	EXT_FIELD_TYPE                         [1 byte]
	EXT_FIELD_LEN                          [1 byte]
	EXT_FIELD                              [EXT_FIELD_LEN bytes]
	ONION_KEY_TYPE                             [1 bytes]//   The ONION_KEY_TYPE field is:      [01] NTOR:          ONION_KEY is 32 bytes long.
	ONION_KEY_LEN                              [2 bytes]
	ONION_KEY                                  [ONION_KEY_LEN bytes]
	NSPEC      (Number of link specifiers)     [1 byte]
	NSPEC times:
	LSTYPE (Link specifier type)           [1 byte]
	LSLEN  (Link specifier length)         [1 byte]
	LSPEC  (Link specifier)                [LSLEN bytes]
	PAD        (optional padding)              [up to end of plaintext]
      */

      LOG_DEBUG("dec ",enc.data(),enc.size());

      unsigned char *p2=enc.data();
      int s2=enc.size();
      if(s2<20) goto  p_intro2_err;
      memcpy(mat->rdvc,p2,20);
      p2+=20;s2-=20;
      if(s2<1) goto  p_intro2_err;
      nbext=p2[0];
      printf("nb ext %d\n",nbext);
      s2--;p2++;
      
      for(int i=0;i<nbext;i++) {
	if(s2<2)
	  goto p_intro2_err;
	int l=p2[1];
	printf("ext %d l=%d\n",i,l);
	s2-=2+l;p2+=2+l;
      }
      if(s2<3) goto  p_intro2_err;
      if(p2[0]!=1 ||p2[1]!=0||p2[2]!=32) goto  p_intro2_err;
      s2-=3;p2+=3;
      memcpy(mat->node.ntor,p2,32);
      p2+=32;s2-=32;
      if(!mat->node.decode_link_specifier(p2,s2)) goto  p_intro2_err;

    }      

    mbedtls_cipher_free( &cipher_ctx );
    //p_intro2_ok:
    printf("process_intro2 ok\n");
    return mat;
    
  p_intro2_err:
    mbedtls_cipher_free( &cipher_ctx );
    delete mat;
    return 0;
  }

  void construct_intro1(vector<unsigned char> &payload,intro_node_t &intro_node,info_node_t &rdv_node,rdv_material_t &rdv_material) {
    /*
            LEGACY_KEY_ID               [20 bytes] //all zeroes for new style
            AUTH_KEY_TYPE               [1 byte] // Ed25519 public key [02]
            AUTH_KEY_LEN                [2 bytes] //32
            AUTH_KEY                    [AUTH_KEY_LEN bytes]
            N_EXTENSIONS                [1 bytes]
            N_EXTENSIONS times:
               EXT_FIELD_TYPE           [1 byte]
               EXT_FIELD_LEN            [1 byte]
               EXT_FIELD                [EXT_FIELD_LEN bytes]
            ENCRYPTED:
               CLIENT_PK                [PK_PUBKEY_LEN bytes]
               ENCRYPTED_DATA           [Padded to length of plaintext]
               MAC                      [MAC_LEN bytes]

    */
    for(int i=0;i<20;i++)
      payload.push_back(0x0);

    // Append the size
    payload.push_back(2);
    payload.push_back(0);
    payload.push_back(32);

    LOG_DEBUG("auth_key",intro_node.auth_key,32);

    memcpy(rdv_material.AUTH_KEY,intro_node.auth_key,32);
    memcpy(rdv_material.B,intro_node.enc_key_c,32);

    append(payload,intro_node.auth_key,32);

    payload.push_back(0); //nb ext

    {
      vector<unsigned char> encrypted;
      /*
      
	RENDEZVOUS_COOKIE                          [20 bytes]
	N_EXTENSIONS                               [1 byte]
	N_EXTENSIONS times:
	EXT_FIELD_TYPE                         [1 byte]
	EXT_FIELD_LEN                          [1 byte]
	EXT_FIELD                              [EXT_FIELD_LEN bytes]
	ONION_KEY_TYPE                             [1 bytes]//   The ONION_KEY_TYPE field is:      [01] NTOR:          ONION_KEY is 32 bytes long.
	ONION_KEY_LEN                              [2 bytes]
	ONION_KEY                                  [ONION_KEY_LEN bytes]
	NSPEC      (Number of link specifiers)     [1 byte]
	NSPEC times:
	LSTYPE (Link specifier type)           [1 byte]
	LSLEN  (Link specifier length)         [1 byte]
	LSPEC  (Link specifier)                [LSLEN bytes]
	PAD        (optional padding)              [up to end of plaintext]
      */

      append(encrypted,rdv_material.rdvc,20);

      encrypted.push_back(0);
      encrypted.push_back(1);
      encrypted.push_back(0);
      encrypted.push_back(32);

      append(encrypted,rdv_node.ntor,32); //ONION_KEY used to connect to rendezvous node

      auto ls=rdv_node.gen_link_specifier();
      append(encrypted,ls);

      //todo encrypt
      /*
	The PROTOID for this variant is "tor-hs-ntor-curve25519-sha3-256-1".
	We also use the following tweak values:
	const char* protoid="tor-hs-ntor-curve25519-sha3-256-1";

	t_hsenc    = PROTOID | ":hs_key_extract"
	t_hsverify = PROTOID | ":hs_verify"
	t_hsmac    = PROTOID | ":hs_mac"
	m_hsexpand = PROTOID | ":hs_key_expand"

	To make an INTRODUCE1 cell, the client must know a public encryption
	key B for the hidden service on this introduction circuit. The client
	generates a single-use keypair:

	x,X = KEYGEN()

	and computes:

	intro_secret_hs_input = EXP(B,x) | AUTH_KEY | X | B | PROTOID
	info = m_hsexpand | subcredential
	hs_keys = KDF(intro_secret_hs_input | t_hsenc | info, S_KEY_LEN+MAC_LEN)
	ENC_KEY = hs_keys[0:S_KEY_LEN]
	MAC_KEY = hs_keys[S_KEY_LEN:S_KEY_LEN+MAC_KEY_LEN]

	and sends, as the ENCRYPTED part of the INTRODUCE1 cell:

	CLIENT_PK                [PK_PUBKEY_LEN bytes]
	ENCRYPTED_DATA           [Padded to length of plaintext]
	MAC                      [MAC_LEN bytes]


	Substituting those fields into the INTRODUCE1 cell body format
	described in [FMT_INTRO1] above, we have
      */
      const char *protoid="tor-hs-ntor-curve25519-sha3-256-1";
      
      const char *t_hsenc_    = ":hs_key_extract";
      //const char *t_hsverify_ = ":hs_verify";
      //const char *t_hsmac_    = ":hs_mac";
      const char *m_hsexpand_ = ":hs_key_expand";

      random_tab(rdv_material.private_key,32);

      ed25519_prepare(rdv_material.private_key);
      c25519_smult(rdv_material.public_key, c25519_base_x, rdv_material.private_key);
      LOG_DEBUG("pub_key ",rdv_material.public_key,32);

      
      //hs_keys = KDF(intro_secret_hs_input | t_hsenc | info, S_KEY_LEN+MAC_LEN)
      //intro_secret_hs_input = EXP(B,x) | AUTH_KEY | X | B | PROTOID
      //info = m_hsexpand | subcredential
      vector<unsigned char> secret_hs_input;


      unsigned char tmp[32];
      //EXP(B,x)
      c25519_smult(tmp, intro_node.enc_key_c, rdv_material.private_key);

      append(secret_hs_input,tmp,32);
      append(secret_hs_input,intro_node.auth_key,32);
      append(secret_hs_input,rdv_material.public_key,32); // X
      append(secret_hs_input,intro_node.enc_key_c, 32); //B
      append(secret_hs_input, protoid);

      append(secret_hs_input, protoid);
      append(secret_hs_input, t_hsenc_);
      append(secret_hs_input, protoid);

      append(secret_hs_input, m_hsexpand_);
      append(secret_hs_input, intro_node.subcred,32);

      int dl=64;//S_KEY_LEN+MAC_LEN;

      /* * Instantiate KDF with SHAKE-256. */
      
      sha3_ctx_t ctx;
      shake256_init(&ctx);

      LOG_DEBUG("secret_hs_input : ",secret_hs_input.data(),secret_hs_input.size());
      
      shake_update(&ctx,secret_hs_input.data(),secret_hs_input.size());

      shake_xof(&ctx);               // switch to extensible output

      unsigned char derived[dl];
      shake_out(&ctx, derived, dl); 

      LOG_DEBUG("derived keys : ",derived,dl);

      unsigned char ENC_KEY[32];
      unsigned char MAC_KEY[32];
      memcpy(ENC_KEY,derived,32);
      memcpy(MAC_KEY,derived+32,32);

      unsigned char MAC[32];

      mbedtls_cipher_context_t cipher_ctx;

      mbedtls_cipher_init( &cipher_ctx );
      auto cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CTR);
      assert(cipher_info);
      
      int r=0;
      r=r || mbedtls_cipher_setup( &cipher_ctx, cipher_info);
      r=r || mbedtls_cipher_setkey( &cipher_ctx,ENC_KEY,256,MBEDTLS_ENCRYPT);

      unsigned char zeroiv[16];
      memset(zeroiv,0,16);
      r=r || mbedtls_cipher_set_iv( &cipher_ctx, zeroiv, 16 );
      while(encrypted.size()%16) encrypted.push_back(0); 
      size_t ol=0;
      r=r || mbedtls_cipher_update( &cipher_ctx, encrypted.data(), encrypted.size(), encrypted.data(), &ol );
      assert(ol==encrypted.size());
      
      append(payload,rdv_material.public_key,32);

      append(payload,encrypted.data(),encrypted.size());
      LOG_DEBUG("enc data ",encrypted.data(),encrypted.size());
      
      /*
	Instantiate MAC(key=k, message=m) with H(k_len | k | m),
        where k_len is htonll(len(k)).
      */
      // the message is the whole message (statring from the rendezvous cookie, with the encrypted payload


      MAC_SHA3(MAC,MAC_KEY,32,payload.data(),payload.size());

      append(payload,MAC,32);
      LOG_DEBUG("MAC ",MAC,32);

      mbedtls_cipher_free( &cipher_ctx );

    }

  }
  
  void intro1_protocol(intro_node_t &intro_node,info_node_t &rdv_node,rdv_material_t &rdv_material) {
    vector<unsigned char> payload;
    construct_intro1(payload,intro_node,rdv_node,rdv_material);

    write_data(cell_relay_command_t::RELAY_COMMAND_INTRODUCE1,payload, 0);
    
    printf("intro1 sent\n");
  }

  bool finish_hs_handshake(rdv_material_t &rdv_material,const unsigned char *payload,int payload_len) {
    if(payload_len<64) return 0;

    print("finish_hs_handshake payload ",payload,payload_len);

    
    /*
      The server's handshake reply is:

       SERVER_PK   Y                         [PK_PUBKEY_LEN bytes]
       AUTH        AUTH_INPUT_MAC            [MAC_LEN bytes]

      rend_secret_hs_input = EXP(Y,x) | EXP(B,x) | AUTH_KEY | B | X | Y | PROTOID
    */

    unsigned char Y[32];
    unsigned char AUTH[32];

    const char *protoid="tor-hs-ntor-curve25519-sha3-256-1";
    
    const char *t_hsenc_    = ":hs_key_extract";
    const char *t_hsverify_ = ":hs_verify";
    const char *t_hsmac_    = ":hs_mac";
    const char *m_hsexpand_ = ":hs_key_expand";

    memcpy(Y,payload,32);

    memcpy(AUTH,payload+32,32);

    print("got Y ",Y,32);
    print("got MAC/AUTH ",AUTH,32);
    
    
    vector<unsigned char> rend_secret_hs_input;
    unsigned char tmp[32];

    c25519_smult(tmp, Y, rdv_material.private_key);
    append(rend_secret_hs_input,tmp,32); //exp(Y,x)
    c25519_smult(tmp, rdv_material.B, rdv_material.private_key);
    append(rend_secret_hs_input,tmp,32); //exp(B,x)
    append(rend_secret_hs_input,rdv_material.AUTH_KEY,32);
    append(rend_secret_hs_input,rdv_material.B,32);
    append(rend_secret_hs_input,rdv_material.public_key,32); //X
    append(rend_secret_hs_input,Y,32);
    append(rend_secret_hs_input,protoid);

    print("rend_secret_hs_input ",rend_secret_hs_input.data(),rend_secret_hs_input.size());

    /*
      NTOR_KEY_SEED = MAC(ntor_secret_input, t_hsenc)
      verify = MAC(ntor_secret_input, t_hsverify)
      auth_input = verify | AUTH_KEY | B | Y | X | PROTOID | "Server"
      AUTH_INPUT_MAC = MAC(auth_input, t_hsmac)
    */

    /*
      Instantiate MAC(key=k, message=m) with H(k_len | k | m), H=SHA3_256
      where k_len is htonll(len(k)).
    */

    //void H_SHA3_256(unsigned char *out,const unsigned char *a,int la,const unsigned char *b=NULL,int lb=0,const unsigned char *c=NULL,int lc=0) {

    unsigned char NTOR_KEY_SEED[32];

    unsigned long long len=htonll(rend_secret_hs_input.size());
    H_SHA3_256(NTOR_KEY_SEED,(const unsigned char*)&len,8,rend_secret_hs_input.data(),rend_secret_hs_input.size(),(const unsigned char*)protoid,-1,(const unsigned char*)t_hsenc_,-1);
    print("NTOR_KEY_SEED ",NTOR_KEY_SEED,32);

    unsigned char verify[32];
    H_SHA3_256(verify,(const unsigned char*)&len,8,rend_secret_hs_input.data(),rend_secret_hs_input.size(),(const unsigned char*)protoid,-1,(const unsigned char*)t_hsverify_,-1);
    print("verify ",verify,32);

    vector<unsigned char> auth_input;
    append(auth_input,verify,32);
    append(auth_input,rdv_material.AUTH_KEY,32);
    append(auth_input,rdv_material.B,32);
    append(auth_input,Y,32);
    append(auth_input,rdv_material.public_key,32); //X
    append(auth_input,protoid);
    append(auth_input,"Server");

    unsigned char AUTH_INPUT_MAC[32];

    len=htonll(auth_input.size());
    H_SHA3_256(AUTH_INPUT_MAC,(const unsigned char*)&len,8,auth_input.data(),auth_input.size(),(const unsigned char*)protoid,-1,(const unsigned char*)t_hsmac_,-1);
        
    print("comp AUTH_INPUT_MAC ",AUTH_INPUT_MAC,32);

    /*
      Finally the client verifies that the received AUTH field of HANDSHAKE_INFO
      is equal to the computed AUTH_INPUT_MAC.
    */

    if(!match(AUTH,AUTH_INPUT_MAC,32)) return 0;

    /*
      The hidden service and its client need to derive crypto keys from the
      NTOR_KEY_SEED part of the handshake output. To do so, they use the KDF
      construction as follows:

      K = KDF(NTOR_KEY_SEED | m_hsexpand,    HASH_LEN * 2 + S_KEY_LEN * 2)

      The first HASH_LEN bytes of K form the forward digest Df; the next HASH_LEN
      bytes form the backward digest Db; the next S_KEY_LEN bytes form Kf, and the
      final S_KEY_LEN bytes form Kb.  Excess bytes from K are discarded.

      Subsequently, the rendezvous point passes relay cells, unchanged, from each
      of the two circuits to the other.  When Alice's OP sends RELAY cells along
      the circuit, it authenticates with Df, and encrypts them with the Kf, then
      with all of the keys for the ORs in Alice's side of the circuit; and when
      Alice's OP receives RELAY cells from the circuit, it decrypts them with the
      keys for the ORs in Alice's side of the circuit, then decrypts them with Kb,
      and checks integrity with Db.  Bob's OP does the same, with Kf and Kb
      interchanged.
    */

    sha3_ctx_t ctx;
    shake256_init(&ctx);
    
    shake_update(&ctx,NTOR_KEY_SEED,32);
    shake_update(&ctx,protoid,strlen(protoid));
    shake_update(&ctx,m_hsexpand_,strlen(m_hsexpand_));
    
    shake_xof(&ctx);               // switch to extensible output
    
    int dl= 32*2+ 2*32; //HASH_LEN * 2 + S_KEY_LEN * 2; //
    unsigned char derived[dl];
    shake_out(&ctx, derived, dl); 

    print("derived keys ",derived,128);
     
    memcpy(rdv_material.Df,derived,32);
    memcpy(rdv_material.Db,derived+32,32);
    memcpy(rdv_material.Kf,derived+64,32);
    memcpy(rdv_material.Kb,derived+96,32);

    rdv_material.init_sym();
    
    return 1;
  }

  bool connect_rendezvous(intro_material_t *intro_material ) {
    assert(intro_material);
    assert(intro_material->intro_keys);
    
    //cb_hs=cb;
    //arg_hs=arg;

    /*
      The server's handshake reply is:

       SERVER_PK   Y                         [PK_PUBKEY_LEN bytes]
       AUTH        AUTH_INPUT_MAC            [MAC_LEN bytes]

      rend_secret_hs_input = EXP(Y,x) | EXP(B,x) | AUTH_KEY | B | X | Y | PROTOID
    */

    // gen Y,Y
    unsigned char y[32];
    unsigned char Y[32];
    random_tab(y,32);
    //Y=exp([9],y)
    c25519_smult(Y,c25519_base_x,y);
    
    vector<unsigned char> payload;
    append(payload,intro_material->rdvc,20);
    append(payload,Y,32);
    
    //unsigned char Y[32];
    //unsigned char AUTH[32];

    //memcpy(Y,payload,32);
    //memcpy(AUTH,payload+32,32);

    const char *protoid="tor-hs-ntor-curve25519-sha3-256-1";
    
    const char *t_hsenc_    = ":hs_key_extract";
    const char *t_hsverify_ = ":hs_verify";
    const char *t_hsmac_    = ":hs_mac";
    const char *m_hsexpand_ = ":hs_key_expand";

    vector<unsigned char> rend_secret_hs_input;
    unsigned char tmp[32];

    //c25519_smult(rdv_material.public_key, c25519_base_x, rdv_material.private_key);

    c25519_smult(tmp, intro_material->public_key,y); //exp(Y,x) = exp([9],y*x) = exp(X,y)
    append(rend_secret_hs_input,tmp,32); 

    // B= [9]^ intro_node.enc_key_sec  exp(B,x)= ([9]^x)^intro_node.enc.sec
    c25519_smult(tmp, intro_material->public_key, intro_material->intro_keys->enc.secret_key);
    append(rend_secret_hs_input,tmp,32);

    append(rend_secret_hs_input,intro_material->intro_keys->auth.public_key,32); //AUTH_KEY
    
    append(rend_secret_hs_input,intro_material->intro_keys->enc.public_key_c,32); //B
    append(rend_secret_hs_input,intro_material->public_key,32); //X
    append(rend_secret_hs_input,Y,32); //Y
    append(rend_secret_hs_input,protoid);

    print("rend_secret_hs_input ",rend_secret_hs_input.data(),rend_secret_hs_input.size());
    
    /*
      NTOR_KEY_SEED = MAC(ntor_secret_input, t_hsenc)
      verify = MAC(ntor_secret_input, t_hsverify)
      auth_input = verify | AUTH_KEY | B | Y | X | PROTOID | "Server"
      AUTH_INPUT_MAC = MAC(auth_input, t_hsmac)
    */

    /*
      Instantiate MAC(key=k, message=m) with H(k_len | k | m), H=SHA3_256
      where k_len is htonll(len(k)).
    */

    //void H_SHA3_256(unsigned char *out,const unsigned char *a,int la,const unsigned char *b=NULL,int lb=0,const unsigned char *c=NULL,int lc=0) {

    unsigned char NTOR_KEY_SEED[32];

    unsigned long long len=htonll(rend_secret_hs_input.size());
    H_SHA3_256(NTOR_KEY_SEED,(const unsigned char*)&len,8,rend_secret_hs_input.data(),rend_secret_hs_input.size(),(const unsigned char*)protoid,-1,(const unsigned char*)t_hsenc_,-1);
    print("NTOR_KEY_SEED ",NTOR_KEY_SEED,32);

    unsigned char verify[32];
    H_SHA3_256(verify,(const unsigned char*)&len,8,rend_secret_hs_input.data(),rend_secret_hs_input.size(),(const unsigned char*)protoid,-1,(const unsigned char*)t_hsverify_,-1);
    print("verify ",verify,32);

    vector<unsigned char> auth_input;
    append(auth_input,verify,32);
    append(auth_input,intro_material->intro_keys->auth.public_key,32); //rdv_material.AUTH_KEY
    append(auth_input,intro_material->intro_keys->enc.public_key_c,32); //rdv_material.B
    append(auth_input,Y,32); //Y
    append(auth_input,intro_material->public_key,32); //X  =rdv_material.public_key
    append(auth_input,protoid);
    append(auth_input,"Server");

    unsigned char AUTH_INPUT_MAC[32];

    len=htonll(auth_input.size());
    H_SHA3_256(AUTH_INPUT_MAC,(const unsigned char*)&len,8,auth_input.data(),auth_input.size(),(const unsigned char*)protoid,-1,(const unsigned char*)t_hsmac_,-1);
        
    print("comp AUTH_INPUT_MAC ",AUTH_INPUT_MAC,32);

    append(payload,AUTH_INPUT_MAC,32);

    print("connect RDV payload ",payload.data(),payload.size());
    
    /*
      Finally the client verifies that the received AUTH field of HANDSHAKE_INFO
      is equal to the computed AUTH_INPUT_MAC.
    */

    //if(!match(AUTH,AUTH_INPUT_MAC,32)) return 0;

    /*
      The hidden service and its client need to derive crypto keys from the
      NTOR_KEY_SEED part of the handshake output. To do so, they use the KDF
      construction as follows:

      K = KDF(NTOR_KEY_SEED | m_hsexpand,    HASH_LEN * 2 + S_KEY_LEN * 2)

      The first HASH_LEN bytes of K form the forward digest Df; the next HASH_LEN
      bytes form the backward digest Db; the next S_KEY_LEN bytes form Kf, and the
      final S_KEY_LEN bytes form Kb.  Excess bytes from K are discarded.

      Subsequently, the rendezvous point passes relay cells, unchanged, from each
      of the two circuits to the other.  When Alice's OP sends RELAY cells along
      the circuit, it authenticates with Df, and encrypts them with the Kf, then
      with all of the keys for the ORs in Alice's side of the circuit; and when
      Alice's OP receives RELAY cells from the circuit, it decrypts them with the
      keys for the ORs in Alice's side of the circuit, then decrypts them with Kb,
      and checks integrity with Db.  Bob's OP does the same, with Kf and Kb
      interchanged.
    */

    sha3_ctx_t ctx;
    shake256_init(&ctx);
    
    shake_update(&ctx,NTOR_KEY_SEED,32);
    shake_update(&ctx,protoid,strlen(protoid));
    shake_update(&ctx,m_hsexpand_,strlen(m_hsexpand_));
    
    shake_xof(&ctx);               // switch to extensible output
    
    int dl= 32*2+ 2*32; //HASH_LEN * 2 + S_KEY_LEN * 2; //
    unsigned char derived[dl];
    shake_out(&ctx, derived, dl); 

    print("derived keys ",derived,128);

    assert(rdv_material==NULL);

    rdv_material=new rdv_material_t;
    
    memcpy(rdv_material->Db,derived,32);
    memcpy(rdv_material->Df,derived+32,32);
    memcpy(rdv_material->Kb,derived+64,32);
    memcpy(rdv_material->Kf,derived+96,32);

    rdv_material->init_sym();

    
    int stream_id=new_stream_id();
    write_data(cell_relay_command_t::RELAY_COMMAND_RENDEZVOUS1,payload.data(),payload.size(),stream_id);
    streams[stream_id];

    hs_circuit=1;

    return 1;
  }

  
  void establish_rendezvous(rdv_material_t &rdv_material) {

    this->rdv_material=&rdv_material;
    int stream_id=new_stream_id();
    write_data(cell_relay_command_t::RELAY_COMMAND_ESTABLISH_RENDEZVOUS,rdv_material.rdvc,20,stream_id);
    streams[stream_id];
  }

  int begin_dir(stream_callback_t cb=NULL) {
    int stream_id=new_stream_id();
    LOG_INFOVV("stream_id=%d\n",stream_id);
    if(stream_id==0) {
      LOG_SEVERE("stream_id = 0 !\n");
      return 0;
    }

    LOG_INFOVV("Sending RELAY_BEGIN_DIR cell\n");
    
    streams[stream_id].init(this,stream_id);

    streams[stream_id].set_ncb(cb);
    
    LOG_INFOVV("start StreamID is %04X.\n", stream_id);

    vector<unsigned char> payload; //empty, only zeros with autopading

    if (!write_data(cell_relay_command_t::RELAY_BEGIN_DIR,payload, stream_id)) {
      LOG_WARN("error on writing request.\n");
    }

    return stream_id;
  }
  
  int stream_resolve(const string& hostname) {
    int stream_id=new_stream_id();
    LOG_INFOVV("stream_id=%d\n",stream_id);
    if(stream_id==0) {
      LOG_SEVERE("stream_id = 0 !\n");
      return 0;
    }

    /*
      To find the address associated with a hostname, the OP sends a
      RELAY_RESOLVE cell containing the hostname to be resolved with a NUL
      terminating byte. (For a reverse lookup, the OP sends a RELAY_RESOLVE
      cell containing an in-addr.arpa address.)
    */

    LOG_INFOVV("Sending RELAY_RESOLVE cell for hostname <%s>.\n", hostname.c_str());
    
    vector<unsigned char> payload;
    
    for (const char& c: hostname)
      payload.push_back(c);
    payload.push_back(0x00); // NUL terminating byte

    streams[stream_id].init(this,stream_id);
    
    if (!write_data(cell_relay_command_t::RELAY_RESOLVE,payload, stream_id)) {
      LOG_WARN("error on writing request.\n");
    }

    return stream_id;
  }

  
  
  int resolve(const string& hostname, in_addr &resolved,int timelimit=10*1000) { //timelimit in ms
    int i=stream_resolve(hostname);
    if(i==0) {
      LOG_SEVERE("stream_id = 0 \n");
      return 0;
    }
    int r=0;
    for(int u=0;u<timelimit;u+=10) {
      if(streams[i].got_resolved) {
	LOG_INFOV("resolve done\n");
	if(streams[i].resolve_ok) {
	  memcpy(&resolved,&(streams[i].resolved),sizeof(resolved));
	  r=1;
	} 
	remove_stream(i);
	return r;
      }
      usleep(10000);
    }
    remove_stream(i);
    return 0;
  }

  void print_circuit_info() {
    string s;
    for(int i=0;i<Nnodes;i++) {
      if(nodes[i]==NULL) s+=string("NULL");
      else {
	s+=nodes[i]->short_info();
      }
      s+=string(" <-> ");
    }
    s+=string("web");

    LOG_INFO("Circuit: | bs=%d | %s\n",build_status,s.c_str());
  }

};
  

bool fill_nodes(circuit_t *tc,info_node_t *exit=NULL) {
  mutex_dir.lock();

  int tofill=tc->Nnodes;
  if(exit) tofill--;
    
  for(int i=0;i<tofill;i++) {
    int ii=0;
    if(i) {
      if(i+1!=tc->Nnodes)
	ii=1;
      else {
	ii=2;
      }
    }

    
#ifdef DIR_LOWMEM
    small_random_set_t sr(MAX_NODES);
    while(1) {
      if(sr.empty()) {
	break;
      }
      int r=sr.pick();
      assert(r>=0 && r<MAX_NODES);
      if(relays.nodes[ii][r].is_ok()==0) continue;
      tc->nodes[i]=new relay_t(relays.nodes[ii][r]);
      break;
    }
#endif

#ifndef DISABLE_CACHE
    random_set_t sr(CACHE_SIZE);
    while(1) {
      if(sr.empty()) {
	printf("random set is empty in fill_nodes ... (with cache)\n");
	break;
      }
      int r=sr.pick();
      assert(r>=0 && r<16384);
	
      if(cache_descs[r].is_ok()==0) continue;
      if(cache_descs[r].in_consensus()==0) continue;
      if(ii==0 && cache_descs[r].can_be_guard()==false) continue;
      if(ii==2 && cache_descs[r].can_be_exit()==false) continue;
      if(ii==1 && cache_descs[r].can_be_middle()==false) continue;
      tc->nodes[i]=new relay_t(cache_descs[r]);
      break;
    }
#endif
    if(tc->nodes[i]) {
      //tc->nodes[i]->print_info();
    } else {
      printf("no node found in fill_nodes ! i=%d \n",i);
      mutex_dir.unlock();
      return 0;
    }
  }
  if(exit) {
    tc->nodes[tofill]=new relay_t(*exit);
    //tc->nodes[tofill]->print_info();
  }
  //printf("==========\n");
  mutex_dir.unlock();
  return 1;
}

circuit_t *gen_working_circuit(info_node_t *exit,int max=30,int max2=3) {
  circuit_t *tc=NULL;
  int j=0;
  for(int i=0;i<max && j<max2 && tc==NULL;) {
    tc=new circuit_t("gen_working_circuit");
    j++;
    int r=fill_nodes(tc,exit);
    if(!r) {
      if(tor_dbg>0)
	printf("fill_nodes fails, waits...\n");
      delete tc;
      tc=NULL;
      sleep(1);
      continue;
    }
    tc->print_circuit_info();
    tc->build_circuit();
    if(tc->firstconnection)
      i++;
    if(tc->build_status!=circuit_t::BS_BUILT) {
      delete tc;
      //sleep ?
      tc=NULL;
    }
  }
  return tc;
}

circuit_t *gen_working_circuit(int m=30) {
  return gen_working_circuit(NULL,m,m);
}


#define SOCK_CONNECT_TOR_BUILD -51
#define SOCK_CONNECT_TOR_NOT_BUILT -52
#define SOCK_CONNECT_TOR_STREAM_TIMEOUT -53
#define SOCK_CONNECT_TOR_STREAM_START -54
#define SOCK_CONNECT_TOR_RESOLVE -55

class socket_tor_t : public socket_t {
  bool resources_ready=0;
  bool manage_circuit=1;
  int stream_id=0;
  circuit_t *tc=NULL;
  cvector_t<unsigned char,4096> *buff;

  void log(const char *file,const char *fn,int line,int lvl, const char* format, ... )
  {
    if(lvl>dbg) return;
    va_list arglist;
    
    printf("[%s][socket_tor %p :: %s:%d] ",loglvlstr[lvl],this,fn,line);
    va_start( arglist, format );
    vprintf( format, arglist );
    va_end( arglist );
  }

public:  
  relay_t* get_exit_node() {
    if(tc==NULL) return NULL;
    return tc->get_exit_node();
  }
  socket_tor_t() {
  }

  socket_tor_t(circuit_t *tc2) {
    tc=tc2;
    manage_circuit=0;
  }

  bool setup_dir(circuit_t *tc2,int sid) {
    assert(tc2);
    assert(sid);

    tc=tc2;
    manage_circuit=0;
    stream_id=sid;

    setup_resources();

    if(tc->build_status!=circuit_t::BS_BUILT) {
      LOG_WARN("setup_dir: circuit not built !\n");
      return 0;
    }

    return 1;
  }

  ~socket_tor_t() {
    if(tc && stream_id>0) {
      tc->streams[stream_id].finish();
      tc->streams[stream_id].set_ncb(NULL);
    }
    release_resources();
  }
  
  bool is_connected() const {
    if(tc==NULL || tc->build_status!=circuit_t::BS_BUILT) return false;
    if(stream_id==0) return false;
    if(tc->streams[stream_id].finished) return false;
    if(tc->streams[stream_id].connected==false) return false;
    return true;
  }

  void setup_resources(info_node_t *exit=NULL) {
    if(resources_ready) 
      release_resources();

    buff=new cvector_t<unsigned char,4096>();
    
    if(manage_circuit) {
      tc=gen_working_circuit(exit);
    } else {
      assert(exit==NULL);
    }
    
    resources_ready = true;
  }

  void release_resources() {
    if(manage_circuit && tc) {
      tc->destroy_circuit();
      delete tc;
      tc=NULL;
    }

    delete buff;
    buff=NULL;
    
    resources_ready = false;
  }

  mutex_t mut;
  condvar_t cond_write,cond_read;

  void callback(const unsigned char *t,int l)
  {
    assert(buff);
    if(t==NULL) { //special
      if(l==CB_RELAY_END) {//end of connection
	cond_write.broadcast();
	return;
      }
      if(l==CB_RELAY_BEGIN) { //connected
	cond_connected.broadcast();
	return;
      }
      ::LOG_FATAL("special not handled...\n");
      assert(0);
    }
    mut.lock();
    while(buff->left()<l)
      cond_read.wait(mut);
      
    buff->push_back(t,l);
    cond_write.broadcast();
    mut.unlock();
  }


  condvar_t cond_connected;
  mutex_t mut_connected;

  int wait_connected(int to=10*1000) {
    mut_connected.lock();
    while(1) {
      int r=cond_connected.timedwait(mut_connected,to);
      if(!r) {
	mut_connected.unlock();
	return 0;
      }
      if(tc->streams[stream_id].connected==false) continue;
      break;
    }
    mut_connected.unlock();
    return 1;
  }

  int connect_dir_and_wait(info_node_t *n) {
    assert(n);
    assert(manage_circuit);
    setup_resources(n);

    if(tc==NULL || tc->build_status!=circuit_t::BS_BUILT) {
      LOG_WARN("circuit not built\n");
      return SOCK_CONNECT_TOR_BUILD;
    }

    stream_id=tc->begin_dir(std::bind(&socket_tor_t::callback,this,std::placeholders::_1,std::placeholders::_2));

    if(stream_id==0) {
      LOG_WARN("begin_dir fail\n");
      return SOCK_CONNECT_TOR_STREAM_START;
    }
    
    return wait_connected(10*1000);
  }
  
  int accept() {
    setup_resources();
    assert(0==manage_circuit);
    if(tc->build_status!=circuit_t::BS_BUILT) {
      LOG_WARN("circuit not built\n");
      return SOCK_CONNECT_TOR_NOT_BUILT;
    }
    stream_id=tc->accept(std::bind(&socket_tor_t::callback,this,std::placeholders::_1,std::placeholders::_2));

    if(stream_id<=0) return 0;

    return 1;
  }
    
  int connect(const string &host, const short port) {
    setup_resources();

    if(manage_circuit) {

    } else {
      if(tc->build_status!=circuit_t::BS_BUILT) {
	LOG_WARN("circuit not built\n");
	return SOCK_CONNECT_TOR_NOT_BUILT;
      }
    }

    if(host.size() && !is_ipv4_address(host)) {
      LOG_INFOVV("resolve...\n");
      in_addr res;
      auto r=tc->resolve(host,res);
      if(!r) {
	LOG_WARN("resolve fail\n");
	return SOCK_CONNECT_TOR_RESOLVE;
      }
      LOG_INFOVV("resolve ok\n");
      stream_id=tc->stream_start(res, port,std::bind(&socket_tor_t::callback,this,std::placeholders::_1,std::placeholders::_2));
    }
    else {
      stream_id=tc->stream_start("", port,std::bind(&socket_tor_t::callback,this,std::placeholders::_1,std::placeholders::_2));
    }

    if(stream_id==0) {
      LOG_WARN("stream_start fail\n");
      return SOCK_CONNECT_TOR_STREAM_START;
    }
    
    return wait_connected(10*1000);
  }

  void disconnect() {

  }

  int write(const unsigned char *data,int len) {
    int o=len;

    LOG_DEBUG("sock_tor : write %d\n",len);
    
    while(len) {
      int l=len;
      if(len>480) l=480;
      tc->stream_send(stream_id,data,l);
      data+=l;
      len-=l;
    }

    return o;
  }

  virtual int read(unsigned char *data,int maxlen) {
    LOG_DEBUG("sock_tor : read maxlen: %d timeout=%d\n",maxlen,timeout);

    int re=0;
    assert(buff);
    unsigned long long st=timer_get_ms();
    mut.lock();

    while(1) {
      re=buff->read(data,maxlen);
      LOG_DEBUG("buff->read re=%d\n",re);
      assert(re>=0);
      if(re) {
	mut.unlock();
	cond_read.broadcast();
	return re;
      }
      
      assert(re==0);
      if(tc->streams[stream_id].connected==false || tc->streams[stream_id].finished) {
	mut.unlock();
	LOG_DEBUG("sock_tor ret SOCK_CLOSED connected=%d finished=%d\n",tc->streams[stream_id].connected,tc->streams[stream_id].finished);
	return SOCK_CLOSED;
      }
      long long t=timer_get_ms()-st;
      t=timeout-t;
      LOG_DEBUG("sock_tor read timeleft %d\n",int(t));
      if(t<=0) {
	LOG_DEBUG("ret timeout\n");
	mut.unlock();
	return SOCK_TIMEOUT;
      }
      
      cond_write.timedwait(mut,t);
      //LOG_DEBUG("wait data... re=%d t=%d %d\n",re,t,get_timeout());
    }
      
    return re;
  }

  virtual int write(const string &s) {
    return write((const unsigned char*)s.c_str(),s.size());
  }

};

string get_tor_ip(const string &host) {
  socket_tor_t *sock=new socket_tor_t();
  sock->set_timeout(10*1000+43);
  auto r=get_ip(host,sock,80);
  delete sock;
  return r;
}


string get_tor_ip_tls(const string &host) {
  socket_tor_t *stor=new socket_tor_t();
  socket_tls_t *stls=new socket_tls_t();
  stls->set_timeout(10*1000+44);
  stor->set_timeout(10*1000+45);
  stls->setsock(*stor);
  
  stor->connect(host,443); //todo check error
  stls->connect(host,443); //todo check error
  
  printf("connected\n");
  auto r=get_ip_2(host,stls);
  delete stls;
  delete stor;
  return r;
}

mutex_t mut_dead_circuits;
set<circuit_t*> dead_circuits;

void clean_delete_circuit(circuit_t *tc)
{
  LOG_DEBUG("clean_delete_circuit(%p)\n",tc);
  if(!tc) return;
  mut_dead_circuits.lock();
  dead_circuits.insert(tc);
  mut_dead_circuits.unlock();
}

void clean_delete_circuit()
{
  LOG_DEBUGV("clean_delete_circuit()...\n");
  mut_dead_circuits.lock();
  for(auto &it:dead_circuits) {
    delete it;
  }
  dead_circuits.clear();
  mut_dead_circuits.unlock();
}


struct circuits_t {
  enum status_t {
    NONE,
    WAIT,

    OK_CONNECTED,
    OK_JOB,

    FAIL_CONNECTED_EARLY,
    FAIL_CONNECTED,
    FAIL_JOB,

    DESTROYED,
  } ;

  virtual bool is_working() const {
    for(auto &it:circuits)
      if(it->status==WAIT) return 1;
    return 0;
  }

  string name="noname";

  struct cs_t {
#ifdef MEMDBG
    void * operator new(size_t size)
    {
      void * p = malloc(size);
      _mn[p]=size;
      printf("*** cs_t::new %p size=%d\n",p,int(size));
      return p;
    }
    
    void operator delete(void * p)
    {
      auto size=_mn[p];
      printf("*** cs_t::delete %p size=%d\n",p,int(size));
      memset(p,0x42,size);
      _mn.erase(p);
      //free(p);
    }
#endif
    int cbs=0;

    void clear() {
      cbs=0;
      exit=0;
      status=NONE;
      tc=NULL;
      i=0;j=0;
    }
    
    circuits_t *ptrcircuits=NULL;
    int k=-1;
    info_node_t *exit=NULL;
    status_t status=NONE;
    circuit_t *tc=NULL;
    int i=0,j=0; //tries

    ~cs_t() {
      LOG_INFOV("~circuits_t():cs %p\n",this);
    }
    
    cs_t(int kk) {
      LOG_INFOV("circuits_t():cs %p kkid=%d\n",this,kk);
      k=kk;
    }

    
    circuit_t * gen() {
      auto otc=tc;
      char tmp[20];
      snprintf(tmp,19," id=%d ",k);
      tc=new circuit_t("circuits gen "+ptrcircuits->name+string(tmp));

      LOG_INFOV("circuits_t():cs::gen %p kid=%d tc=%p->%p\n",this,k,otc,tc);
      j++;
      int r=fill_nodes(tc,exit);
      if(!r) {
	LOG_INFO("circuits_t::cs %p kid=%d fill_nodes fails...\n",this,k);
	status=FAIL_CONNECTED_EARLY;
	ptrcircuits->done(k,status);
	delete tc;
	tc=NULL;
      } else {
	LOG_INFO("circuits_t::cs %p kid=%d trying to build circuit tc=%p :\n",this,k,tc);
	tc->print_circuit_info();

	tc->set_ncb(std::bind(&circuits_t::callback,ptrcircuits,this,std::placeholders::_1));
	
	r=tc->async_build_circuit();
	if(r==0) {
	  LOG_INFOVV("circuits_t::cs %p kid=%d async_build_circuit FAIL\n",this,k);
	  status=FAIL_CONNECTED_EARLY;
	  ptrcircuits->done(k,status);
	  delete tc;
	  tc=NULL;
	}
      }
      
      return tc;
    }

    void print() const {
      LOG_INFO("curcuit %p (p:%p) status:%d\n",tc,ptrcircuits,int(status));
    }
  };
  
  virtual void done(int i,int ok) {
    circuits[i]->cbs=ok;
  }

  void print() const {
    LOG_INFO("circuits %p:\n",this);
    for(auto &it:circuits)
      it->print();
  }
  
  vector<cs_t*> circuits;
  
  int max=30;
  int max2=3;
    
  void destroy_all() {
    for(auto &it:circuits) {
      if(it->tc)
	delete it->tc;
    }
  }

  void callback(cs_t *cs,cb_t l) {
    LOG_DEBUG("CB in circuits_t %p cs_t %p kid=%d cb %d\n",this,cs,cs->k,int(l));
    if(l==CB_CIRCUIT_BUILT_FAIL) {
      if(cs->tc) {
	cs->tc->set_ncb(NULL);
	clean_delete_circuit(cs->tc);
      }
      cs->tc=NULL;
      if(cs->i<max && cs->j<max2) {
	cs->gen();
      } else {
	cs->status=FAIL_CONNECTED;
	done(cs->k,cs->status);
      }
    } else if(l==CB_CIRCUIT_BUILT_OK) {
      cs->status=OK_CONNECTED;
      done(cs->k,cs->status);
    } else if(l==CB_DESTROY) {
      cs->status=DESTROYED;
      done(cs->k,cs->status);
    } else {
      never_here();
    }
  }

  void async_gen_working_circuit(int k,info_node_t *exit=NULL) {
    LOG_INFO("async_gen_working_circuit this=%p kid=%d exit=%p\n",this,k,exit);

    while(circuits.size()<=k)
      circuits.push_back(NULL);

    cs_t *cs=NULL;
    if(!circuits[k]) {
      cs=new cs_t(k);
      circuits[k]=cs;
    } else {
      cs=circuits[k];
      cs->clear();
    }

    if(circuits[k]->tc) {
      circuits[k]->tc->set_ncb(NULL);
      clean_delete_circuit(circuits[k]->tc);
    }
    circuits[k]->tc=NULL;
      
    
    cs->exit=exit;
    cs->status=WAIT;
    cs->ptrcircuits=this;
    
    cs->gen();
  }

  virtual ~circuits_t() {
    LOG_INFOV("~circuits_t() %p\n",this);
    for(auto &it:circuits) {
      if(it) {
	if(it->tc)
	  it->tc->set_ncb(NULL);
	clean_delete_circuit(it->tc);
	delete it;
      }
    }
  }
  
};

int publish_hs_descr(socket_t &sock,ip_info_node_t &dir,s_vc_t &a,ps_vector<char> &v)
{
  LOG_INFOV("upload hs descriptor \n");
  
  string req= "/tor/hs/3/publish";

  req=httppost(req,inet_ntoa(*(in_addr*)dir.ipv4),v.size());
  
  if(sock.write_string(req)==false) {
    LOG_WARN("sock.write_string fail\n");
    return DESCR_KO;
  }

  int n=sock.write((unsigned char *)v.data(),v.size());
    
  //write(1,v.data(),v.size());

  LOG_INFOV("sock.write rets %d /%d\n",n,int(v.size()));
  if(n!=v.size())
    return DESCR_KO;

  return DESCR_OK;
}

// int publish_hs_descr_and_wait(socket_t &sock,ip_info_node_t &dir,s_vc_t &a,ps_vector<char> &v)
// {
//   auto r=publish_hs_descr(sock,dir,a,v);
//   if(r!=DESCR_OK) return r;
  
//   char bf[128];
//   int httpcode=0;
//   newliner_t nl;
//   while(1) {
//     int r=sock.read((unsigned char*)bf,127);
//     if(r<0) {
//       LOG_WARN("r<0\n");
//       break;
//     }
//     if(r==0) break;
//     nl.update((char*)bf,r);

//     while((r=nl.read(bf,127))>0) {
//       bf[r]=0;
//       LOG_DEBUG("G %s",bf);
//       if(strncmp(bf,"HTTP/",5)==0) {
// 	auto c=cut(bf);
// 	if(c.size()>1) httpcode=atoi(c[1].c_str());
//       }
//     }
//   }

//   LOG_INFO("publish_hs_descr got http code %d\n",httpcode);

  
//   if(httpcode!=200) {
//     LOG_WARN("error got http code %d\n",httpcode);
//     return DESCR_KO;
//   }
  
//   return DESCR_OK;
// }

struct circuits_hsdirs_t : public circuits_t {
#ifdef MEMDBG
  void * operator new(size_t size)
  {
    void * p = malloc(size);
    _mn[p]=size;
    printf("**** circuits_hsdir_t::new %p size=%d\n",p,int(size));
    return p;
  }
    
  void operator delete(void * p)
  {
    auto size=_mn[p];
    printf("**** circuits_hsdir_t::delete %p size=%d\n",p,int(size));
    memset(p,0x44,size);
    _mn.erase(p);
    //free(p);
  }
#endif

  ps_vector<char> v;
  s_vc_t a;
  set<int> okid;
  map<int,int> mid;
  
  vector<unsigned short> ids;

  circuits_hsdirs_t(const vector<unsigned short> &ids_,int tp):a(v) {
    ids=ids_;
    char tmp[100];
    snprintf(tmp,100,"hsdir tp=%d",tp);
    name=tmp;
  }

  void publish() {
    LOG_INFO("publish...\n");
    int k=0;
    for(auto &ii:ids) {
      auto ex=&(cache_descs[ii]);
      mid[k]=ii;
      async_gen_working_circuit(k++,ex);
    }
  }
  
  map<int,socket_tor_t *> ms;
  
  virtual ~circuits_hsdirs_t() {
    LOG_INFOV("~circuits_hsdirs_t() %p\n",this);
    for(auto &it:ms) {
      delete it.second;
    }
  }
  
  void callback(int id,const unsigned char *t,int l)
  {
    auto tc=circuits[id]->tc;
    LOG_INFOVV("cb circuits_hsdirs_t id=%d t=%p l=%d tc=%p\n",id,t,l,tc);
    
    if(t==NULL) { //special
      if(l==CB_RELAY_END) {//end of connection
	LOG_INFOVV("cb circuits_hsdirs_t id=%d RELAY_END\n",id);

	if(circuits[id]->status!=OK_JOB)
	  circuits[id]->status=FAIL_JOB;
	return;
      }
      if(l==CB_RELAY_BEGIN) { //connected
	m.lock();
	auto it=ms.find(id);
	assert(it!=ms.end());
	socket_tor_t *s=it->second;
	publish_hs_descr(*s,*(s->get_exit_node()),a,v);
	m.unlock();
	return;
      }
      ::LOG_FATAL("special not handled...\n");
      assert(0);
    }

    LOG_INFOVV("cb circuits_hsdirs_t id=%d DATA len=%d \n",id,l);

    newliner_t nl;
    nl.update((const char*)t,l);

    int httpcode=0;

    char bf[128];
    int r;
    while((r=nl.read(bf,127))>0) {
      bf[r]=0;
      LOG_DEBUG("G %s",bf);
      if(strncmp(bf,"HTTP/",5)==0) {
	auto c=cut(bf);
	if(c.size()>1) httpcode=atoi(c[1].c_str());
      }
    }

    LOG_INFO("publish_hs_descr got http code %d id=%d orig_id=%d\n",httpcode,id,mid[id]);

    if(httpcode!=200) {
      LOG_WARN("error got http code %d\n",httpcode);
      circuits[id]->status=FAIL_JOB;
    } else {
      okid.insert(mid[id]);
      circuits[id]->status=OK_JOB;
    }

  }

  mutex_t m;

  virtual bool is_working() const {
    for(auto &it:circuits)
      if(it->status==WAIT || it->status==OK_CONNECTED) return 1;
    return 0;
  }

  virtual void done(int id,int ok) {
    if(ok==OK_CONNECTED) {
      LOG_INFOVV("circuits to hsdirs done %d OK\n",id,ok);
      auto tc=circuits[id]->tc;

      m.lock();
      //int sid=tc->begin_dir(scb,circuits[id]);
      int sid=tc->begin_dir(std::bind(&circuits_hsdirs_t::callback,this,id,std::placeholders::_1,std::placeholders::_2));

      socket_tor_t *s=new socket_tor_t();
      
      assert(ms.find(id)==ms.end());
      ms[id]=s;
      s->setup_dir(tc,sid);
      m.unlock();
    } else {
      LOG_WARN("circuits to hsdirs failed id=%d\n",id);
    }
  }
};

