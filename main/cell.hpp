#pragma once

#define MAX_CELL_SIZE 514 
#define PAYLOAD_LEN  509
#include <list>
using namespace std;

#include "tor_defs.hpp"

#include <sys/poll.h>

#include "poll.hpp"

int dbg_cell=DBGBASE;

bool isVariableLength(cell_command_t Command) {
  return (Command == cell_command_t::VERSIONS || static_cast<unsigned int>(Command) >= 128) ;
};
  

int expected_cell_size(int linkversion, bool circlen2, unsigned char *data,int len)
{
  LOG_DEBUGV("expectedsize lv:%d c2:%d len:%d payload:%s...\n",linkversion,circlen2,len,to_str(data,(len<32)?len:32).c_str());
  
  if(linkversion==1) circlen2=1;
  int circid=0;
  if(len<3) return -1;
  if(circlen2==0 &&len<5) return -1;
  int z=0;
  if(circlen2) {
    circid=toshort(data);
    z+=2;
  } else {
    circid=toint(data);
    z+=4;
  }
  cell_command_t cmd=(cell_command_t)data[z++];

  LOG_DEBUGV("expectedsize circid=%x : cmd=%d %s\n",circid,int(cmd),cell_command_str(cmd));

  if(isVariableLength(cmd)) {
    if(len-z<2) return -1;
    int l=toshort(data+z);
    z+=2;
    return z+l;
  }

  //fixed size
  if(linkversion<4) return 512;
  return 514;
}

struct cell_t {
protected:

  void log(const char *file,const char *fn,int line,int lvl, const char* format, ... )
  {
    if(lvl>dbg_cell) return;
    va_list arglist;
    
    printf("[%s][cell %p :: %s:%d] ",loglvlstr[lvl],this,fn,line);
    va_start( arglist, format );
    vprintf( format, arglist );
    va_end( arglist );
  }

public:
  virtual unsigned char *payload() =0;

  unsigned int circuit_id;
  unsigned short stream_id;
  unsigned char link_protocol_version;
  short size;
  cell_command_t command;
  cell_relay_command_t relay_command;

  virtual ~cell_t() {}

  int payload_size() const { return size;}
  
  virtual unsigned int maxsize() const =0;
  virtual const unsigned char *const_payload() const =0;
  unsigned char payload(int i) const {
    return const_payload()[i];
  }
  
  cell_t(const unsigned char& link_protocol_version_, const unsigned int& circid, const cell_command_t& command_) {
    size=0;
    link_protocol_version = link_protocol_version_;
    circuit_id = circid;
    command = command_;
    stream_id = -1;
  }

  bool push_back(const unsigned char& byte) {
    assert(size<maxsize());
    put1(payload()+(size++),byte);
    return true;
  }

  bool push_back_short(const unsigned short& what) {
    assert(size+1<maxsize());
    put_short(payload()+size,what);
    size+=2;
    return true;
  }

  bool push_back_int(const unsigned int& what) {
    assert(size+3<maxsize());
    put_int(payload()+size,what);
    size+=4;
    return true;
  }

  bool push_back(const unsigned char * what,int len) {
    assert(size+len<=maxsize());
    memcpy(payload()+size,what,len);
    size+=len;
    return true;
  }
  
  bool push_back(const vector<unsigned char> &what) {
    return push_back(what.data(),what.size());
  }

  void clear_payload() {
    size=0;
  }

  int get_header_size() {
    int sh=3;
    if (command == cell_command_t::VERSIONS || link_protocol_version < 4) {
    }
    else if (link_protocol_version >= 4) {
      sh+=2;
    }
    if (isVariableLength())
      sh+=2;
    return sh;
  }

  int sh=0;
  void prepare_send_cell() {
    sh=get_header_size();
    int z=-sh;
    if (command == cell_command_t::VERSIONS || link_protocol_version < 4) {
      put_short(payload()+z,circuit_id);
      z+=2;
    } else if (link_protocol_version >= 4) {
      put_int(payload()+z,circuit_id);
      z+=4;
    }

    put1(payload()+z,static_cast<unsigned char>(command));
    z++;
    
    if (isVariableLength()) {
      put_short(payload()+z,size);
      z+=2;
    }
    assert(z==0);

    //pad
    if (command == cell_command_t::VERSIONS || command == cell_command_t::AUTHORIZE) {
      
    } else if (command == cell_command_t::RELAY || command == cell_command_t::RELAY_EARLY) {
      // random pad
      // Modified ! the padding for relay cells is done in the PrepareAsRelayCell method
    } else {
      if(size<PAYLOAD_LEN)
	memset(payload()+size,0,PAYLOAD_LEN-size);
      size=PAYLOAD_LEN;
    }
  }

  bool send_cell_nomt(asocket_t &client) {
    prepare_send_cell();

    int r=client.write(payload()-sh,sh+size);
    return r==sh+size;
  }

  const char *command_str() const {
    return cell_command_str(command);
  }

  bool isVariableLength() {
    return ::isVariableLength(command);
  }

  unsigned short GetLinkProtocolFromVersionCell() {
    if (command != cell_command_t::VERSIONS || size < 2 || size % 2 != 0) 
      return 0;
		
    unsigned short highest = 0;
    for (int i = 0; i<size; i += 2) {
      unsigned short current = toshort(payload()+i);
      if (current > highest)
	highest = current;
    }
    
    return highest;
  }

  void create_netinfo(const struct in_addr& yourPublicIP) {
    /*
      The cell's payload is:
      TIME       (Timestamp)                     [4 bytes]
      OTHERADDR  (Other OR's address)            [variable]
      ATYPE   (Address type)                  [1 byte]
      ALEN    (Adress length)                 [1 byte]
      AVAL    (Address value in NBO)          [ALEN bytes]
      NMYADDR    (Number of this OR's addresses) [1 byte]
      NMYADDR times:
      ATYPE   (Address type)                 [1 byte]
      ALEN    (Adress length)                [1 byte]
      AVAL    (Address value in NBO))        [ALEN bytes]
    */
		
    clear_payload();
    command = cell_command_t::NETINFO;
    push_back_int(get_unix_time());

    /* [04] IPv4. [06] IPv6. */
    push_back(4); //Ipv4
    push_back(4); // size:4
    push_back((unsigned char*)&yourPublicIP.s_addr,4);
		
    /* NMYADDR , same infos ... */
    push_back(0x01);
    push_back(4);
    push_back(4);
    push_back((unsigned char*)&yourPublicIP.s_addr,4);
  }


  bool append_create2(relay_t& relay) {
    /*
      A CREATE2 cell contains:

      HTYPE     (Client Handshake Type)     [2 bytes]
      HLEN      (Client Handshake Data Len) [2 bytes]
      HDATA     (Client Handshake Data)     [HLEN bytes]
    */

    // Set HTYPE to 0x0002  ntor -- the ntor+curve25519+sha256 handshake; see 5.1.4
    push_back_short(2);

    /*
      This handshake uses a set of DH handshakes to compute a set of
      shared keys which the client knows are shared only with a particular
      server, and the server knows are shared with whomever sent the
      original handshake (or with nobody at all).  Here we use the
      "curve25519" group and representation as specified in "Curve25519:
      new Diffie-Hellman speed records" by D. J. Bernstein.

      In this section, define:

      H(x,t) as HMAC_SHA256 with message x and key t.
      H_LENGTH  = 32.
      ID_LENGTH = 20.
      G_LENGTH  = 32
      PROTOID   = "ntor-curve25519-sha256-1"
      t_mac     = PROTOID | ":mac"
      t_key     = PROTOID | ":key_extract"
      t_verify  = PROTOID | ":verify"
      MULT(a,b) = the multiplication of the curve25519 point 'a' by the
      scalar 'b'.
      G         = The preferred base point for curve25519 ([9])
      KEYGEN()  = The curve25519 key generation algorithm, returning
      a private/public keypair.
      m_expand  = PROTOID | ":key_expand"
      KEYID(A)  = A
    */

    /*
      To perform the handshake, the client needs to know an identity key
      digest for the server, and an ntor onion key (a curve25519 public
      key) for that server. Call the ntor onion key "B".  The client
      generates a temporary keypair:
	
      x,X = KEYGEN()
    */

    relay.ECDH_Curve25519_GenKeys();

    // The identity digest is the node's fingerprint! 
    // (that is, verified by sending a CREATE2 with a correct one -> received CREATED2, with a wrong one received DESTROY! :D)
    // The onion key is retrieved by relay information from descriptor

    /*
      and generates a client-side handshake with contents:

      NODEID      Server identity digest  [ID_LENGTH bytes]
      KEYID       KEYID(B)                [H_LENGTH bytes]
      CLIENT_PK   X                       [G_LENGTH bytes]
    */

    constexpr unsigned short ID_LENGTH = 20;
    constexpr unsigned short H_LENGTH = 32;
    constexpr unsigned short G_LENGTH = 32;
    constexpr unsigned short HLEN = ID_LENGTH + H_LENGTH + G_LENGTH;

    push_back_short(HLEN);

    //handshake data:
    push_back(relay.fp,20);
    push_back(relay.ntor,32);
    push_back(relay.tk->CURVE25519_PUBLIC_KEY,32);

    return true;
  }

  
  bool create_create2(relay_t& relay) {
    clear_payload();
    command = cell_command_t::CREATE2;
    return append_create2(relay);
  }
    

  bool create_extend2(relay_t& relay) {
    clear_payload();

    /*
      An EXTEND2 cell's relay payload contains:

      NSPEC      (Number of link specifiers)     [1 byte]
      NSPEC times:
      LSTYPE (Link specifier type)           [1 byte]
      LSLEN  (Link specifier length)         [1 byte]
      LSPEC  (Link specifier)                [LSLEN bytes]

      ==> the rest is the same as CREATE2

      HTYPE      (Client Handshake Type)         [2 bytes]
      HLEN       (Client Handshake Data Len)     [2 bytes]
      HDATA      (Client Handshake Data)         [HLEN bytes]
    */

    // reset command
		
    /* 	
	When speaking v2 of the link protocol or later, clients MUST only send
	EXTEND/EXTEND2 cells inside RELAY_EARLY cells
    */

    command = cell_command_t::RELAY_EARLY;

    //relay.print_info();
    
    push_back(relay.gen_link_specifier());

    // The end of EXTEND2 are the same as CREATE2, with more header data.
    if (!append_create2(relay)) {
      LOG_SEVERE("EXTEND2 Relay cell failed construction because CREATE2 contents in failure!\n");
      return false;
    }

    LOG_DEBUG("EXTEND2 cell built with success.\n");

    return true;
  }

  void prepare_relaycell(const cell_relay_command_t& command, const unsigned short& streamID,vector<unsigned char> &digest,skin_ctx_t &skin) {
    // Assume payload ready

    /*
      Relay command           [1 byte]
      'Recognized'            [2 bytes]
      StreamID                [2 bytes]
      Digest                  [4 bytes]
      Length                  [2 bytes]
      Data                    [Length bytes]
      Padding                 [PAYLOAD_LEN - 11 - Length bytes]
    */

    // Set default values
    stream_id = streamID;
    relay_command = command;
		
    vector<unsigned char> header;

    header.push_back(command); // Relay command
    append_short(header,0); //The 'recognized' field
    append_short(header,stream_id);

    // Get the real length of the current encrypted payload because digest must be done
    // also on the padding bytes.
    unsigned short payloadLen = size;

    // Pad now the payload, adding random bytes till PAYLOAD_LEN minus the 11 header bytes
    /*
      Implementations SHOULD fill this field with four zero-valued bytes, followed by as many
      random bytes as will fit.  (If there are fewer than 4 bytes for padding,
      then they should all be filled with zero.
    */

    while (size < PAYLOAD_LEN - 11 && size < payloadLen + 4)
      payload()[size++]=0;
		
    if(size < PAYLOAD_LEN - 11) {
      random_tab(payload()+size,PAYLOAD_LEN-11-size);
      size = PAYLOAD_LEN - 11;
    }
    
    append_int(header,0); // digest field
    append_short(header,payloadLen);

    // Prepend the header to payload
    memmove(payload()+header.size(),payload(),size);
    size+=header.size();
    memcpy(payload(),header.data(),header.size());
    
    // Check the size (should be exactly PAYLOAD_LEN)
    if (size != PAYLOAD_LEN) {
      LOG_FATAL("prepare_relaycell error: the payload is %d bytes insted of %d.\n", size, PAYLOAD_LEN);
      assert(0);
    }


    digest.resize(skin.digest_forward->digest_size());

    skin.digest_forward->update(payload(),size);
    skin.digest_forward->get_digest(digest.data());

    memcpy(payload()+5,digest.data(),4);
  }


  int prepare(const unsigned char *buffer,int buffsize, const unsigned char& link_protocol_version_,bool withpayload=0) {
    if (link_protocol_version_ > 0)
      link_protocol_version = link_protocol_version_;
		
    command = cell_command_t::PADDING;
    clear_payload();
		
    if(buffsize<5)
      return -1;

    int z=0;
    if (link_protocol_version < 4) {
      circuit_id = toshort(buffer);
      z+=2;
    } else {
      circuit_id = toint(buffer);
      z+=4;
    }

    command = cell_command_t(buffer[z++]);
    
    if(isVariableLength() && (buffsize-z) < 2)
      return -1;
		
    if (isVariableLength()) {
      unsigned short len=toshort(buffer+z);
      z+=2;
      if((buffsize-z)<len)
	return -1;

      assert(len<maxsize());
      
      size=len;

      if(withpayload) {
	memcpy(payload(),buffer+z,len);
	return 0;
      }
      return z;
    } 

    //fixed size
    if (buffsize<z+PAYLOAD_LEN)
      return false;
    
    size=PAYLOAD_LEN;
    assert(z<16);
    if(withpayload) {
      memcpy(payload(),buffer+z,PAYLOAD_LEN);
      return 0;
    }
    return z;
  }

  bool build_from_buffer(const unsigned char *buffer,int buffsize, const unsigned char& link_protocol_version_) {
    int r=prepare(buffer,buffsize,link_protocol_version_,1);
    return r==0;
  }


  
  /*
    A RELAY cell PAYLOAD contains:
      Relay command           [1 byte]
      'Recognized'            [2 bytes]
      StreamID                [2 bytes]
      Digest                  [4 bytes]
      Length                  [2 bytes]
      Data                    [Length bytes]
      Padding                 [PAYLOAD_LEN - 11 - Length bytes]
  */

  bool build_relaycell_from_payload(vector<unsigned char> &digest,skin_ctx_t &skin) {
    stream_id = 0;
    relay_command = cell_relay_command_t::RELAY_END;

    // Check if RELAY or RELAY_EARLY command
    if (command != cell_command_t::RELAY && command != cell_command_t::RELAY_EARLY) {
      LOG_SEVERE("Cell is not a RELAY cell! Command is %s\n", command_str() );
      return false;
    }

    if(size<11)
      return false;

    relay_command = static_cast<cell_relay_command_t>( payload()[0] );

    unsigned int recognized = toshort(payload()+1);
    if(recognized)
      LOG_WARN("WARNING recognised = %x , and should be 0\n",recognized );

    stream_id = toshort(payload()+3);

    unsigned int Digest = toint(payload()+5);

    LOG_INFOVV("RELAY Cell command :%s stream id: %04X digest: %08X\n", relay_cell_command_str(relay_command), stream_id, Digest);
    
    memset(payload()+5,0,4);

    digest.resize(skin.digest_backward->digest_size());
    skin.digest_backward->update(payload(),size);
    skin.digest_backward->get_digest(digest.data());
    

    unsigned int calculatedDigest = toint(digest.data());

    // Check the digest matching
    if (Digest != calculatedDigest) {
     LOG_WARN("digest %08X != %08X\n", Digest, calculatedDigest);
      return false;
    }

    // Get the length field
    unsigned short payloadLength = toshort(payload()+9);

    LOG_DEBUG("RELAY Cell real payload Length: %04X\n", payloadLength);

    // check if enough size for payload
    if (size < payloadLength + 11) {
      LOG_WARN("RELAY Cell real payload length is of %u bytes but buffer has only %d\n", payloadLength + 11, size);

      return false;
    }

    // Remove header informations
    memmove(payload(),payload()+11,size-11);
    size-=11;

    // REAL Payload, exclude padding bytes.
    size=payloadLength;

    LOG_INFOVV("RELAY real Payload size is now %d bytes.\n", size);

		
    return true;
  }

  bool is_recognized() {
    if (command != cell_command_t::RELAY && command != cell_command_t::RELAY_EARLY) {
      assert(0);
      return 0;
    }

    if (size < 11) {
      return 0;
    }

    return toshort(payload()+1)==0;
  }

  bool is_recognized(skin_ctx_t &skin) {
    if(!is_recognized()) return false;

    unsigned int digest4 = toint(payload()+5);

    memset(payload()+5,0,4);

    unsigned char digest[skin.digest_backward->digest_size()];
    {
      auto nd2=skin.digest_backward->copy();
      nd2->update(payload(),size);
      nd2->get_digest(digest);
      delete nd2;
    }

    unsigned int calculated_digest = toint(digest);
    put_int(payload()+5,digest4);

    if (calculated_digest != digest4) {
      LOG_DEBUG("cell digest not match %08X != %08X\n", calculated_digest, digest4); //usually, it's not an error, the recognised field can be 0 sometime...

      return 0;
    }

    LOG_DEBUG("cell is_recognized\n");

    return 1;
  }

  void encrypt(skin_ctx_t &s) {
    s.encrypt(payload(),size);
  }

  void decrypt(skin_ctx_t &s) {
    s.decrypt(payload(),size);
  }

};

template<int ms> 
struct cell_t_t : public cell_t {
  unsigned char msg[ms+7];
  unsigned char *payload() {return msg+7;}
  const unsigned char *const_payload() const {return msg+7;}

  virtual unsigned int maxsize() const {return ms;}
  
  cell_t_t(const unsigned char& link_protocol_version, const unsigned int& circid, const cell_command_t& command):cell_t(link_protocol_version,circid,command) {}

  ~cell_t_t() {}
};

typedef cell_t_t<2048> cell_t_big;

typedef cell_t_t<514> cell_t_small;

//enum for callback sockcell -> circuit
enum mcb_type_t {
  MCBT_NONE,
  MCBT_DATA,
  MCBT_START,
  MCBT_CONNECT,
  MCBT_END,
  MCBT_PING,
};



struct new_sockcell_t : public asocket_tls_t {
#ifdef DBGPOLL
  string name;
#endif

  void cb_timeout(int arg) {
    cb_cell(NULL,MCBT_PING,arg);
  }

  void cb_pollin() {
    if(0==(connected&STATUS_TLS_CONNECTED)) {
      asocket_tls_t::cb_pollin();
      if((connected&STATUS_ERROR)) {
	cb_cell(NULL,MCBT_END,0);
	return;
      }
      if((connected&STATUS_TLS_CONNECTED)) {
	if(mbedtls_ssl_get_bytes_avail(&ssl)>0)
	  LOG_SEVERE("mbedtls_ssl_get_bytes_avail(&ssl)>0 !\n");
	  
	cb_cell(NULL,MCBT_CONNECT,0);
      }
    }
    if(connected&STATUS_TLS_CONNECTED) {
      auto c=read_cell(0);
      if(c) {
	cb_cell(c,MCBT_DATA,0);
      }
      while(mbedtls_ssl_get_bytes_avail(&ssl)>0) {
	auto c=read_cell(0);
	if(c) {
	  cb_cell(c,MCBT_DATA,0);
	}
      }
    }	
  }

  void cb_pollout() {
    //LOG_INFO("here\n");
    asocket_tls_t::cb_pollout();
  }

  virtual void pcallback(pollable_t **pc,poll_reg_t &r) {
    //LOG_INFO("here\n");
    if(r.events==POLL_POLLOUT) {
      cb_pollout();


      poll_reg_t r;

      r.events=POLL_TIMEOUT|POLL_POLLIN;
      r.fd=fd;
      r.timeout=5000;
#ifdef DBGPOLL
      r.name=name;
#endif
      reg(r);

    }
    if(r.events==POLL_POLLIN) {
      cb_pollin();
    }
    if(r.events==POLL_TIMEOUT) {
      cb_timeout(r.timeout);
    }
  }

  virtual void cb_cell(cell_t *,mcb_type_t,int)=0; //to be set in circuit_t
  
  cell_t_small smallcell;
  
  rec_mutex_t mut_send;

  unsigned char sbf[16];
  cell_t *pc=NULL; //sanity check
  short  exp=0;
  short linkversion=0;
  short wr=0;
  short  wr2=0;
  
  bool firstcell=1;
  bool exiting=0;
  
  void log(const char *file,const char *fn,int line,int lvl, const char* format, ... )
  {
    if(lvl>dbg) return;
    va_list arglist;
    
    printf("[%s][new_sockcell %p :: %s:%d] ",loglvlstr[lvl],this,fn,line);
    va_start( arglist, format );
    vprintf( format, arglist );
    va_end( arglist );
  }

  void disconnect_sockcell() {
    LOG_DEBUGVV("disconnect\n");
    exiting=1;
    disconnect_tls();
  }

  void disconnect() {
    disconnect_sockcell();
  }
  
  new_sockcell_t():smallcell(0, 0, cell_command_t::PADDING) {  }

  void delete_cell(cell_t *cell) {
    LOG_DEBUG("delete this=%p %p\n",this,cell);
    assert(pc==cell);
    if(cell != &smallcell) {
      void *ptr=cell;
      cell->~cell_t();
      big_free(ptr);
    }
    pc=NULL;
  }

  virtual ~new_sockcell_t() {
    LOG_DEBUGVV("~new_sockcell_t\n");
    disconnect_sockcell();
    if(pc)
      delete_cell(pc);
  }

  

  bool send(cell_t *cell) {
    mut_send.lock();
    if(exiting) {
      LOG_DEBUG("send() fail because exiting\n");
      delete cell;
      mut_send.unlock();
      return 1;
    }
    bool r=cell->send_cell_nomt(*this);
    delete cell;
    mut_send.unlock();
    return r;
  }

  
  
  cell_t *read_cell(bool wait=1) {
    LOG_DEBUG("read_cell p=%p w=%d\n",this,wait);
    bool eof=0;
    
    if(!(is_connected()))
      LOG_INFOVV("read:cell wait=%d: client not connected\n",wait);

    while(is_connected()) {
      LOG_INFOVV("read:cell loop wait=%d: wr=%d exp=%p\n",wait,wr,exp);
      
      if(exp<=0) {
	assert(wr<9);
	int a=asocket_tls_t::read(sbf+wr,9-wr);
	if(a==SOCK_TIMEOUT)
	  break;
	if(a<0) {
	  LOG_INFOVV("read_cell a = %d <0 !! close\n",a);
	  eof=1;
	  break;
	}
	if(a==0) {
	  LOG_INFOVV("read_cell a = 0 closed\n");
	  eof=1;
	  break;
	}
	wr+=a;
	exp=expected_cell_size((linkversion==0)?2:linkversion,linkversion==0,sbf,wr); 

	LOG_DEBUG("expected size: %d\n",exp);
	if(exp>0) {
	  assert(wr>0 && wr<16 && exp>wr);
	  assert(pc==NULL);
	  if(exp>514) {
	    LOG_DEBUG("big cell size=%d\n",exp);
	    // this cell is a CERT cell, only one in circuit live
	    void* ptr=big_malloc(sizeof(cell_t_big));
	    pc=new(ptr) cell_t_big(0, 0, cell_command_t::PADDING);
	  } else pc=&smallcell;
	  int z=pc->prepare(sbf,exp,(linkversion==0)?2:linkversion);
	  assert(z>0);
	  assert(z<=wr);
	  memcpy(pc->payload(),sbf+z,wr-z);
	  wr2=wr-z;
	}
	if(!wait) break;
	continue;
      }

      LOG_INFOVV("read:cell loop(2) wait=%d: wr=%d exp=%p\n",wait,wr,exp);

      assert(exp>10);
      assert(exp>wr);

      assert(pc);
      int a=asocket_tls_t::read(pc->payload()+wr2,exp-wr);
      if(a==SOCK_TIMEOUT)
	break;
      if(a<0) {
	LOG_INFOVV("read_cell (2) a = %d <0 !! close\n",a);
	eof=1;
	break;
      }
      if(a==0) {
	LOG_INFOVV("read_cell(2) a = 0 closed\n");
	eof=1;
	break;
      }
      wr+=a;
      wr2+=a;

      if(wr<exp) {
	if(!wait) break;
	continue;
      }
      assert(wr==exp);

      assert(pc);

      exp=-1;
      wr=0;
      wr2=0;

      if(firstcell) {
	if (pc->command != cell_command_t::VERSIONS) {
	  LOG_WARN("first cell is not a VERSIONS cell\n");
	} else {
	  linkversion=pc->GetLinkProtocolFromVersionCell();
	  LOG_INFOV("got first cell. version = %d\n",linkversion);
	}
	firstcell=0;
      }

      return pc;
    }
    if(eof) {
      LOG_INFOVV("disconnection in read_cell\n");
      exiting=1;
      disconnect_sockcell();
      cb_cell(NULL,MCBT_END,0);
    }
    if(!is_connected()) {
      LOG_INFOVV("client->isconnected() == false !\n");
      exiting=1;
      cb_cell(NULL,MCBT_END,0);
    }

    return NULL;
  }

};

typedef new_sockcell_t sockcell_t;







		
