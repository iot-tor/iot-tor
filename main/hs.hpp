#ifndef DISABLE_CACHE

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <string>
#include <algorithm>
#include <string.h>
#include <mbedtls/bignum.h>
#include <mbedtls/sha512.h>

using namespace std;

#ifdef ESP

#define NB_RAD 2
#define NB_FDIR 4
#define NB_OLD 2
#define NB_INTRO 2

#else

#define NB_RAD 2
#define NB_FDIR 4
#define NB_OLD 2
#define NB_INTRO 3
#endif

#ifdef ESP
int max_pub=1;
int max_pub_circuits=4;
#else
int max_pub=2;
int max_pub_circuits=10;
#endif


/** Ed25519 Basepoint value. Taken from section 5 of
 * https://tools.ietf.org/html/draft-josefsson-eddsa-ed25519-03 */
static const char *str_ed25519_basepoint =
  "(15112221349535400772501151409588531511"
  "454012693041857206046113283949847762202, "
  "463168356949264781694283940034751631413"
  "07993866256225615783033603165251855960)";

void comp_subcred(unsigned char *subcred,const unsigned char *public_key,const unsigned char *blinded_public_key)
{
  unsigned char cred[32];
  /*
    The subcredential for a period is derived as:
x	
    subcredential = H("subcredential" | credential | blinded-public-key).
	
    In the above formula, credential corresponds to:
	
    credential = H("credential" | public-identity-key)
  */
  //::print("CR pk ",public_key,32);
  //::print("CR bpk ",blinded_public_key,32);

  H_SHA3_256(cred,(const unsigned char*)"credential",-1,public_key,32);
  H_SHA3_256(subcred,(const unsigned char*)"subcredential",-1,cred,32,blinded_public_key,32);

  //::print("CR cred ",cred,32);
  //::print("CR subcred ",subcred,32);
}

void derive_blind_key(unsigned char *der,const unsigned char *pub,unsigned long long tn,const unsigned char *secret=NULL)
{
  //printf("derive key tn=%Ld\n",tn);
  //print("pub:",pub,32);

  /* Create the nonce N. The construction is as follow:
   *    N = "key-blind" || INT_8(period_num) || INT_8(period_length) */

  unsigned char nonce[25];
  long long tplen=1440;
  memcpy(nonce,"key-blind",9);

  tn=htonll(tn);
  tplen=htonll(tplen);

  for(int u=0;u<8;u++) {
    nonce[9+u]=((unsigned char*)(&tn))[u];
    nonce[17+u]=((unsigned char*)(&tplen))[u];
  }

  /* Generate the parameter h and the construction is as follow:
   *    h = H(BLIND_STRING | pubkey | [secret] | ed25519-basepoint | N) */

  const char blind_str[] = "Derive temporary signing key";

  sha3_ctx_t c;
  sha3_init(&c,32);//SHA3_256);
  sha3_update(&c,blind_str,sizeof(blind_str));
  sha3_update(&c,pub,32);
  sha3_update(&c,str_ed25519_basepoint,strlen(str_ed25519_basepoint));
  sha3_update(&c,nonce,25);
  unsigned char h[32];
  sha3_final(h,&c);

  //print("digest:",h,32);
  
  //then clamp the blinding factor 'h' according to the ed25519 spec:

  h[0] &= 248;
  h[31] &= 63;
  h[31] |= 64;

  //print("h:",h,32);

  //and do the key derivation as follows:
  if(secret==NULL) { //is_public_key
    //public key for the period:
    
    //A' = h A = (ha)B
    /* ... = zA + R */
    struct ed25519_pt p;
    //struct ed25519_pt q;
    int ok=1;
    ok &= upp(&p, pub);
    ed25519_smult(&p, &p, h);
    pp(der, &p);
    //print("der ",der,32);
    return ;
  } else {
    //private key for the period:

    //a' = h a mod l

    uint8_t a[32];
    uint8_t ap[32];
    uint8_t fh[32];
    fprime_from_bytes(a, secret, 32, ed25519_order);
    fprime_from_bytes(fh,h, 32, ed25519_order);
    fprime_mul(ap, fh, a, ed25519_order);
    
    memcpy(der,ap, 32);

    //RH' = SHA-512(RH_BLIND_STRING | RH)[:32]
    const char *RH_BLIND_STRING = "Derive temporary signing key hash input";

    unsigned char tmp[64];
    mbedtls_sha512_context ctx;
    mbedtls_sha512_init(&ctx);
    mbedtls_sha512_starts(&ctx,0);
    mbedtls_sha512_update(&ctx, (unsigned char *)RH_BLIND_STRING,strlen(RH_BLIND_STRING));
    mbedtls_sha512_update(&ctx, secret+32,32);
    mbedtls_sha512_finish(&ctx, tmp);
    mbedtls_sha512_free(&ctx);
    memcpy(der+32,tmp,32);
  }
}

void comp_hs_index(unsigned char *idx,const unsigned char *pubkey,int replica,unsigned long long tn) {
  // for replicanum in 1...hsdir_n_replicas:
  //     hs_index(replicanum) = H("store-at-idx" |
  //                              blinded_public_key |
  //                              INT_8(replicanum) |
  //                              INT_8(period_length) |
  //                              INT_8(period_num) )

  long long tplen=1440;
  long long re=replica;
  
  tn=htonll(tn);
  tplen=htonll(tplen);
  re=htonll(re);
    
  const char nstr[] = "store-at-idx";

  sha3_ctx_t c;
  sha3_init(&c,32);//SHA3_256);
  sha3_update(&c,nstr,strlen(nstr));

  sha3_update(&c,pubkey,32);
  sha3_update(&c,&re,8);
  sha3_update(&c,&tplen,8);
  sha3_update(&c,&tn,8);
  sha3_final(idx,&c);

  //print("hs_index ",idx,32);
}

struct hsmac_t {
  digest_t dig;
  int size=0;
  
  hsmac_t(): dig(1) {}

  //Where D_MAC = H(mac_key_len | MAC_KEY | salt_len | SALT | ENCRYPTED)
  void init(const unsigned char *mac_key,const unsigned char *salt) {
    //print("init mac key ",mac_key,32);
    //print("init mac salt ",salt,16);
    unsigned long long len=htonll(32); 
    dig.update((unsigned char*)(&len),8);
    dig.update(mac_key,32);
    len=htonll(16); 
    dig.update((unsigned char*)(&len),8);
    dig.update(salt,16);
  }
    
  void update(const unsigned char *in,int lin) {
    dig.update(in,lin);
    size+=lin;
  }

  void get_mac(unsigned char *mac)
  {
    //printf("mac.get_digest size=%d\n",size);
    dig.get_digest(mac);
    //print("mac dig ",mac,32);
  }
};

struct s_hsmac_t : public s_t, public hsmac_t {
  s_hsmac_t(s_t &a):s_t(a) {  }
  s_hsmac_t() {  }
  void push(const unsigned char *in,int inlen) {
    update(in,inlen);
    proc(in,inlen);
  }
};

struct blinded_public_onion_key {
  unsigned char public_key[32];
  unsigned char blinded_public_key[32];
  unsigned char subcred[32];
  long long tp;

  void comp_cred() {
    comp_subcred(subcred,public_key,blinded_public_key);
  }

  void derive() {
    derive_blind_key(blinded_public_key,public_key,tp);
    comp_cred();
  }

  blinded_public_onion_key() {
    memset(public_key,0,32);
    memset(blinded_public_key,0,32);
    memset(subcred,0,32);
    tp=0;
  }

};

struct hsdirs_t :public blinded_public_onion_key {
  unsigned char hsidx[2][32];
  void comp_hs_index() {
    ::comp_hs_index(hsidx[0],blinded_public_key,1,tp);
    ::comp_hs_index(hsidx[1],blinded_public_key,2,tp);
  }

  string hsreq;
  vector<unsigned short> ids; //id in cached_descs of hsdirs

  vector<intro_node_t> intros;
};

/*
2.3.1. Client behavior in the absence of shared random values

   If the previous or current shared random value cannot be found in a
   consensus, then Tor clients and services need to generate their own random
   value for use when choosing HSDirs.

   To do so, Tor clients and services use:

     SRV = H("shared-random-disaster" | INT_8(period_length) | INT_8(period_num))

   where period_length is the length of a time period in minutes, period_num is
   calculated as specified in [TIME-PERIODS] for the wanted shared random value
   that could not be found originally.
*/

void disaster_srv(unsigned char *srv,unsigned long long tp) {
  unsigned char nonce[22+8+8];
  long long tplen=1440;
  memcpy(nonce,"shared-random-disaster",22);

  tp=htonll(tp);
  tplen=htonll(tplen);

  for(int u=0;u<8;u++) {
    nonce[22+u]=((unsigned char*)(&tplen))[u];
    nonce[22+8+u]=((unsigned char*)(&tp))[u];
  }

  sha3_ctx_t c;
  sha3_init(&c,32);//SHA3_256);
  sha3_update(&c,nonce,22+8+8);
  sha3_final(srv,&c);
}


hsdirs_t gen_hsdirs(unsigned char *pub,int tp2)
{
  hsdirs_t r;

  LOG_INFO("(re)gen_hsdir tp=%d \n",tp2);
    
  r.tp=tp2; 
  memcpy(r.public_key,pub,32);
  r.derive();

  char b64[64];
  size_t len;
  mbedtls_base64_encode((unsigned char*)b64,63,&len,r.blinded_public_key,32);
  while(len>0 && (b64[len-1]==0 || b64[len-1]=='=')) len--;
  b64[len]=0;
  r.hsreq=b64;

  r.comp_hs_index();
  // if(hsdir_dbg>2)
  //   print("hsidx[0]: ",r.hsidx[0],32);
  // if(hsdir_dbg>2)
  //   print("hsidx[1]: ",r.hsidx[1],32);
  keeper_t<int,32,4> k[2];
  k[0].init(r.hsidx[0]);
  k[1].init(r.hsidx[1]);

  unsigned char idx[32];
  
  const unsigned char *srvc=relays.get_srv(tp2);
  unsigned char srv[32];
  assert(srvc);
  if(isnull(srvc,32)) {
    LOG_WARN("srv is null ! disaster mode...\n");
    disaster_srv(srv,tp2);
  } else
    memcpy(srv,srvc,32);

  LOG_DEBUG("srv: %s\n",to_str(srv,32).c_str());
  
  auto m=info_node_t::FL_CONS|info_node_t::FL_HSDIR;
  for(int i=0;i<CACHE_SIZE;i++)
    if((cache_descs[i].flags&m)==m) {
      cache_descs[i].get_hsdir_index(idx,srv,tp2);
      //printf("ADD to keepers (i=%d): ",i);
      //print("",idx,32);
      k[0].add(i,idx);
      k[1].add(i,idx);
    }

  // if(hsdir_dbg>2) {
  //   k[0].print();
  //   k[1].print();
  // }
  
  for(int i=0;i<NB_RAD;i++)
    for(int j=0;j<NB_FDIR;j++)
      r.ids.push_back(k[i].bb[j]);
  
  return r;
  
  //private key for the period:
  
  // a' = h a mod l
  //   RH' = SHA-512(RH_BLIND_STRING | RH)[:32]
  //   RH_BLIND_STRING = "Derive temporary signing key hash input"
		      
  // 		      public key for the period:

  //          A' = h A = (ha)B
  
  // ed25519_donna_gettweak(tweak, param);

  // print("blind tweak ",tweak,64);

  // expand256_modm(t, tweak, 32);

  // print("blind t ",t,32);

  // /* No "ge25519_unpack", negate the public key. */
  // memcpy(pkcopy, inp, 32);
  // pkcopy[31] ^= (1<<7);
  // if (!ge25519_unpack_negative_vartime(&A, pkcopy)) {
  //   return -1;
  // }

  // /* A' = [tweak] * A + [0] * basepoint. */
  // ge25519_double_scalarmult_vartime(&Aprime, &A, t, zero);
  // ge25519_pack(out, &Aprime);
}

bool decode_link_specifier(info_node_t &node,const unsigned char *bf,int l) {
  if(l<=0) return 0;
  int p=0;
  int n=bf[p++];
  for(int u=0;u<n;u++) {
    if(p+2>l) return 0;
    int t=bf[p++];
    int s=bf[p++];
    if(p+s>l) return 0;
    //todo

    /*
      [00] TLS-over-TCP, IPv4 address
           A four-byte IPv4 address plus two-byte ORPort
      [01] TLS-over-TCP, IPv6 address
           A sixteen-byte IPv6 address plus two-byte ORPort
      [02] Legacy identity
           A 20-byte SHA1 identity fingerprint. At most one may be listed.
      [03] Ed25519 identity
           A 32-byte Ed25519 identity fingerprint. At most one may
           be listed.
    */
    if(t==0 && s==6) {
      memcpy(node.ipv4,bf+p,4);
      node.port=htons(*(unsigned short*)(bf+p+4));
    } else if(t==2 && s==20) {
      memcpy(node.fp,bf+p,20);
    } else if(t==3 && s==32) {
      memcpy(node.id25519,bf+p,32);
    } else if(t==1) {
      //ipv6
    } else {
      LOG_WARN("error in link_specifier... t=%d s=%d\n",t,s);
    }
    p+=s;
  }
  return 1;
}

bool decode_link_specifier_b64(info_node_t &n,const char *bf) {
  int l=strlen(bf);
  int ml=(l*6)/8+2;
  unsigned char t[ml];
  size_t ol;
  int r=mbedtls_base64_decode(t,ml,&ol,(const unsigned char*)bf,l);
  if(r) {
    LOG_WARN("base64 dec link spec error ret=%d\n",int(r));
    return 0;
  } else 
    return decode_link_specifier(n,t,ol);
}

struct derived_onion_key_t : public onion_key_t {
  unsigned char blinded_public_key[32];
  unsigned char blinded_secret_key[32];
  long long tp;
  unsigned char subcred[32];

  void comp_cred() {
    comp_subcred(subcred,public_key,blinded_public_key);
  }

  void derive() {
    derive_blind_key(blinded_public_key,public_key,tp);
    derive_blind_key(blinded_secret_key,public_key,tp,secret_key);
    comp_cred();
  }

};

struct circuits_intros_t;

struct hsdesc_t : public blinded_public_onion_key { //crypto things of hsdescs
  unsigned char descriptor_signing_key[32];
  long long rc=0; //rev counter
  unsigned char salt1[16],salt2[16];
  unsigned char key1[32];
  unsigned char iv1[16];
  unsigned char mackey1[32];
  unsigned char key2[32];
  unsigned char iv2[16];
  unsigned char mackey2[32];

  circuits_intros_t *intros=NULL;
  
  mbedtls_cipher_context_t cipher1_ctx;
  mbedtls_cipher_context_t cipher2_ctx;

  struct pub_info_t {
    long long when=0;
    int interval=20;
    void fail() {
      when=get_unix_time()+interval;
      interval*=2;
      if(interval>TOR_HSDIR_REPUBLISH_TIME_WHEN_FAILS)
	interval=TOR_HSDIR_REPUBLISH_TIME_WHEN_FAILS;
    }
    void success() {
      when=get_unix_time()+TOR_HSDIR_REPUBLISH_TIME;
      interval=20;
    }
  };
  
  vector<circuit_t*> tci;
  vector<intro_keys_t*> intros_keypairs;
  map<int,pub_info_t> mpublished;
  vector<unsigned short> ids; 

  void print() const {
    int n=tci.size();
    string s;
    assert(intros_keypairs.size()==n);
    for(int i=0;i<n;i++) {
      if(tci[i]==NULL) {
	if(intros_keypairs[i]==NULL)
	  s.push_back('/');
	else
	  s.push_back('k');
      } else {
	if(intros_keypairs[i]==NULL) 
	  s.push_back('?');
	else
	  s.push_back('O');
      }
    }
    LOG_INFO("hsdesc_t tp=%d intros:'%s' \n",int(tp),s.c_str());
  }
  
  void clear() {
    if(aes1init) {
      //printf("mbedtls_cipher_free(&cipher1_ctx) %p this=%p;\n",&cipher1_ctx,this);
      mbedtls_cipher_free(&cipher1_ctx);
    }
    if(aes2init)
      mbedtls_cipher_free(&cipher2_ctx);

    aes1init=aes2init=0;

    for(auto &it:intros_keypairs) delete it;
    intros_keypairs.clear();
    tci.clear();

    memset(descriptor_signing_key,0,32);
    memset(salt1,0,16);
    memset(salt2,0,16);
    memset(iv1,0,16);
    memset(iv2,0,16);
    memset(mackey1,0,32);
    memset(mackey2,0,32);

  }
  
  hsdesc_t() {
    clear();
  }

  ~hsdesc_t() {
    clear();

    if(ch)
      delete ch;
  }

  void kdf1() {
    //SECRET_DATA = blinded-public-key
    const char *STRING_CONSTANT = "hsdir-superencrypted-data";

    sha3_ctx_t ctx;
    shake256_init(&ctx);

    //keys = KDF(secret_input | salt | STRING_CONSTANT, S_KEY_LEN + S_IV_LEN + MAC_KEY_LEN)
    //secret_input = SECRET_DATA | subcredential | INT_8(revision_counter)
    //print("KDF blinded ",blinded_public_key,32);
    shake_update(&ctx,blinded_public_key,32);
    //print("KDF subcred ",subcred,32);
    shake_update(&ctx,subcred,32);
    long long tmp=htonll(rc);
    shake_update(&ctx,&tmp,8);

    shake_update(&ctx,salt1,16);
    //print("KDF salt1 ",salt1,32);
    sha3_update(&ctx,STRING_CONSTANT,strlen(STRING_CONSTANT));

    shake_xof(&ctx);               // switch to extensible output

    const int dl=32+16+32; //S_KEY_LEN + S_IV_LEN + MAC_KEY_LEN;
    unsigned char derived[dl];
    shake_out(&ctx, derived, dl); 

    //print("KDF ",derived,dl);

    memcpy(key1,derived,32);
    memcpy(iv1,derived+32,16);
    memcpy(mackey1,derived+32+16,32);
  }

  void kdf2() {
    //SECRET_DATA = blinded-public-key | descriptor_cookie
    const char *STRING_CONSTANT = "hsdir-encrypted-data";
      
    sha3_ctx_t ctx;
    shake256_init(&ctx);

    //keys = KDF(secret_input | salt | STRING_CONSTANT, S_KEY_LEN + S_IV_LEN + MAC_KEY_LEN)
    //secret_input = SECRET_DATA | subcredential | INT_8(revision_counter)
    shake_update(&ctx,blinded_public_key,32);
    shake_update(&ctx,subcred,32);
    long long tmp=htonll(rc);
    shake_update(&ctx,&tmp,8);

    shake_update(&ctx,salt2,16);
    sha3_update(&ctx,STRING_CONSTANT,strlen(STRING_CONSTANT));

    shake_xof(&ctx);               // switch to extensible output

    const int dl=32+16+32; //S_KEY_LEN + S_IV_LEN + MAC_KEY_LEN;
    unsigned char derived[dl];
    shake_out(&ctx, derived, dl); 

    //print("KDF2 ",derived,dl);

    memcpy(key2,derived,32);
    memcpy(iv2,derived+32,16);
    memcpy(mackey2,derived+32+16,32);
    
    /*
       SECRET_KEY = first S_KEY_LEN bytes of keys
       SECRET_IV  = next S_IV_LEN bytes of keys
       MAC_KEY    = last MAC_KEY_LEN bytes of keys
    */
  }
  
  /*
       SALT = 16 bytes from H(random), changes each time we rebuild the
              descriptor even if the content of the descriptor hasn't changed.
              (So that we don't leak whether the intro point list etc. changed)

	      secret_input = SECRET_DATA | subcredential | INT_8(revision_counter)


   The encrypted data has the format:

       SALT       hashed random bytes from above  [16 bytes]
       ENCRYPTED  The ciphertext                  [variable]
       MAC        D_MAC of both above fields      [32 bytes]

   The final encryption format is ENCRYPTED = STREAM(SECRET_IV,SECRET_KEY) XOR Plaintext .

   Where D_MAC = H(mac_key_len | MAC_KEY | salt_len | SALT | ENCRYPTED)
   and
    mac_key_len = htonll(len(MAC_KEY))
   and
    salt_len = htonll(len(SALT)).


    * Instantiate STREAM with AES256-CTR.
    * Instantiate KDF with SHAKE-256.

  */

  bool aes1init=0;
  bool aes2init=0;
  
  void init_aes_1() {
    if(aes1init)
      mbedtls_cipher_free(&cipher1_ctx);

    aes1init=1;
    mbedtls_cipher_init( &cipher1_ctx );
    
    //printf("mbedtls_cipher_init(&cipher1_ctx) %p;\n",&cipher1_ctx);

    auto cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CTR); //string("AES-256-CTR");
    assert(cipher_info);

    int r=0;
    r=r||mbedtls_cipher_setup( &cipher1_ctx, cipher_info);
    r=r||mbedtls_cipher_setkey( &cipher1_ctx,key1,256,MBEDTLS_ENCRYPT);
    r=r||mbedtls_cipher_set_iv( &cipher1_ctx, iv1, 16 );
    r=r||mbedtls_cipher_reset( &cipher1_ctx);
    assert(r==0);
  }

  void init_aes_2() {
    if(aes2init)
      mbedtls_cipher_free(&cipher2_ctx);

    aes2init=1;
    mbedtls_cipher_init( &cipher2_ctx );
    
    auto cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CTR); //string("AES-256-CTR");
    assert(cipher_info);

    int r=0;
    r=r||mbedtls_cipher_setup( &cipher2_ctx, cipher_info);
    r=r||mbedtls_cipher_setkey( &cipher2_ctx,key2,256,MBEDTLS_ENCRYPT);
    r=r||mbedtls_cipher_set_iv( &cipher2_ctx, iv2, 16 );
    r=r||mbedtls_cipher_reset( &cipher2_ctx);
    assert(r==0);
  }

  struct gen_hs_descr_t {
    onion_key_t key;
    unsigned char psec[64];
    sign_cert_ed25519_t c;
    unsigned char tmp[256];
    s_pem_t surencb64;
    s_hsmac_t macsurenc;
    s_aes_t surenc;
    s_pem_t encb64;
    s_hsmac_t macenc;
    s_aes_t enc;
    unsigned char cu2[32];
#ifdef ADDCHECK
    unsigned char ed2[32];
#endif
    unsigned char zeroes[16];
    unsigned char sig[64];
    unsigned char m[32];
      
    bool gen_hs_descr(s_t &a,onion_key_t &site, hsdesc_t &h) {
      assert(match(h.public_key,site.public_key,32));
  
      int cert_exp=get_unix_time()/3600+4;
  
      s_sign_t aa;
      aa.set_sink(a);
      aa.start_md();

      //unsigned char pder[32];
      //derive_blind_key(pder,site.public_key,tp);
      //memcpy(h.blinded_public_key,pder,32);
      //derive_blind_key(h.blinded_public_key,site.public_key,h.tp);

      h.comp_cred();
  
      derive_blind_key(psec,site.public_key,h.tp,site.secret_key);
  
      const char *prefix="Tor onion service descriptor sig v3";
      aa.update_md((unsigned char*)prefix,strlen(prefix));

      aa.printf("hs-descriptor 3\n");
      aa.printf("descriptor-lifetime 180\n");
      aa.printf("descriptor-signing-key-cert\n");

      random_tab(h.salt1,16);
      random_tab(h.salt2,16);
      //print("salt1 ",h.salt1,16);
      //print("salt2 ",h.salt2,16);
  
      key.generate();
      key.check();
  
      //site.fill(c);
      //print("  ",h.blinded_public_key,32);
      memcpy(c.key,h.blinded_public_key,32);
      memcpy(c.secret,psec,64);
      c.type=8; //Cert type;
      c.key_type=1;
      c.exp=cert_exp;
      memcpy(c.cert_key,key.public_key,32);
      //c.print_info();
      int lt=c.writebin(tmp,256);

#ifdef ADDCHECK
      {//check
	cert_ed25519_t ct;
	int r=ct.init(tmp,lt);
	//printf("r=%d\n",r);
      }
#endif
  
      pem("ED25519 CERT",tmp,lt,aa);
      aa.printf("revision-counter %Ld\n",h.rc);
      aa.printf("superencrypted\n");

      {

	surencb64.init("MESSAGE",aa);
	macsurenc.set_sink(surencb64);
	surenc.set_sink(macsurenc);
	s_aes_t &bb(surenc);
      
	surencb64.start();
    
	surencb64.push(h.salt1,16);

	h.kdf1();
	h.init_aes_1();
	macsurenc.init(h.mackey1,h.salt1);

	surenc.cipher_ctx=&(h.cipher1_ctx);

	bb.printf("desc-auth-type x25519\n");
	bb.printf("desc-auth-ephemeral-key %s\n",random_b64(32).c_str()); //todo
	for(int i=0;i<16;i++)
	  bb.printf("auth-client %s %s %s \n",random_b64(8,0).c_str(),random_b64(16,0).c_str(),random_b64(16,0).c_str());

	bb.printf("encrypted\n");


	encb64.init("MESSAGE",bb);
	macenc.set_sink(encb64);
	enc.set_sink(macenc);
	s_t &cc(enc);

	encb64.start();
	encb64.push(h.salt2,16);


	h.kdf2();
	h.init_aes_2();
	macenc.init(h.mackey2,h.salt2);

	enc.cipher_ctx=&(h.cipher2_ctx);

	cc.printf("create2-formats 2\n");
	//flow-control 1-2 31

	for(int k=0;k<h.intros_keypairs.size();k++) {
	  auto &it(h.intros_keypairs[k]);
	  if(it==NULL) {
	    LOG_WARN("intros_keypair %d is NULL !\n",k);
	    continue;
	  }
	  auto ls=it->node.gen_link_specifier();
	  size_t ol=0;
	  int r=mbedtls_base64_encode((unsigned char*)tmp,255,&ol,ls.data(),ls.size());
	  assert(r==0 && ol<250);
	  tmp[ol]=0;
      
	  cc.printf("introduction-point %s\n",tmp);
	  r=mbedtls_base64_encode((unsigned char*)tmp,255,&ol,it->node.ntor,32);
	  assert(r==0 && ol<250);
	  tmp[ol]=0;
	  cc.printf("onion-key ntor %s\n",tmp);

	  cc.printf("auth-key\n");

	  key.fill(c);
	  c.type=9; //Cert type;
	  c.key_type=1;
	  c.exp=cert_exp;
	  memcpy(c.cert_key,it->auth.public_key,32);
	  int lt=c.writebin((unsigned char*)tmp,256);
	  pem("ED25519 CERT",(unsigned char*)tmp,lt,cc);


	  c25519_smult(cu2, c25519_base_x, it->enc.secret_key);
#ifdef ADDCHECK
	  curve25519_pk_to_ed25519(ed2,cu2);
	  //print("cu2     ",cu2,32);
	  //print("ed2     ",ed2,32);
	  //print("enc.pub ",it->enc.public_key,32);
	  assert(match(ed2,it->enc.public_key,32));
#endif
      
	  r=mbedtls_base64_encode((unsigned char*)tmp,255,&ol,cu2,32);
	  assert(r==0 && ol<250);
	  tmp[ol]=0;
	  cc.printf("enc-key ntor %s\n",tmp);

	  cc.printf("enc-key-cert\n");

	  c.type=0xb; //Cert type;
	  c.key_type=1;
	  c.exp=cert_exp;
	  memcpy(c.cert_key,it->enc.public_key,32);
	  lt=c.writebin((unsigned char*)tmp,256);
	  pem("ED25519 CERT",(unsigned char*)tmp,lt,cc);
      
	}
	memset(zeroes,0,16);

	int u=16-(macenc.size%16);
	cc.push(zeroes,u);
	macenc.finish();
	macenc.get_mac(m);
	//print("enc mac ",m,32);
	enc.finish();
	encb64.push(m,32);
	encb64.finish();

    
	int v=16-(macsurenc.size%16);
	bb.push(zeroes,v);
	assert(macsurenc.size%16==0);
    
	macsurenc.finish();
	macsurenc.get_mac(m);
	//print("surenc mac ",m,32);
	surenc.finish();
	surencb64.push(m,32);
	surencb64.finish();
      }
      aa.stop_md();

  
      edsign_sign_expanded(sig, key.public_key,key.secret_key,aa.message.data(),aa.message.size());

      aa.printf("signature %s\n",base64(sig,64,0).c_str());
  
      return 1;
    }
  };

  
  
  bool gen_hs_descr_(s_t &a,onion_key_t &site) {
    gen_hs_descr_t *t=new gen_hs_descr_t;
    rc=get_unix_time(); //fix not nice 
    auto r=t->gen_hs_descr(a,site,*this);
    delete t;
    return r;
  }

  int gen_hs_descr(onion_key_t &site,s_vc_t &a,ps_vector<char> &v)
  {
    int r=gen_hs_descr_(a,site);
  
    if(r==0) {
      LOG_SEVERE("gen_hs_desc failed\n");
      return DESCR_BAD_CRYPTO;
    }

    return DESCR_OK;
  }


  circuits_hsdirs_t *ch=NULL;

  bool is_publishing() {
    if(ch) {
      LOG_INFOV("still publishing...\n");
      if(ch->is_working()==false) {
	string str="";
	for(int i=0;i<ch->circuits.size();i++) {
	  char tmp[50];
	  if(ch->circuits[i]->status==circuits_t::OK_JOB) {
	    mpublished[ch->circuits[i]->orig].success();
	    snprintf(tmp,50,"%d %s OK /",ch->circuits[i]->orig,shortname(ch->circuits[i]->orig).c_str());
	  } else {
	    mpublished[ch->circuits[i]->orig].fail();
	    snprintf(tmp,50,"%d %s FAIL %s /",ch->circuits[i]->orig,shortname(ch->circuits[i]->orig).c_str(),ch->status_str(circuits_t::status_t(ch->circuits[i]->status)));
	  }
	  str+=string(tmp);
	}
	LOG_INFO("end publisher %d : %s\n",int(tp),str.c_str());
	delete ch;
	ch=NULL;
	LOG_DEBUG("circuits_hsdir_t deleted \n");
	return 0;
      }

      return 1;
    }

    return 0;
  }
  
  bool recomp=0;

  bool publish_hsdirs(poller_t &poller,onion_key_t &site) {
    LOG_INFOV("=== publish ===== tp=%d\n",int(tp));
    unsigned char *pub=public_key;
    
    if(ids.empty() || recomp) {
      auto hsdirs=gen_hsdirs(pub,tp);
      ids=hsdirs.ids;
      recomp=0;
    }

    bool has_intro=0;
    for(auto &it:intros_keypairs) {
      if(it)
	has_intro=1;
    }
    
    if(!has_intro) {
      LOG_WARN("no introduction points: no publish...\n");
      return 0;
    }

    vector<unsigned short> todo;
    for(auto &ii:ids) {
      auto it=mpublished.find(ii);
      if(it!=mpublished.end()) {
	if(get_unix_time()<it->second.when)
	  continue;
      }
      LOG_INFOV("republish tp=%d id=%d\n",int(tp),ii);
      todo.push_back(ii);
    }

    if(todo.empty()) {
      LOG_INFOV("nothing to republish...\n");
      return 0;
    }

    if(todo.size()>max_pub_circuits) {
      random_shuffle(todo.begin(),todo.end());
      todo.resize(max_pub_circuits);
    }

    if(main_dbg>=_LOG_INFO) {
      string r;
      for(auto &it:todo) {
	char tmp[20];
	snprintf(tmp,19,"%d %s / ",it,shortname(it).c_str());
	r+=string(tmp);
      }
      LOG_INFO("(re)publish tp=%d ids=%s\n",int(tp),r.c_str());
    }
    
    ch=new circuits_hsdirs_t(poller,todo,tp);
    ch->dbg=_LOG_SEVERE;
    ch->dbg_sub=_LOG_SEVERE;
#ifdef DBGPOLL
    char tmp[100];
    snprintf(tmp,99,"hsdirs %d",int(tp));
    ch->name=tmp;
#endif

    int r=gen_hs_descr(site,ch->a,ch->v);
    assert(r==DESCR_OK);
    
    ch->publish();

    return 1;
  }

  bool gen_new_keypair(int u,circuit_t *tc) {
    LOG_DEBUG("gen keypair tp=%Ld tc=%p id=%d\n",int(tp),tc,u);
    intro_keys_t *ik=new intro_keys_t;
    ik->generate();
    info_node_t n(*tc->get_exit_node());
    ik->node=n;
    memcpy(ik->subcred,subcred,32);

    intros_keypairs[u]=ik;
    return 1;
  }
  
  bool establish_intro(int u,circuit_t *tc) {
    LOG_DEBUG("establish_intro tp=%Ld tc=%p id=%d\n",int(tp),tc,u);
    assert(intros_keypairs[u]);
    tc->establish_intro(*(intros_keypairs[u]));
    tci[u]=tc;
    return 1;
  }

  void kill_intro(int u) {
    LOG_DEBUG("kill intro tp=%Ld %d\n",int(tp),u);
    if(intros_keypairs[u]) {
      delete intros_keypairs[u];
      intros_keypairs[u]=NULL;
    }

    if(tci[u]) {
      tci[u]=NULL;
    }
  }  

  void set_intro_point(int i,circuit_t *tc) {
    LOG_INFO("set_intro_point id=%d tc=%p\n",i,tc);
    if(tc) {
      if(tc->build_status!=circuit_t::BS_BUILT) {
	LOG_FATAL("tc->build_status=%d\n",tc->build_status);
	assert(0);
      }
    }
    assert(i>=0 && i<128);
    while(tci.size()<=i)
      tci.push_back(NULL);
    while(intros_keypairs.size()<=i)
      intros_keypairs.push_back(NULL);

    if(tci[i]) {
      LOG_INFOV("tci[%d]=%p != NULL\n",i,tci[i]);
      tci[i]=NULL;
    }
    
    if(tc==NULL) return; //deregister

    if(intros_keypairs[i]==NULL) {
      gen_new_keypair(i,tc);    
    }

    establish_intro(i,tc);    
  }

  
};

struct circuits_intros_t : public circuits_t {
#ifdef MEMDBGSUB
  void * operator new(size_t size)
  {
    void * p = malloc(size);//MEMDBG
    printf("*** new circuits_intro_t %p size=%d\n",p,int(size));
    return p;
  }
    
  void operator delete(void * p)
  {
    printf("*** delete circuits_intro_t %p \n",p);
    free(p);
  }
#endif
  hsdesc_t *hd=NULL;

  virtual void pcallback(pollable_t **chain,poll_reg_t &fds) {
    circuits_t::pcallback(chain,fds);
    
    if(postdo&2) {
      postdo&=~2;
      LOG_INFOV("postdo something... (circuits_intro_t)\n");
      for(auto &cs:circuits) {
	if(cs->tc && cs->tc->intro_ok &&cs->status==OK_CONNECTED) {
	  cs->status=OK_JOB;
	  LOG_INFO("job OK : intro_ok\n");
	}
	if(cs->tc && cs->tc->has_intro2() ) {
	  LOG_INFOV("TODO proc intro2 here\n");
	}
      }
    }
  }

  
  virtual ~circuits_intros_t() {
    LOG_DEBUG("~circuits_intros_t %p\n",this);
  }

  virtual void done(int i,int ok) {
    LOG_INFO("circuits_intros done %p tc=%p id=%d ok=%d\n",circuits[i],circuits[i]->tc,i,ok);
    circuits[i]->cbs=ok;

    if(ok==FAIL_CONNECTED || ok==FAIL_JOB) {
      circuits[i]->fails++;
      hd->set_intro_point(i,NULL);
      return;
    }
    if(ok==DESTROYED) {
      hd->set_intro_point(i,NULL);
      return;
    }
    
    if(ok==OK_CONNECTED) {
      circuits[i]->fails=0;
      hd->set_intro_point(i,circuits[i]->tc);
      return;
    }
    
    LOG_SEVERE("TODO done ok=%d\n",ok);
  }
  
  circuits_intros_t(poller_t &poller,hsdesc_t *h,int tp):circuits_t(poller) {
    hd=h;
    intro=1;
  }

  void establish_intros(int n) {
    assert(circuits.size()==0);
    for(int i=0;i<n;i++)
      async_gen_working_circuit(i);
  }

  void check() {
    LOG_INFOV("check all intro points\n");
    for(int i=0;i<circuits.size();i++) {
      assert(circuits[i]);
      auto cbs=circuits[i]->cbs;
      auto tc=circuits[i]->tc;
      if(circuits[i]->status==WAIT || circuits[i]->status==FAIL_CONNECTED_RETRY) {
	LOG_INFOV("check id=%d : still working...\n",i);
	continue;
      }
      if(tc==NULL || cbs==FAIL_CONNECTED || cbs==DESTROYED || tc->check_alive()==false) {
	LOG_INFO("reconstruct circuit id=%d %p prevtc=%p cbs=%d status=%d\n",i,circuits[i],tc,cbs,circuits[i]->status);
	hd->set_intro_point(i,NULL);
	relay_t *ex=NULL;
	if(tc) {
	  ex=tc->get_exit_node();
	  circuits[i]->tc=NULL;
	  clean_delete_circuit(tc);
	}
	if(circuits[i]->fails>=4) { //change exit point...
	  ex=NULL;
	  circuits[i]->fails=0;
	}
	if(ex==NULL) hd->kill_intro(i);
	async_gen_working_circuit(i,ex);
      }      
    }
  }
};

bool no_hs_publish=0; //debug option


struct hs_server_t : public union_poller_t {

  map<int,hsdesc_t*> hd;

  onion_key_t site;
  unsigned char pub[32];
  mutex_t mut_th;
  
  void print2() {
    for(auto &it:hd) {
      if(it.second==NULL)
	LOG_WARN("%d it.second=NULL\n",it.first);
      else {
	it.second->print();
      }
    }
  }
  
  void print(bool force=0) {
    int l=0;
    for(auto &ht:hd) {
      for(int i=0;i<ht.second->tci.size();i++) {
	auto tc=ht.second->tci[i];
	if(tc) {
	  l++;
	}
      }
    }
    
    static int ol=0;
    mut_th.lock();
    mut_th.unlock();
    if(l!=ol || force)
      LOG_INFO("%d connections to intro points\n",l);
    ol=l;
  }
  
  hsdesc_t *get_hd(int tp,bool create=1) {
    hsdesc_t *h=NULL;
    if(hd.find(tp)==hd.end()) {
      if(!create) return NULL;
      h=new hsdesc_t();
      hd[tp]=h;
    } else
      h=hd.at(tp);
    return h;
  }

  hs_server_t(const string &path="") {
    init(path);

    poller=&main_poller;
    poll_reg_t r;
    r.events=POLL_TIMEOUT;
    r.timeout=500; //500 ms
#ifdef DBGPOLL
    r.name="hs";
#endif
    union_poller_t::pollable_t::reg(r);
  }

  void delete_hd(int tp) {
    auto p=hd.at(tp);
    LOG_INFO("delete_hd(tp=%d) p=%p\n",int(tp),p);
    assert(p);

    auto ci=p->intros;
    LOG_INFOV("delete hsdesc tp=%d circuits_intros %p :\n",int(tp),p,ci);
    assert(ci);
    ci->destroy_all();
    delete ci;
    
    LOG_INFOV("delete hsdesc_t tp=%d %p :\n",int(tp),p);
    delete p;
  }
  
  void remove_old_hd() {
    int dt=-1;
    if(relays.srv_period_f>=0.5)
      dt=0;
    
    int stp=get_cons_time_period()+dt;

    LOG_INFO("remove old hd stp=%d\n",stp);

    for(auto &it:hd) {
      LOG_INFO(" hds tp=%d\n",it.first);
    }
    
    for(auto &it:hd) {
      if(it.first<stp) {
	delete_hd(it.first);
	hd.erase(it.first);
	remove_old_hd();
	return;
      }
    }
  }

  void remove_all_hd() {
    LOG_INFOVV("remove_all_hd()\n");
    for(auto &it:hd)
      delete_hd(it.first);
    hd.clear();
  }

  void create_hsdescs(int tp) {
    if(hd.find(tp)!=hd.end()) {
      LOG_INFOV("intros already ok for tp=%d\n",int(tp));
      return;
    }
    
    LOG_INFO("== establish intros tp=%d ==\n",int(tp));
    
    hsdesc_t &hh(*get_hd(tp));
    memcpy(hh.public_key,site.public_key,32);
    hh.tp=tp;
    hh.derive();

    hh.intros_keypairs.resize(NB_INTRO,NULL);
    hh.tci.resize(NB_INTRO,NULL);

    auto ci=new circuits_intros_t(*this,&hh,tp);
    ci->dbg=DBGBASE;
    ci->dbg_sub=_LOG_SEVERE;
    
#ifdef DBGPOLL
    char tmp[100];
    snprintf(tmp,99,"intros %d",int(tp));
    ci->name=tmp;
#endif
    hh.intros=ci;
    ci->establish_intros(NB_INTRO);

    //for(int i=0;i<NB_INTRO;i++)
    //  hh.establish_intro(i);
  }

  void create_hsdescs() {
    int dt=-1;
    if(relays.srv_period_f>=0.5)
      dt=0;
    
    int stp=get_cons_time_period()+dt;

    for(int no=0;no<NB_OLD;no++)
      create_hsdescs(stp+no);
  }

  char sw=0;
  short old_nb_refresh=0;
  
  void publish() {
    LOG_INFOV("publish\n");

    bool recomp_=0;
    if(old_nb_refresh!=tor_nb_refresh()){
      recomp_=1;
      old_nb_refresh=tor_nb_refresh();
    }
    
    int dt=-1; //-1 0
    if(relays.srv_period_f>=0.5)
      dt=0; //0 1
    
    //comp_all_hsdir_index(dt);

    int np=0;
    for(int no=0;no<NB_OLD;no++) {
      int tp=get_cons_time_period()+dt+no;

      auto hh=get_hd(tp,0);
      if(!hh) {
	LOG_INFOV("no (yet) hd for %d\n",int(tp));
	continue;
      }
      if(recomp_) hh->recomp=1;
      assert(hh->tp==tp);
      assert(match(pub,hh->public_key,32));

      if(hh->is_publishing()) np++;
    }

    if(np>=max_pub) return;

    int osw=sw;
    for(int no_=0;no_<NB_OLD;no_++) {
      int no=no_^osw;
      
      int tp=get_cons_time_period()+dt+no;

      auto hh=get_hd(tp,0);
      if(!hh)
	continue;
      assert(hh->tp==tp);
      assert(match(pub,hh->public_key,32));
      if(hh->is_publishing()) {
	continue;
      }
      
      auto ci=hh->intros;
      assert(ci);
      if(ci->is_working()) {
	LOG_INFOV("do not publish intros for tp=%d since circuits is still working\n",int(tp));
      } else {
	int r=hh->publish_hsdirs(*this,site);
	if(r) np++;
	sw=sw^1;
      }
      if(np>=max_pub) break;
    }
    LOG_INFOV("publish done\n");
  }

  struct server_t {
    hs_server_t *o;
    intro_material_t *t;
    circuit_t *tc=NULL;
    poller_t *poller;
    int tries=0;

    void destroy_tc() {
      LOG_INFOV("server_t %p destroy_tc tc=%p\n",this,tc);
      for(auto &it:ss)
	delete it;
      ss.clear();
      if(tc)
	clean_delete_circuit(tc);
      tc=NULL;
    }

    bool check_alive() {
      if(!tc) return false;
      if(!tc->check_alive()) return false;
      return true;
    }
    
    ~server_t() {
      LOG_DEBUG("~server_t %p\n",this);
      if(t)
	delete t;
      t=NULL;
      destroy_tc();
    }
    
    bool gen() {
      tries++;
      if(tries>10) {
	LOG_WARN("too may tries...\n");
	return 0;
      }

      tc=new circuit_t(*poller);
#ifdef DBGPOLL
      tc->name="rdv circ";
#endif
      
      int r=fill_nodes(tc,&(t->node));
      if(!r) {
	LOG_WARN("fill_nodes fails...\n");
	delete tc;
	tc=NULL;
	return 0;
      }
      //tc->print_circuit_info();
      
      tc->set_ncb(std::bind(&server_t::cb,this,std::placeholders::_1));
      
      r=tc->async_build_circuit();
      if(r==0) {
	LOG_WARN("async_build_circuit FAIL\n");
	clean_delete_circuit(tc);
	tc=NULL;
      }
      return 1;
    }

    list<shitty_http_server_t*> ss;
    
    void init(hs_server_t *h,intro_material_t *i,poller_t *p) {
      o=h;
      t=i;
      poller=p;

      gen();
    }

    int finished=0;
    
    int k=0;

    void cb(ccb_t cb) {
      LOG_INFOV("cb %d\n",cb);
      
      if(cb==CCB_CIRCUIT_BUILT_FAIL) {
	destroy_tc();
	if(!gen()) {
	  finished=1;
	}
      } else if(cb==CCB_CIRCUIT_BUILT_OK) {
	LOG_INFOV("circuit to rdv node built, now connect_rendezvous...\n");
	tc->connect_rendezvous(t);
	LOG_INFOV("connect_rendezvous done\n");
	delete t;
	t=NULL;
      } else if(cb==CCB_DESTROY) {
	finished=1;
	destroy_tc();
      } else if(cb==CCB_RELAY_BEGIN) {
	LOG_INFO("CCB_RELAY_BEGIN, launch HTTP server !\n");
	
	string bod="<html><body>";
	bod+="<p>HELLO WORLD</p>";

	{
	  static int kk=0;
	  char tmp[150];
	  int s=timer_get_ms()/1000;
	  snprintf(tmp,150,"<p>#req=%d (%d)</p> <p>uptime : %d secs = %lf hours</p>",kk++,k++,s,s/3600.);
	  bod+=tmp;
	}
#ifdef ESP
	bod+="<p>";
	bod+=esp_heap_info("<br />");
	bod+="</p>";
#endif	
	
	bod+="</body></html>\r\n";
	
	
	auto sr=new asocket_tor_t(tc);
	if(!sr->accept()) {
	  LOG_WARN("problem with accept()\n");
	  delete sr;
	} else {
	  LOG_INFOV("new shitty_http_server... \n");
	  auto r=shitty_http_server(sr,bod);
	  ss.push_back(r);
	  LOG_INFOV("new shitty_http_server returns\n");
	}
	
      } else {
	LOG_INFO("handle cb %d ?\n",cb);
      }
    }
  };

  list<server_t*> ls;
  
  bool proc_intro2_connect(intro_material_t *t)
  {
    LOG_INFO("proc_intro2_connect...\n");
    auto tt=new server_t;
    tt->init(this,t,this);
    ls.push_back(tt);
    return 1;
  }

  void clean_servers() {
    LOG_INFOV("clean severs...\n");
    list<server_t*> ls2;
    for(auto &it:ls) {
      if(it->check_alive()==false) {
	LOG_INFOV("clean severs : delete %p...\n",it);
	delete it;
      } else {
	ls2.push_back(it);
      }
    }
    ls.swap(ls2);
  }
  

  bool proc_intro2(circuit_t *it)
  {
    LOG_INFO("== has_intro2 returns ==\n");
    intro_material_t *t=it->get_intro2();
    assert(t);
    LOG_INFO("== construct circuit to RDV node: ==\n");
    t->node.print_info();
    return proc_intro2_connect(t);
  }

  void loop() {
    const int D=20;//  //DDDD ->20
    static int k=0;
    LOG_INFOV("hs server loop %d \n",k);

    if((k%D)==0 && tor_is_ok()) {
#ifdef ESP
      esp_memory_info();
#endif
      print_mem_stat();
      printf("hostname: ");site.print_host();
      //print2();
      //print(1);

      if(hd.size()<=1)
	create_hsdescs();
      remove_old_hd();
      if(hd.size()>2)
	LOG_FATAL("something wrong: more than two timeperiods !\n");
      
      if(!no_hs_publish) publish(); //k%(D*100)==0);
    }

    k++;

    if(tor_is_ok()) {
      for(auto &ht:hd) {
	auto ci=ht.second->intros;
	if(false==ci->is_working()) {
	  ci->check();
	}
      }
    }

    for(auto &ht:hd) {
      for(int i=0;i<ht.second->tci.size();i++) {
	auto tc=ht.second->tci[i];
	if(tc) {
	  while(tc->has_intro2())
	    proc_intro2(tc);
	}
      }
    }

    print(0);
    //site.print_info();
  }
  
  void finish() {
    remove_all_hd();
    for(auto &it:ls)
      delete it;
    ls.clear();
  }

  virtual ~hs_server_t() {
    finish();
    union_poller_t::pollable_t::unreg();
  }

  virtual void pcallback(pollable_t **chain,poll_reg_t &fds) {
    if(chain[0]==NULL) {
      assert(fds.events==POLL_TIMEOUT);
      loop();
      return;
    }
    union_poller_t::pcallback(chain,fds);
  }
  
  
  void init(const string &path) {
    
#ifndef LINUX
    if(!site.read_spiffs()) {
      LOG_INFO("hs_keys not found, generate new HS key\n");

      //site.generate(); 

      memcpy(site.secret_key,mysec_hs,64); //mysec_hs/mypub_hs are in private.hpp. put your, or use site.generate() for a new key
      memcpy(site.public_key,mypub_hs,32);

      site.write_spiffs();
    }


#else
    if(path=="hard") {
      memcpy(site.secret_key,mysec_hs,64); //mysec_hs/mypub_hs are in private.hpp. put your, or use site.generate() for a new key
      memcpy(site.public_key,mypub_hs,32);
    } else if(path=="" || path=="random") {
      site.generate();  //force new key
      site.write("hstmp/");
    } else {
      if(!site.read(path.c_str())) {
	LOG_SEVERE("cannot read hs key in %s/. generate new one\n",path.c_str());
	site.generate();  //force new key
	site.write("hstmp/");
      }
    }

#endif
    
    site.print_info();

    parse_onionv3(site.get_ad().c_str(),pub);
    assert(match(pub,site.public_key,32));
  }
  
};


/// for HS client

struct hsdesc_processor_t : public hsdesc_t {
  hsdirs_t *hsdir=NULL;
  
  char bf[256];
  aclientbuff_t<256> cb;

  bool surenc=0;

  newliner_t nl1,nl2;
  bool end1=0,end2=0;

  int salted=0;
  int salted2=0;

  intro_node_t node;

  int iskey=0;
  int iskey2=0;

  char strkey[65*10];
  unsigned char pemkey[400];
  int keysize=0;
  
  void finish_process_intro_point() {
    if(!node.isnull()) {
      bool ok=1;
      memcpy(node.subcred,subcred,32);

      // check that ed25519 and curve25519 public key are the same (up to conversion)
      unsigned char e[32];
      curve25519_pk_to_ed25519(e,node.enc_key_c);
      //print("enc-key-conv ",e,32);
      if(!match(e,node.enc_key_e,32)) {
	LOG_WARN("CRYPTOFAIL 25519 conv NOT MATCH !\n");
	ok=0;
	//assert(0);
      } //else printf("XXXXXX CONV MATCH !!!\n");

      // unsigned char c[32];
      // crypto_sign_ed25519_pk_to_curve25519(c,node.enc_key_e);
      // print("to cuve ",c,32);
      
      if(ok) {
	LOG_INFO("new intro point: %s\n",node.info_str().c_str());
	hsdir->intros.push_back(node);
      }
      
      
    }
    node.kill();
  }

  /* todo: 

     "enc-key-cert" NL certificate NL

     [Exactly once per introduction point]

     Cross-certification of the encryption key using the descriptor
     signing key.

     For "ntor" keys, certificate is a proposal 220 certificate wrapped
     in "-----BEGIN ED25519 CERT-----" armor, cross-certifying the
     descriptor signing key with the ed25519 equivalent of a curve25519
     public encryption key derived using the process in proposal 228
     appendix A. The certificate type must be [0B], and the signing-key
     extension is mandatory.
  */

  
  void process_layer2(char *bf,int l)
  {
    //for(int i=0;i<l;i++)      if(bf[i]==0) printf("P2 0 at %d / %d !!\n",i,l);
    
    LOG_INFOV("=HSDIR2= %s",bf);
    if(iskey2) {
      if(strncmp(bf,"-----BEGIN",10)==0) {
      
      } else if(strncmp(bf,"-----END",8)==0) {
	size_t res=0;
	int ret=mbedtls_base64_decode(pemkey,sizeof(pemkey)-1,&res, (const unsigned char*)strkey,keysize);
	if(ret) {
	  LOG_WARN("base64 dec error ret=%d res=%d\n",int(ret),int(res));
	} else {
	  assert(res<sizeof(pemkey)-1);

	  cert_ed25519_t ck;
	  ck.init(pemkey,res);
	  //ck.print_info();
	  if(ck.ok==0)
	    node.kill();
	  else if(!match(ck.key,descriptor_signing_key,32)) {
	    LOG_WARN("key mismatch in auth-key/enc-key-cert\n");
	    node.kill();
	  } else {
	    if(iskey2==1) memcpy(node.auth_key,ck.cert_key,32);
	    if(iskey2==2) memcpy(node.enc_key_e,ck.cert_key,32);
	  }
	  
	}
	iskey2=0;
	keysize=0;
      } else {
	if(keysize+strlen(bf)+1<sizeof(strkey)) {
	  memcpy(strkey+keysize,bf,strlen(bf));
	  keysize+=strlen(bf);
	} else {
	  LOG_SEVERE("OVERFLOW\n");
	}
      }
    }
    auto r=cut(bf);
    if(r.size()==0) return;
    if(r[0]=="introduction-point" && r.size()>1) {
      finish_process_intro_point();
      
      decode_link_specifier_b64(node,r[1].c_str());
    }
    if(r.size()>=3 && r[0]=="onion-key" && r[1]=="ntor") {
      size_t ol;
      mbedtls_base64_decode(node.ntor,32,&ol,(const unsigned char*)r[2].c_str(),r[2].size());
      //node.print_info();
    }
    if(r.size()>=3 && r[0]=="enc-key" && r[1]=="ntor") {
      size_t ol;
      unsigned char ntor[32];
      mbedtls_base64_decode(ntor,32,&ol,(const unsigned char*)r[2].c_str(),r[2].size());
      //print("enc-key (c25519)  ",ntor,32);

      unsigned char e[32];
      curve25519_pk_to_ed25519(e,ntor);
      //print("enc-key (ed25519) ",e,32);

      memcpy(node.enc_key_c,ntor,32);
    }
    if(r[0]=="auth-key")
      iskey2=1;
    if(r[0]=="enc-key-cert")
      iskey2=2;
  }

  void process_enc(unsigned char *dbf,int l)
  {

    static FILE *fo=fopen("enc","w");

    fprintf(fo,"%s",dbf);

    nl2.update((char*)dbf,l);
    char bf[256];
    int r=0;
    while((r=nl2.read(bf,255))>0) {
      if(bf[r-1]==0) {
	end2=1;
	LOG_INFOV("END2...\n");
      }
      bf[r]=0;
      process_layer2(bf,r);
      if(end2) return;
    }
  }

  struct delay_t {
    unsigned char tmp[128];
    int p=0;
    int push(const unsigned char *in,int lin, unsigned char *out) {
      memcpy(tmp+p,in,lin);
      p+=lin;
      if(p<=32) return 0;
      int r=p-32;
      memcpy(out,tmp,r);
      memmove(tmp,tmp+r,32);
      p=32;
      return r;
    }
  };
    
  hsmac_t mac1,mac2;
  delay_t delay1,delay2;

  void decode_enc(unsigned char *bf,int l)
  {
    if(l==0) return;
    if(salted2==0) {
      assert(l>=16);
      memcpy(salt2,bf,16);
      //print("XXX salt2 ",salt2,16);
      salted2=1;
      kdf2();
      init_aes_2();
      mac2.init(mackey2,salt2);
      decode_enc(bf+16,l-16);
      return;
    }

    l=delay2.push(bf,l,bf);
    mac2.update(bf,l);

    size_t olen=0;
    unsigned char out[50];
    if( mbedtls_cipher_update( &cipher2_ctx, bf, l, out, &olen ) != 0 ) {
      LOG_FATAL("mbedtls_cipher_update() returned error\n");
      exit(1);
    }

    assert(olen==l);
    out[l]=0;
    
    process_enc(out,l);
  }

  bool enc=0;
  
  void process_enc_b64(const char *bf) {
    unsigned char b[50];
    size_t len=0;
    int r=mbedtls_base64_decode(b,50,&len,(const unsigned char*)bf,strlen(bf));
    if(r) {
      LOG_WARN("base64 dec enc error ret=%d len=%d\n",int(r),int(len));
    } else {
      decode_enc(b,len);
    }
  }

  void process_layer1(const char *bf,int l)
  {
    if(bf[0]!=0)
      if(!enc)
      	LOG_DEBUG("=HSDIR1= %s",bf);

    if(enc) {
      if(strncmp(bf,"-----BEGIN",10)==0) {
      } else if(strncmp(bf,"-----END",8)==0) {
	enc=0;
      } else {
	process_enc_b64(bf);
      }
      return ;
    }
    if(strncmp(bf,"encrypted",9)==0)
      enc=1;
  }
  
  void process_superenc(unsigned char *dbf,int l)
  {
    if(end1)
      return;
    nl1.update((char*)dbf,l);
    char bf[256];
    int r=0;
    while((r=nl1.read(bf,255))>0) {
      if(bf[r-1]==0) {
	end1=1;
	break;
      }
      bf[r]=0;
      process_layer1(bf,r);
    }
  }
  
  void decode_superenc(unsigned char *bf,int l)
  {
    if(l==0) return;
    if(salted==0) {
      assert(l>=16);
      memcpy(salt1,bf,16);
      //print("XXX salt ",salt1,16);
      salted=1;
      kdf1();
      init_aes_1();
      mac1.init(mackey1,salt1);
      decode_superenc(bf+16,l-16);
      return;
    }

    l=delay1.push(bf,l,bf);
    mac1.update(bf,l);

    size_t olen=0;
    unsigned char out[48];
    if( mbedtls_cipher_update( &cipher1_ctx, bf, l, out, &olen ) != 0 ) {
      LOG_WARN("mbedtls_cipher_update() returned error\n");
      exit(1);
    }
    assert(olen==l);

    process_superenc(out,l);
  }

  void process_superenc_b64(const char *bf)
  {
    unsigned char b[50];
    size_t len=0;
    int r=mbedtls_base64_decode(b,50,&len,(const unsigned char*)bf,strlen(bf));
    if(r) {
      LOG_WARN("base64 dec error ret=%d len=%d\n",int(r),int(len));
    } else {
      decode_superenc(b,len);
    }
  }

  int body=0;
  ps_vector<unsigned char> allmessage;
  bool sigok=0;
  
  void process_line_hsdescriptor(char *bf,int rr)
  {
    if(body)
      append(allmessage,(unsigned char*)bf,rr);

    bf[rr]=0;
    //if(!surenc) printf("=HSDIR0= %s",bf);
    assert(bf[rr-1]=='\n'); //TODO

    if(surenc) {
      if(strncmp(bf,"-----BEGIN",10)==0) {
      } else if(strncmp(bf,"-----END",8)==0) {
	surenc=0;
	body=0;
      } else {
	process_superenc_b64(bf);
      }
      return ;
    }

    if(iskey) {
      if(strncmp(bf,"-----BEGIN",10)==0) {
      
      } else if(strncmp(bf,"-----END",8)==0) {
	size_t res=0;
	int ret=mbedtls_base64_decode(pemkey,sizeof(pemkey)-1,&res, (const unsigned char*)strkey,keysize);
	if(ret) {
	  LOG_WARN("base64 dec error ret=%d res=%d\n",int(ret),int(res));
	} else {
	  assert(res<sizeof(pemkey)-1);

	  cert_ed25519_t ck;
	  ck.init(pemkey,res);
	  //ck.print_info();
	  if(ck.ok && ck.type==8 && ck.key_type==1) {
	    if(!match(blinded_public_key,ck.key,32)) {
	      printf("CRYPTOFAIL key mismatch in descriptor-signing-key-cert\n");
	      //print("blinded_public_key ",blinded_public_key,32);
	      //print("ck.key ",ck.key,32);
	      badcrypto=1;
	      memcpy(descriptor_signing_key,ck.cert_key,32);
	    } else {
	      memcpy(descriptor_signing_key,ck.cert_key,32);
	    }
	  }
	}
	iskey=0;
	keysize=0;
      } else {
	if(keysize+strlen(bf)+1<sizeof(strkey)) {
	  memcpy(strkey+keysize,bf,strlen(bf));
	  keysize+=strlen(bf);
	} else {
	  LOG_SEVERE("OVERFLOW\n");
	}
      }
    } else {
      auto v=cut(bf);
      if(v.size()==0) return;
      if(v[0]=="descriptor-signing-key-cert")
	iskey=1;
      if(v[0]=="revision-counter" && v.size()>1)
	rc=atoll(v[1].c_str());
      if(v[0]=="superencrypted") {
	surenc=1;
      }
      if(v[0]=="signature") {
	string s=v[1]+"==";
	unsigned char sig[65];
	size_t ol;
	int r=mbedtls_base64_decode(sig,64,&ol,(const unsigned char*)s.c_str(),s.size());
	if(!r && ol==64) {
	  //uint8_t edsign_verify(const uint8_t *signature, const uint8_t *pub,		      const uint8_t *message, size_t len)

	  int r=edsign_verify(sig, descriptor_signing_key,allmessage.data(),allmessage.size());
	  if(r==0) {
	    LOG_WARN("CRYPTOFAIL edsign_verify fail\n"); 
	    badcrypto=1;
	  }
	  else
	    sigok=1;
	}

	/// check macs
	unsigned char m[32];
	mac1.get_mac(m);
	if(!match(m,delay1.tmp,32)) {
	  LOG_WARN("CRYPTOFAIL mac error in superencrypt\n");
	  badcrypto=1;
	}
	mac2.get_mac(m);
	if(!match(m,delay2.tmp,32)) {
	  LOG_WARN("CRYPTOFAIL mac error in encrypt\n");
	  badcrypto=1;
	}

      }
    }

  }
  
  bool badcrypto=0;
  bool fail=0;

  const char *prefix="Tor onion service descriptor sig v3";

#if 0
  int process_hs_descriptor(const char *fn) {
    FILE *in=fopen(fn,"r");
    if(!in)
      return DESCR_KO;
    
    surenc=0;
    fail=0;
    iskey=0;
    append(allmessage,(const unsigned char *)prefix,strlen(prefix));

    while(fgets(bf,255,in)) {
      int rr=strlen(bf);
      if(strncmp(bf,"hs-descriptor",13)==0) body=1;
      process_line_hsdescriptor(bf,rr);
    }
    //printf("EOF\n");
    
    finish_process_intro_point();

    if(sigok==0) {
      LOG_WARN("no/bad sig\n");
      return DESCR_BAD_CRYPTO;
    }

    if(badcrypto) {
      LOG_WARN("crypto fail\n");
      return DESCR_BAD_CRYPTO;
    }

    if(fail) {
      LOG_WARN("file operation failed\n");
      return DESCR_KO;
    }

    return DESCR_OK;
  }
#endif
  
  int download_hs_descriptor_in(asocket_t &sock,ip_info_node_t &dir,hsdirs_t &hd)
  {
    hsdir=&hd;
    string hs=hd.hsreq;

    string req= "/tor/hs/3/"+hs;

    req=httprequest(req,inet_ntoa(*(in_addr*)dir.ipv4),1);

    LOG_INFO("download hs descriptor %s \n",hs.c_str());
    
    //printf("%s",req.c_str());

    surenc=0;
    fail=0;
    iskey=0;
    
    if(sock.write_string(req)==false) {
      LOG_WARN("sock.write_string fail\n");
      return DESCR_KO;
    }

    cb.clear();
    cb.set_sock(&sock);

    append(allmessage,(const unsigned char*)prefix,strlen(prefix));;
    
    while(1) {
      int rr=cb.read_until((unsigned char*)bf,255,"\n",1);
      if(strncmp(bf,"hs-descriptor",13)==0) body=1;
      if(rr==0) break;
      if(rr<0) {
	fail=1;
	break;
      }
      bf[rr]=0;
      printf("HSD %s",bf);
      process_line_hsdescriptor(bf,rr);
    }

    finish_process_intro_point();
    
    printf("DONE HSD\n");

    cb.clear();

    if(badcrypto) {
      LOG_WARN("crypto fail\n");
      return DESCR_BAD_CRYPTO;
    }

    if(fail) {
      LOG_WARN("sock operation failed\n");
      return DESCR_KO;
    }

    return DESCR_OK;
  }
};


#endif


