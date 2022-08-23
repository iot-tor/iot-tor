#pragma once
#include "socks.hpp"
#include <assert.h>
#include <assert.h>
#include <vector>
#include <string>
#include <map>
#include <list>
#include <array>
#include <set>
#include <string.h>
#include <array>
#include <tuple>
#include <mbedtls/base64.h>
#include <arpa/inet.h>


#include "stream.hpp"


using namespace std;

#ifndef EXIT_PORT
#define EXIT_PORT 88
#endif

int exit_port=EXIT_PORT;

int dir_dbg=2;

mutex_t mutex_dir;

struct ip_info_node_t {
  //in_addr ipv4;
  unsigned char ipv4[4];
  unsigned short port=0;
  unsigned short dirport=0;

  bool isnull() const {
    for(int i=0;i<4;i++)
      if(ipv4[i]) return 0;
    return 1;
  }
    
  void clear() {
    memset(this,0,sizeof(*this));
  }
  ip_info_node_t() {
    clear();
  }
  string str() const {
    char bf[50];
    auto ip=ipv4_to_string(*(in_addr*)ipv4);
    snprintf(bf,50,"%16s:%5d (%05d)",ip.c_str(),port,dirport);
    return bf;
  }

  string short_info() const { 
    auto ip=ipv4_to_string(*(in_addr*)ipv4);
    char tmp[30];
    snprintf(tmp,30,"%16s:%5d",ip.c_str(),port);
    return tmp;
  }

};

void comp_hsdir_index(unsigned char *idx,const unsigned char *id25519,const unsigned char *srv,int tn_) {
  /* hsdir_index(node) = H("node-idx" | node_identity |
     shared_random_value |
     INT_8(period_num) |
     INT_8(period_length) ) */

  unsigned long long tn=tn_;
  long long tp=1440;

  tn=htonll(tn);
  tp=htonll(tp);
    
  const char nstr[] = "node-idx";

  sha3_ctx_t c;
  sha3_init(&c,32);//SHA3_256);
  sha3_update(&c,nstr,strlen(nstr));

  sha3_update(&c,id25519,32);
  sha3_update(&c,srv,32);
  sha3_update(&c,&tn,8);
  sha3_update(&c,&tp,8);
  sha3_final(idx,&c);
}


ip_info_node_t my_ip;

static const char *MONTH_NAMES[] =
  { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

void proc_date(char *bf,int r) {
  bf[r]=0;
  LOG_INFO("proc_date %s\n",bf);
  auto c=cut(bf);
  if(c.size()<5) return;
  int mday=atoi(c[2].c_str());
  int mon=-1;
  for(int u=0;u<12;u++)
    if(strncmp(c[3].c_str(),MONTH_NAMES[u],3)==0)
      mon=u+1;
  if(mon==-1) return;
  int year=atoi(c[4].c_str());
  auto c2=cut(c[5],":");
  if(c2.size()<3) return;
  int hour=atoi(c2[0].c_str());
  int min=atoi(c2[1].c_str());
  int sec=atoi(c2[2].c_str());

#if 0
  struct tm t;
  t.tm_mday=mday;
  t.tm_mon=mon-1;
  t.tm_year=year-1900;
  t.tm_hour=hour;
  t.tm_min=min;
  t.tm_sec=sec;
  //printf("date: %02d %02d %d %02d:%02d:%02d\n",day,month,year,h,m,s);
  t.tm_isdst = -1;
  auto n=mktime(&t);
  LOG_INFO("time (mktime): %d\n",(int)n);
#endif

  auto now=date_to_unix_time(year,mon,mday,hour,min,sec);
  LOG_INFO("time (own): %d\n",(int)now);

  set_unix_time(now);
}

void proc_xyouraddress(char *bf,int r) {
  bf[r]=0;
  auto c=cut(bf);
  if(c.size()>1) {
    auto a=string_to_ipv4(c[1]);
    if(!match(my_ip.ipv4,(const unsigned char*)&a,4)) {
      LOG_INFO("public_ip_address change %s->%s\n",ipv4_to_string(*(in_addr*)my_ip.ipv4).c_str(),c[1].c_str());
    }
    memcpy(my_ip.ipv4,&a,4);
    //printf("public_ip_address %s\n",ipv4_to_string(*(in_addr*)my_ip.ipv4).c_str());
  }
}

string get_public_ip() {
  if(my_ip.isnull())
    return get_public_ip_server();
  return ipv4_to_string(*(in_addr*)my_ip.ipv4);
}

#define DESCR_BAD_CRYPTO -1
#define DESCR_OK 1
#define DESCR_KO 0
#define DESCR_404 -404

struct info_node_t : public ip_info_node_t {
  unsigned char fp[20];
  unsigned char id25519[32];
  unsigned char ntor[32];
  int time=0; //when we downloaded this descriptor, in hours since epoch
  unsigned short flags=0;

  constexpr static unsigned int FL_BAD=1;
  constexpr static unsigned int FL_AUTH=2;
  constexpr static unsigned int FL_EXIT=4;
  constexpr static unsigned int FL_GUARD=8;
  constexpr static unsigned int FL_FAST=16;
  constexpr static unsigned int FL_V2DIR=32;
  constexpr static unsigned int FL_STABLE=64;
  constexpr static unsigned int FL_VALID=128;
  constexpr static unsigned int FL_HSDIR=256;
  constexpr static unsigned int FL_PORT_OK=16384;

  constexpr static unsigned int FL_DIFF=8192; // difference ram/file
  constexpr static unsigned int FL_CONS=32768; //in consensus

  constexpr static unsigned int FL_C_MASK=FL_AUTH|FL_EXIT|FL_GUARD|FL_V2DIR|FL_STABLE|FL_VALID|FL_HSDIR|FL_FAST|FL_PORT_OK;

  void mark_diff() {
    flags|=FL_DIFF;
  }

  void unmark_diff() {
    flags&=~FL_DIFF;
  }
  
  void copy_desc(const info_node_t &node)
  {
    memcpy(fp,node.fp,20);
    memcpy(id25519,node.id25519,32);
    memcpy(ntor,node.ntor,32);
    time=node.time;
  }

  void copy(const info_node_t &node)
  {
    memcpy(ipv4,node.ipv4,4);
    port=node.port;
    dirport=node.dirport;
    copy_desc(node);
    flags=node.flags;
  }
  
  void kill() {
    clear();
  }

  vector<unsigned char> gen_link_specifier(bool ed=1) const {
    vector<unsigned char> ls;

    /*
       NSPEC      (Number of link specifiers)     [1 byte]
         NSPEC times:
           LSTYPE (Link specifier type)           [1 byte]
           LSLEN  (Link specifier length)         [1 byte]
           LSPEC  (Link specifier)                [LSLEN bytes]

   Link specifiers describe the next node in the circuit and how to
   connect to it. Recognized specifiers are:

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

    int n=2;
    if(ed) n++;
    ls.push_back(n);

    ls.push_back(0);
    ls.push_back(6);
    append(ls,ipv4,4);
    append_short(ls,port);

    ls.push_back(2);
    ls.push_back(20);
    append(ls,fp,20);

    if(ed) {
      ls.push_back(3);
      ls.push_back(32);
      append(ls,id25519,32);
    }
    
    return ls;
  }

  bool decode_link_specifier(unsigned char *p,int s) {
    /*
       NSPEC      (Number of link specifiers)     [1 byte]
         NSPEC times:
           LSTYPE (Link specifier type)           [1 byte]
           LSLEN  (Link specifier length)         [1 byte]
           LSPEC  (Link specifier)                [LSLEN bytes]

   Link specifiers describe the next node in the circuit and how to
   connect to it. Recognized specifiers are:

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
    bool idok=0;
    bool idedok=0;
    bool ipok=0;
    if(s<1) return 0;
    int n=p[0];p++;s--;
    for(int i=0;i<n;i++) {
      if(s<2) return 0;
      int l=p[1];
      int t=p[0];
      p+=2;
      s-=2;
      switch(t) {
      case 0:
	if(l<6) return 0;
	ipok=1;
	memcpy(ipv4,p,4);
	port=toshort(p+4);
	break;
      case 2:
	if(l<20) return 0;
	idok=1;
	memcpy(fp,p,20);
	break;
      case 3:
	if(l<32) return 0;
	idedok=1;
	memcpy(id25519,p,32);
	break;
      }
      p+=l;
      s-=l;
    }
    
    return idok && idedok && ipok;
  }

  static string flags2str(int f) {
    if(f<0) return "NULL";
    string r="";
    if(f&FL_BAD) r=r+("BAD ");
    if(f&FL_AUTH) r=r+("AUTH ");
    if(f&FL_EXIT) r=r+("EXIT ");
    if(f&FL_GUARD) r=r+("GUARD ");
    if(f&FL_FAST) r=r+("FAST ");
    if(f&FL_V2DIR) r=r+("V2DIR ");
    if(f&FL_STABLE) r=r+("STABLE ");
    if(f&FL_VALID) r=r+("VALID ");
    if(f&FL_HSDIR) r=r+("HSDIR ");
    if(f&FL_PORT_OK) r=r+("PORT_OK ");
    if(f&FL_CONS) r=r+("CONS ");
    if(f&FL_DIFF) r=r+("DIFF ");
    return r;
  }
  
  string info_str() const {
    auto ip=ipv4_to_string(*(in_addr*)ipv4);
    char bf[256];
    snprintf(bf,255,"%16s:%5d ",ip.c_str(),port);
    return bf+string(" ")+to_str(fp,20);
  }

  void print_info() const { 
    auto ip=ipv4_to_string(*(in_addr*)ipv4);
    printf("%16s:%5d (%05d) time=%d ok=%d nr=%f\n",ip.c_str(),port,dirport,time,is_ok(),need_refresh());
    printf("%s\n",flags2str(flags).c_str());
    printf("\n");
    ::print("fp ",fp,20);
    ::print("id25519 ",id25519,32);
    ::print("ntor ",ntor,32);
  }

  bool is_ok() const { //is_ok returns 1 if the node has an IP and a fingerprint
    if(isnull()) return 0;
    int r=0; 
    for(int i=0;i<20;i++)
      r=r|fp[i];
    if(r==0) return 0;
    return 1;
  }

  bool in_consensus() const { 
    return (flags&FL_CONS)==FL_CONS;
  }

  bool need_refresh_rand(float tg,float h=1) {
    auto r=need_refresh();
    if(r<=tg) return 0;
    if(r>=1.) return 1;
    float l=48*(1-r)*h*random_short()/65536.;
    return l<1;
  }
  
  float need_refresh() const {
    if(isnull()) return -1;
    int r=0;

    if(!in_consensus()) return -1;

    r=0;
    for(int i=0;i<32;i++)
      r=r|id25519[i];
    if(r==0) {
#ifndef DISABLE_CACHE
      if(flags&FL_HSDIR) return 10;
#endif
      return 5;
    }
    
    r=0;
    for(int i=0;i<32;i++)
      r=r|ntor[i];
    if(r==0) return 2;

    unsigned long long t=get_unix_time()/3600-time;
    
    if(t>24*6) // 6 days : refresh
      return 1;
    if(t<24*4) //<4 days : no refresh
      return 0;
    t-=24*4;
    return t/48.;
  }
  

#define DIRTYPE 3
#define NODETYPES 3

#define DIRCACHE_FLAGS (FL_V2DIR|FL_FAST)
#define GUARD_FLAGS (FL_GUARD|FL_FAST)
#define EXIT_FLAGS (FL_EXIT|FL_FAST|FL_PORT_OK)
#define MIDDLE_FLAGS (FL_FAST)

  void clear() {
    ip_info_node_t::clear();
    memset(fp,0,20);
    memset(ntor,0,32);
    memset(id25519,0,32);
    time=0;
    flags=0;
  }
  string str() const {
    char bf[60];
    auto ip=ipv4_to_string(*(in_addr*)ipv4);
    auto f=to_str(fp,20);
    snprintf(bf,60,"%16s:%5d (%05d) %s",ip.c_str(),port,dirport,f.c_str());
    return bf;
  }
  info_node_t() {
    clear();
  }
  string fingerprint() const {
    string fingerprint_;

    for(int i=0;i<20;i++) {
      char x[5];
      snprintf(x,4,"%02x",fp[i]);
      fingerprint_+=x;
    }
    return fingerprint_;
  }

  bool is_hsdir() const {
    return (flags&FL_HSDIR);
  }

  bool can_be_exit() const {
    return (flags&EXIT_FLAGS)==EXIT_FLAGS;
  }
  bool can_be_guard() const {
    return (flags&GUARD_FLAGS)==GUARD_FLAGS;
  }
  bool can_be_middle() const {
    return (flags&MIDDLE_FLAGS)==MIDDLE_FLAGS;
  }
  bool can_be_dir() const {
    if(dirport==0) return false;
    return (flags&DIRCACHE_FLAGS)==DIRCACHE_FLAGS;
  }

  void get_hsdir_index(unsigned char *idx,const unsigned char *srv,int tp)
  {
    ::comp_hsdir_index(idx,id25519,srv,tp);
  }

};

bool samenode(const info_node_t &a,const info_node_t &b)
{
  for(int i=0;i<4;i++)
    if(a.ipv4[i]!=b.ipv4[i]) return 0;
  for(int i=0;i<20;i++)
    if(a.fp[i]!=b.fp[i]) return 0;
  return 1;
}

#ifndef DISABLE_CACHE
#define CACHE_SIZE 16384
#define HSDESCR_MAX_SIZE 16384
info_node_t *cache_descs=NULL;
#endif

bool hascachefile=0;

int count_flags(int r)
{
  int nb=0;
  for(int i=0;i<CACHE_SIZE;i++)
    if(cache_descs[i].flags&r)
      nb++;
  return nb;
}

void clear_flag(int r) {
#ifndef DISABLE_CACHE
  for(int i=0;i<CACHE_SIZE;i++)
    cache_descs[i].flags&=~r;
#endif
#ifdef DIR_LOWMEM
  for(int j=0;j<NODETYPES;j++)
    for(int i=0;i<MAX_NODES;i++)
      relays.nodes[j][i].flags&=~r;
#endif
}

void clear_cons_flag() {
  clear_flag(info_node_t::FL_CONS);
}

void clear_diff_flag() {
  clear_flag(info_node_t::FL_DIFF);
}


void save_cache(bool re=0)
{
#ifdef USEFS
  clear_diff_flag();
#ifndef DISABLE_CACHE
  LOG_INFOV("save_cache\n");
  FILE *out=NULL;
  if(re==0) {
    out=fopen(BASEPATH "descs.bin","r+");
    if(!out)
      LOG_WARN("save_cache:fopen r+ %s\n",errno_str(errno).c_str());
    else {
      LOG_DEBUG("fopen " BASEPATH "descs.bin in r+ OK");
      fseek(out,0,SEEK_SET);
    }
  } 
  if(!out) {
    out=fopen(BASEPATH "descs.bin","w");
    if(out==NULL) {
      LOG_WARN("save_cache:fopen w %s\n",errno_str(errno).c_str());
      return;
    } else {
      LOG_DEBUG("fopen " BASEPATH "descs.bin in w OK");
    }
  }
  fwrite_secure(cache_descs,1,CACHE_SIZE*sizeof(info_node_t),out);
  fclose(out);
  hascachefile=1;
  LOG_INFOV("save_cache done\n");
#endif
#endif
}

// void save_cache()
// {
//   list_dirs();
// // #ifndef ESP
//    save_cache(0);
// // #else
//    //save_cache(1);
//   //#endif
// }

void read_cache() {
#ifdef USEFS
  list_dirs();
#ifndef DISABLE_CACHE
  FILE *in=fopen(BASEPATH "descs.bin","r");
  if(!in) {
    LOG_WARN("fopen: %s\n", errno_str(errno).c_str());
    return;
  }
  LOG_INFOV("cache file present\n");
  hascachefile=1;

  for(int i=0;i<CACHE_SIZE;i++)
    cache_descs[i].kill();
    
  int n=fread(cache_descs,1,CACHE_SIZE*sizeof(info_node_t),in);
  
  if(n!=CACHE_SIZE*sizeof(info_node_t)) {
    int i=n/sizeof(info_node_t);
    cache_descs[i].kill();
    LOG_WARN("cache file not complete nfread rets=%d i=%d\n",n,i);
    hascachefile=0;
  }
  fclose(in);
#endif
#endif
}

void cache_printtab();

void save_diff_cache() {
#ifdef USEFS
#ifndef DISABLE_CACHE
  LOG_INFOV("save_diff_cache\n");
  //cache_printtab();
  
  if(hascachefile==false) {
    save_cache();
    return;
  }
  int nb=count_flags(info_node_t::FL_DIFF);
  LOG_INFOV("%d nodes diff in cache\n",nb);
  if(nb>1024) {
    LOG_INFOV("too many changes, save all\n");
    save_cache();
    return ;
  }
  if(nb<32) {
    LOG_INFOV("too few changes, dont save\n");
    return ;
  }

  FILE *out=fopen(BASEPATH "descs.bin","r+");
  if(!out) {
    LOG_WARN("save_diff_cache:fopen %s\n",errno_str(errno).c_str());
    return;
  }
  for(int i=0;i<CACHE_SIZE;i++) {
    if(cache_descs[i].flags&info_node_t::FL_DIFF) {
      cache_descs[i].unmark_diff();
      //printf("====%d====\n",i);      cache_descs[i].print_info();
      fseek(out,sizeof(info_node_t)*i,SEEK_SET);
      assert(ftell(out)==sizeof(info_node_t)*i);
      fwrite_secure(cache_descs+i,1,sizeof(info_node_t),out);
      assert(ftell(out)==sizeof(info_node_t)*(i+1));
    }
  }
  LOG_INFOV("save_diff_cache done\n");

  fclose(out);
#endif
#endif
}

bool force_save_cache() {
#ifndef DISABLE_CACHE
  if(hascachefile==false)
    return 1;
  int nb=count_flags(info_node_t::FL_DIFF);
  return nb>=256;
#endif
  return 0;
}

void print_cached() {
#ifndef DISABLE_CACHE
  unsigned char fp[20];
  memset(fp,0,20);
  for(int i=0;i<CACHE_SIZE;i++)
    if(memcmp(fp,cache_descs[i].fp,20)) {
      printf("cache %d:\n",i);
      cache_descs[i].print_info();
    }
#endif
}

#ifndef DISABLE_CACHE
info_node_t *find_desc_cache(const unsigned char *fp) {
  //print(" ",fp,20);
  for(int u=0;u<30;u++) {
    unsigned short i=toshort(fp+u)%CACHE_SIZE;
    if(0==memcmp(fp,cache_descs[i].fp,20)) {
      //printf("ret %d\n",i);
      return &(cache_descs[i]);
    }
  }
  //printf("ret null\n");
  return NULL;
}

int get_free_desc_cache(const unsigned char *fp) {
  int b=-1;
  int bp=11;
  int bu=-1;
  for(int u=0;u<19;u++) {
    unsigned short i=toshort(fp+u)%CACHE_SIZE;
    int p=10;
    if(isnull(cache_descs[i].fp,20)) {
      p=0;
    } else if(cache_descs[i].in_consensus()) {
	p=1;
    } else {
      if(cache_descs[i].is_hsdir()==false)
	p=5;
    }
    if(p<bp) {
      bp=p;
      b=i;
      bu=u;
    }
  }
  if(bp>=5) {
    LOG_WARN("get_free_desc_cache warn p=%d b=%d bu=%d\n",bp,b,bu);
    //print(" ",fp,20);
  }
  return b;
}
#endif

void cache_printtab() {
#ifndef DISABLE_CACHE
  map<unsigned int,int> m;
  for(int i=0;i<CACHE_SIZE;i++) {
    int r=-1;
    if(cache_descs[i].is_ok()) {
      r=cache_descs[i].flags;
    }
    m[r]++;
  }
  for(auto &it:m)
    printf("%s : %d\n",info_node_t::flags2str(it.first).c_str(),it.second);
#endif
#if 0 //ndef DISABLE_CACHE
  unsigned char fp[20];
  memset(fp,0,20);
  for(int i=0;i<8000 /*CACHE_SIZE*/;i++) {
    int r=-1;
    if(cache_descs[i].is_ok()==0) {
      printf("\e[40m");
      printf("\e[39m");
      printf(" ");
      continue;
    }
    float nr=cache_descs[i].need_refresh();
    if(nr<0.) {
      printf("\e[40m");
    } else if(nr>=0.9999) { // red: to refresh
      printf("\e[41m");
    } else if(nr<=0.00001) {
      printf("\e[42m"); //green : <4 days
    } else
      printf("\e[43m"); //orange 4..6 days 
      
    if(cache_descs[i].flags&info_node_t::FL_CONS) {
      printf("\e[37m");
    } else {
      printf("\e[31m");
    }

    char c='m';
    if(cache_descs[i].flags&info_node_t::FL_GUARD) c='g';
    if(cache_descs[i].flags&info_node_t::FL_EXIT) {
      c='e';
      if(cache_descs[i].flags&info_node_t::FL_PORT_OK)
	c='f';
    }
    
    printf("%c",c);
  }
  printf("\n");

  printf("\e[37m");
  printf("\e[40m");
#endif


}

typedef info_node_t info_relay_t;

class relay_t : public info_relay_t {
public:
  string str_ipv4() {
    return ipv4_to_string(*(in_addr*)ipv4);
  }
  
  relay_t(const info_relay_t &node)
  {
    info_relay_t::copy(node);
  }
  		
  skin_ctx_t skin;

  struct handshake_keys_t { //temporary keys for the handshake
    unsigned char CURVE25519_PUBLIC_KEY[32];
    unsigned char CURVE25519_PRIVATE_KEY[32];
    
    /** SERVER's PK received within CREATED2 or EXTENDED2 */
    unsigned char CREATED_EXTENDED_RESPONSE_SERVER_PK[32];
    /** SERVER's AUTH received within CREATED2 or EXTENDED2 */
    unsigned char CREATED_EXTENDED_RESPONSE_SERVER_AUTH[32];

    ~handshake_keys_t() {    }

  };

  handshake_keys_t *tk=NULL;

  void free_temp() {
    DELCLEAR(tk);
  }

  void allocate_temp() {
    if(tk==NULL)
      tk=new handshake_keys_t();
  }
  
  relay_t() {  }
  

  ~relay_t() {
    free_temp();

  }

  void ECDH_Curve25519_GenKeys() {
    allocate_temp();
    random_tab(tk->CURVE25519_PRIVATE_KEY,32);
    ed25519_prepare(tk->CURVE25519_PRIVATE_KEY);
    c25519_smult(tk->CURVE25519_PUBLIC_KEY, c25519_base_x, tk->CURVE25519_PRIVATE_KEY);
  }

  bool finish_handshake(const unsigned char *created2_extended2_payload,int len) {
    /*
      A CREATED2 cell contains:

      HLEN      (Server Handshake Data Len) [2 bytes]
      HDATA     (Server Handshake Data)     [HLEN bytes]

      where HDATA with ntor protocol is:
			
      SERVER_PK   Y                       [G_LENGTH bytes] => 32 bytes
      AUTH        H(auth_input, t_mac)    [H_LENGTH bytes] => 32 bytes
    */

    // In future may change...
    constexpr unsigned int G_LENGTH = 32;
    constexpr unsigned int H_LENGTH = 32;

    // Check if data is enough WARNING: in future the length may change!
    if (len < 2+G_LENGTH+H_LENGTH) {
      LOG_WARN("Error, CREATED2 contains inconsistent payload (%u bytes against %u expected). Failure.\n", len, 2+G_LENGTH+H_LENGTH);
      return false;
    }

    unsigned short HLEN = 0;
    HLEN += static_cast<unsigned short>( created2_extended2_payload[0] << 8 );
    HLEN += static_cast<unsigned short>( created2_extended2_payload[1] );

    // Check HLEN consistent
    if (HLEN != G_LENGTH+H_LENGTH) {
      LOG_WARN("Error, CREATED2 contains inconsistent HLEN payload (%u bytes against %u expected). Failure.\n", HLEN, G_LENGTH+H_LENGTH);
      return false;
    }

    // Prepare and copy first G_LENGTH bytes
    for(int i=0;i<32;i++)
      tk->CREATED_EXTENDED_RESPONSE_SERVER_PK[i]=created2_extended2_payload[2+i];
		
    {
      //      if(dbg_certs>2) printf("Relay's PK: ");
      //if(dbg_certs>2) print(tk->CREATED_EXTENDED_RESPONSE_SERVER_PK,32);
    }

    // And the other H_LENGTH 32 bytes
    for(int i=0;i<32;i++)
      tk->CREATED_EXTENDED_RESPONSE_SERVER_AUTH[i]=created2_extended2_payload[2+32+i];

    {
      //if(dbg_certs>2) printf("Relay's AUTH: ");
      //if(dbg_certs>2) print(tk->CREATED_EXTENDED_RESPONSE_SERVER_AUTH,32);
    }

    // Do the calculations needed to finish the handshake

    /*
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

#define PROTOID "ntor-curve25519-sha256-1"

    const char *t_mac = (PROTOID ":mac");
    const char *t_key=(PROTOID ":key_extract");
    const char *t_verify = (PROTOID ":verify");
    const char *m_expand=(PROTOID ":key_expand");

    // WARNING: mbedtls uses big endian format for computation but the tor protocol
    // exchanged keys are always in little endian so must be reversed!
    // (too many time spent on understanding why never work)

    /*
      The server's handshake reply is:

      SERVER_PK   Y                       [G_LENGTH bytes]
      AUTH        H(auth_input, t_mac)    [H_LENGTH bytes]
		
      and computes:
      secret_input = EXP(Y,x) | EXP(B,x) | ID | B | X | Y | PROTOID
    */

    vector<unsigned char> secret_input;

    // append EXP(Y,x)
    unsigned char tmp[32];
    c25519_smult(tmp, tk->CREATED_EXTENDED_RESPONSE_SERVER_PK, tk->CURVE25519_PRIVATE_KEY);
    append(secret_input,tmp,32);

    // append EXP(B,x)
    c25519_smult(tmp, ntor, tk->CURVE25519_PRIVATE_KEY);
    append(secret_input, tmp,32);
    
    append(secret_input,fp,20);
    append(secret_input,ntor,32);
    append(secret_input,tk->CURVE25519_PUBLIC_KEY,32);
    append(secret_input,tk->CREATED_EXTENDED_RESPONSE_SERVER_PK,32);
    append(secret_input, PROTOID);

    /* verify = H(secret_input, t_verify) */
    auto verify = HMAC_SHA256(secret_input, (const unsigned char *)t_verify, strlen(t_verify));

    /* auth_input = verify | ID | B | Y | X | PROTOID | "Server" */
		
    vector<unsigned char> auth_input;
    append(auth_input,verify);
    append(auth_input,fp,20);
    append(auth_input,ntor,32);
    append(auth_input,tk->CREATED_EXTENDED_RESPONSE_SERVER_PK,32);
    append(auth_input,tk->CURVE25519_PUBLIC_KEY,32);
    append(auth_input, PROTOID);
    append(auth_input, "Server");

    bool ok=1;
    
    /* The client verifies that AUTH == H(auth_input, t_mac). */
    auto auth_verify = HMAC_SHA256(auth_input, (const unsigned char *)t_mac,strlen(t_mac));
    if(memcmp(auth_verify.data(),tk->CREATED_EXTENDED_RESPONSE_SERVER_AUTH,32)) {
      LOG_WARN("AUTH and H(auth_input, t_mac) not matching!\n");
      ok=0;
    }

    LOG_INFOV("Relay response to CREATE2/EXTEND2 verified (success).\n");
	
    /*
      The client then checks Y is in G^* =======>>>> Both parties check that none of the EXP() operations produced the 
      point at infinity. [NOTE: This is an adequate replacement for checking Y for group membership, if the group is curve25519.]
    */

    // This is satisfied when Z is set to 1 (see ECDH_Curve25519_ComputeSharedSecret function body)
    // Would throw error if infinity

    /* 
       Both parties now have a shared value for KEY_SEED.  They expand this
       into the keys needed for the Tor relay protocol, using the KDF
       described in 5.2.2 and the tag m_expand. 

       [...]

			
       For newer KDF needs, Tor uses the key derivation function HKDF from
       RFC5869, instantiated with SHA256.  (This is due to a construction
       from Krawczyk.)  The generated key material is:

       K = K_1 | K_2 | K_3 | ...

       Where H(x,t) is HMAC_SHA256 with value x and key t
       and K_1     = H(m_expand | INT8(1) , KEY_SEED )
       and K_(i+1) = H(K_i | m_expand | INT8(i+1) , KEY_SEED )
       and m_expand is an arbitrarily chosen value,
       and INT8(i) is a octet with the value "i".

       In RFC5869's vocabulary, this is HKDF-SHA256 with info == m_expand,
       salt == t_key, and IKM == secret_input.
    */

    const unsigned short KEY_LEN = 16;
    const unsigned short HASH_LEN = 20;
    const unsigned short DIGEST_LEN = 32; // TODO : did not found any reference to DIGEST_LEN size, suppose 32 with sha256
    const unsigned short EXTRACT_TOTAL_SIZE = HASH_LEN+HASH_LEN+KEY_LEN+KEY_LEN+DIGEST_LEN;

    vector<unsigned char> hkdf(EXTRACT_TOTAL_SIZE);

    //enable mbedtls HLDF in idf.py menuconfig !!
    
    mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
		 (const unsigned char*)t_key, strlen(t_key),
		 secret_input.data(), secret_input.size(), 
		 (const unsigned char*)m_expand,strlen(m_expand),
		 hkdf.data(), hkdf.size()
		 );

    /*
      When used in the ntor handshake, the first HASH_LEN bytes form the
      forward digest Df; the next HASH_LEN form the backward digest Db; the
      next KEY_LEN form Kf, the next KEY_LEN form Kb, and the final
      DIGEST_LEN bytes are taken as a nonce to use in the place of KH in the
      hidden service protocol.  Excess bytes from K are discarded.
    */
		
    skin.init_v2(hkdf.data());

    memcpy(skin.KH,hkdf.data()+20*2+16*2,32);
    
#undef PROTOID

    free_temp();

    return ok;
  }

};


struct auth_node_t : public info_node_t {
  mbedtls_pk_context *dir_key=NULL;
  unsigned char dir[20];
  auth_node_t() {
    clear();
    kill();
  }

  void print_info() const { 
    info_node_t::print_info();
    print("dir ",dir,20);
  }
    
  void clear() {
    memset(dir,0,sizeof(dir));
  }
  ~auth_node_t() {
    del_key();
  }

  void init_key() {
    del_key();
    dir_key=new mbedtls_pk_context();
    mbedtls_pk_init(dir_key);
  }
  
  void del_key() {
    if(dir_key) {
      mbedtls_pk_free(dir_key);
      delete dir_key;
    }
    dir_key=NULL;
  }
};

#define MAX_NODES 64
#define MAX_NODES_DIR 64
#define MAX_NODES_AUTH 16

struct consensus_t {
  auth_node_t nodes_auth[MAX_NODES_AUTH];
#ifdef DIR_LOWMEM
  ip_info_node_t nodes_dir[MAX_NODES_DIR];
  info_relay_t nodes[NODETYPES][MAX_NODES];
  int relays_pos[NODETYPES+1];
#endif
  int est_relays_by_type[NODETYPES+1];
  int auth_pos=0;
  char cons_hour; 
  int srv_period=0;
  float srv_period_f=0;
  unsigned char srv[32],srv_previous[32];
  //map<int,array<unsigned char*,32> > srvs;
  int nblines=45000;
  long long time=0;

  unsigned char *get_srv(int tp) {
    //printf("get_srv arg=%d  local_tp=%d srv_tp=%d/%.3f\n",tp,l_get_time_period(),srv_period,srv_period_f);
    if(cons_hour<12) { // <=> srv_period_f>=0.5
      if(tp==srv_period+1)
	return srv;
      if(tp==srv_period)
	return srv_previous;
    } else {
      //cons-hour>=12 <=> srv_period_f <0.5
      if(tp==srv_period)
	return srv;
      if(tp==srv_period-1)
	return srv_previous;
    }
    
    LOG_SEVERE("get_srv tp=%d returns NULL srv_period=%d cons_hour=%d\n",tp,srv_period,cons_hour);
    return NULL;
  }
  
  void clear_auths() {
    auth_pos=0;
    for(int i=0;i<MAX_NODES_AUTH;i++)
      nodes_auth[i].kill();
  }

  void clean() { //remove nodes not in consensus
#ifdef DIR_LOWMEM
    for(int j=0;j<NODETYPES;j++) {
      for(int i=0;i<MAX_NODES;i++) {
	if(0==(nodes[j][i].flags&info_node_t::FL_CONS))
	  nodes[j][i].kill();
      }
    }
#endif
  }

  void refresh(const consensus_t &r,float refresh_percent=1.)
  {
    nblines=r.nblines;
    time=r.time;
    memcpy(srv,r.srv,32);
    memcpy(srv_previous,r.srv_previous,32);
    srv_period=r.srv_period;
    srv_period_f=r.srv_period_f;
    cons_hour=r.cons_hour;

    for(int i=0;i<MAX_NODES_AUTH;i++) {
      nodes_auth[i]=r.nodes_auth[i];
    }

#ifdef DIR_LOWMEM
    for(int i=0;i<MAX_NODES_DIR;i++)
      nodes_dir[i]=r.nodes_dir[i];
    for(int j=0;j<NODETYPES;j++) {
      small_random_set_t s(MAX_NODES);
      int n=refresh_percent*MAX_NODES;
      for(int i=0;i<MAX_NODES;i++) {
	if(nodes[j][i].isnull()) {
	  while(!s.empty()) {
	    auto v=s.pick();
	    if(!r.nodes[j][v].isnull()) {
	      nodes[j][i]=r.nodes[j][v];
	      n--;
	      break;
	    }
	  }
	}
      }
      for(;n>=0;n--) {
	while(!s.empty()) {
	  auto v=s.pick();
	  if(!r.nodes[j][relays_pos[j]].isnull()) {
	    nodes[j][relays_pos[j]]=r.nodes[j][v];
	    relays_pos[j]=(relays_pos[j]+1)%MAX_NODES;
	    break;
	  }
	}
      }
    }
#endif

  }

  void printtab() const {
#ifdef DIR_LOWMEM
    for(int j=0;j<NODETYPES;j++) {
      for(int i=0;i<MAX_NODES;i++) {
	printf("lowmem cons %d %d\n",j,i);
	nodes[j][i].print_info();
      }
    }	  

    for(int j=0;j<NODETYPES;j++) {
      printf("%d: ",j);
      for(int i=0;i<MAX_NODES;i++) {
	int r=-1;
	if(nodes[j][i].is_ok()==false) r=0;
	else if(nodes[j][i].need_refresh()>0) r=1;
	else r=2;
	printf("%d",r);
      }
      printf("\n");
    }
#endif
  }
  
  void del_dir_keys() {
    for(int i=0;i<MAX_NODES_AUTH;i++)
      nodes_auth[i].del_key();
  }
  
  void print_auths_static() const {
    printf("===>\n");
    for(int i=0;i<MAX_NODES_AUTH;i++) {
      auto &a(nodes_auth[i]);
      //if(a.isnull()) continue;
      a.print_info();
    }
    for(int i=0;i<MAX_NODES_AUTH;i++) {
      auto &a(nodes_auth[i]);
      if(a.isnull()) continue;
      printf("{");
      for(int u=0;u<4;u++)
	printf("0x%02x,",int(a.ipv4[u]));
      printf("0x%02x,0x%02x},\n",(unsigned char)(a.dirport),(unsigned char)(a.dirport>>8));
    }
    printf("===<\n");
  }
  

  void clear() {
    clear_auths();
#ifdef DIR_LOWMEM
    for(int j=0;j<NODETYPES;j++)
      for(int i=0;i<MAX_NODES;i++)
	nodes[j][i].clear();
    memset(relays_pos,0,sizeof(relays_pos));
#endif
    srv_period=0;
    srv_period_f=0;
    memset(srv,0,32);
    memset(srv_previous,0,32);
    memset(est_relays_by_type,0,sizeof(est_relays_by_type));
  }

  consensus_t() {
    clear();
  }

#define VERSIONNUMBER 49

  void write_file(const char *fn) const {
#ifdef USEFS
    int vn=VERSIONNUMBER;
    LOG_INFO("write low memory cons to '%s'\n",fn);
    FILE *out=fopen(fn,"w");
    if(out==NULL) {
      LOG_WARN("fopen: %s\n", errno_str(errno).c_str());
    }
    assert(out);
    fwrite_secure(&vn,1,4,out);
    for(int i=0;i<MAX_NODES_AUTH;i++)
      fwrite_secure(&(nodes_auth[i]),1,sizeof(info_node_t),out);
#ifdef DIR_LOWMEM
    fwrite_secure(nodes_dir,1,sizeof(nodes_dir),out);
    fwrite_secure(nodes,1,sizeof(nodes),out);
    fwrite_secure(est_relays_by_type,1,sizeof(est_relays_by_type),out);
    fwrite_secure(relays_pos,1,sizeof(relays_pos),out);
#endif
    fwrite_secure(&auth_pos,1,sizeof(auth_pos),out); //=

    fwrite_secure(&srv_period,1,sizeof(srv_period),out); //clear
    fwrite_secure(&srv_period_f,1,sizeof(srv_period_f),out); //clear
    fwrite_secure(srv,1,32,out); //clear
    fwrite_secure(srv_previous,1,32,out); //clear

    fwrite_secure(&nblines,1,sizeof(nblines),out); //=
    fwrite_secure(&time,1,sizeof(time),out); //=
    fwrite_secure(&cons_hour,1,sizeof(cons_hour),out);

    fclose(out);
#endif
  }

  bool read_file(const char *fn) {
#ifdef USEFS
    FILE *in=fopen(fn,"r");
    if(!in) {
      LOG_WARN("fopen: %s\n", errno_str(errno).c_str());
      return 0;
    }
    int vn;
    int t=fread(&vn,1,4,in);
    if(t<4 || vn!=VERSIONNUMBER) {
      fclose(in);
      return 0;
    }
    for(int i=0;i<MAX_NODES_AUTH;i++) {
     nodes_auth[i].clear();
      fread(&(nodes_auth[i]),1,sizeof(info_node_t),in);
    }
#ifdef DIR_LOWMEM
    fread(nodes_dir,1,sizeof(nodes_dir),in);
    fread(nodes,1,sizeof(nodes),in);
    fread(est_relays_by_type,1,sizeof(est_relays_by_type),in);
    fread(relays_pos,1,sizeof(relays_pos),in);
#endif
    fread(&auth_pos,1,sizeof(auth_pos),in);
    fread(&srv_period,1,sizeof(srv_period),in);
    fread(&srv_period_f,1,sizeof(srv_period_f),in);
    fread(srv,1,32,in);
    fread(srv_previous,1,32,in);
    fread(&nblines,1,sizeof(nblines),in);
    fread(&time,1,sizeof(time),in);
    fread(&cons_hour,1,sizeof(cons_hour),in);
    fclose(in);
    return 1;
#else
    return 0;
#endif
  }


  
  info_node_t *find_desc(const unsigned char *fp) {
#ifndef DISABLE_CACHE
    return find_desc_cache(fp);
#endif
#ifdef DIR_LOWMEM
    for(int j=0;j<NODETYPES;j++)
      for(int i=0;i<MAX_NODES;i++)
	if(0==memcmp(fp,nodes[j][i].fp,20))
	  return &(nodes[j][i]);
#endif

    return NULL;
  }

  auth_node_t *find_auth_desc(const unsigned char *fp) {
    for(int i=0;i<MAX_NODES_AUTH;i++)
      if(0==memcmp(fp,nodes_auth[i].fp,20))
	return &(nodes_auth[i]);

    return NULL;
  }

  void print() {
    for(int i=0;i<MAX_NODES_AUTH;i++) {
      auto s=nodes_auth[i].str();
      printf("auth  %2d : %s\n",i,s.c_str());
    }
#ifdef DIR_LOWMEM
    for(int i=0;i<NODETYPES;i++)
      printf("#%d : est:%d pos:%d\n",i,est_relays_by_type[i],relays_pos[i]);
    
    for(int j=0;j<NODETYPES;j++) {
      for(int i=0;i<4 && i<MAX_NODES;i++) {
	auto s=nodes[j][i].str();
	printf("nodes[%d] %2d : %s\n",j,i,s.c_str());
      }
    }
#endif
  }
  
};

consensus_t relays;

int get_cons_time_period(float *f=NULL) {
  if(f) (*f)=relays.srv_period_f;
  return relays.srv_period;
}



info_node_t *find_desc(const unsigned char *fp) {
  return relays.find_desc(fp);
}


info_node_t *get_free_desc(const unsigned char *fp_) {
#ifndef DISABLE_CACHE
  auto r=get_free_desc_cache(fp_);
  assert(r>=0 && r<=CACHE_SIZE);
  return cache_descs+r;
#endif
  return NULL;
}


static unsigned char static_auth_tab[][6]={
  {0xc1,0x17,0xf4,0xf4,0x50,0x00},
  {0x56,0x3b,0x15,0x26,0x50,0x00},
  {0xc7,0x3a,0x51,0x8c,0x50,0x00},
  {0xcc,0x0d,0xa4,0x76,0x50,0x00},
  {0xab,0x19,0xc1,0x09,0xbb,0x01},
  {0x80,0x1f,0x00,0x22,0xab,0x23},
  {0x2d,0x42,0x21,0x2d,0x50,0x00},
  {0x83,0xbc,0x28,0xbd,0x50,0x00},
  {0x9a,0x23,0xaf,0xe1,0x50,0x00},
};

void one_static_auth(ip_info_node_t &a) {
  int z=random_short()%(sizeof(static_auth_tab)/sizeof(static_auth_tab[0]));
  a.ipv4[0]=static_auth_tab[z][0];
  a.ipv4[1]=static_auth_tab[z][1];
  a.ipv4[2]=static_auth_tab[z][2];
  a.ipv4[3]=static_auth_tab[z][3];
  a.dirport=(int(static_auth_tab[z][5])<<8)+static_auth_tab[z][4];
}


struct set_dir_t {
  struct dir_stat_t : public ip_info_node_t { //a dir with stats
    float tt=0;
    short nbtry=0;
    short nberr=0;
  };

  bool better(dir_stat_t &a,dir_stat_t &b) { //return true if a>b
    if(a.nberr<b.nberr) return true;
    if(a.nberr>b.nberr) return false;
    if(a.nbtry==0) return 1; 
    if(b.nbtry==0) return 0;
    return a.tt/a.nbtry<b.tt/b.nbtry;
  }
  
  vector<dir_stat_t> v;

  void init() {
    v.clear();
#ifdef DIR_LOWMEM
    small_random_set_t s(MAX_NODES_DIR);
    while(!s.empty()) {
      auto j=s.pick();
      if(!relays.nodes_dir[j].isnull()) {
	dir_stat_t d;
	d.ip_info_node_t::operator=(relays.nodes_dir[j]);
	v.push_back(d);
	//printf("D %s\n",d.str().c_str());
	if(v.size()==16) break;
      }
    }
#endif
#ifndef DISABLE_CACHE
    random_set_t sr(CACHE_SIZE);
    for(int i=0;i<16;) {
      if(sr.empty())
	break;
      int j=sr.pick();
      if(cache_descs[j].is_ok() && cache_descs[j].can_be_dir()) {
	i++;
	dir_stat_t d;
	d.ip_info_node_t::operator=(cache_descs[j]);
	v.push_back(d);
      }
    }
#endif
  }
  
  dir_stat_t *select_one_dir() {
    int best=-1;
    if(v.empty())
      return NULL;

    //for(int i=0;i<v.size();i++)      printf("set_dir %d err=%d try=%d time=%f %f\n",i,v[i].nberr,v[i].nbtry,v[i].tt,v[i].tt/v[i].nbtry);

    for(int i=0;i<v.size();i++) {
      if(best<0 || better(v[i],v[best]))
	best=i;
    }
    assert(best>=0);
    return &(v[best]);
  }

  void mark(dir_stat_t &a,bool succ, float time)
  {
    if(!succ) {
      a.nberr++;
      return;
    }
    a.nbtry++;
    a.tt+=time;
  }
};


//todo no double

list<ip_info_node_t> dirs_to_try;

void make_dirs_to_try() {
  dirs_to_try.clear();

  LOG_INFOV("make_dirs_to_try\n");
  
  set<int> s;
#ifdef DIR_LOWMEM
  for(int i=0;i<12;) {
    int j=random_short()%MAX_NODES_DIR;
    if(s.find(j)==s.end()) {
      s.insert(j);
      i++;
      if(!relays.nodes_dir[j].isnull()) {
	//printf("add dir %d\n",j);
	dirs_to_try.push_back(relays.nodes_dir[j]);
	//printf("%s\n",relays.nodes_dir[j].str().c_str());
      }
    }
  }
  s.clear();
#endif
#ifndef DISABLE_CACHE

  int ok=0;
  for(int j=0;j<CACHE_SIZE;j++) {
    if(cache_descs[j].is_ok() && cache_descs[j].can_be_dir())
      ok++;
  }

  LOG_INFOV("#%d hsdirs\n",ok);

  if(ok>500) {
    int p=0;
    for(int i=0;i<8&&p<10000;p++) {
      int j=random_short()%CACHE_SIZE;
      if(s.find(j)==s.end()) {
	s.insert(j);
	//cache_descs[j].print_info();
	if(cache_descs[j].is_ok() && cache_descs[j].can_be_dir()) {
	  i++;
	  dirs_to_try.push_back(cache_descs[j]);
	}
      }
    }
  }
#endif

  ip_info_node_t a;
  one_static_auth(a);
  //printf("%s\n",a.str().c_str());
  //printf("add dir %d\n",j);

  dirs_to_try.push_back(a);  
}

void select_one_dir(ip_info_node_t &a) {
  if(dirs_to_try.empty()) {
    make_dirs_to_try();
  }
  a=dirs_to_try.front();
  //printf("select %s\n",a.str().c_str());
  dirs_to_try.pop_front();
}



struct consdown_t {
  consensus_t &relays;
  info_relay_t node;
  map<array<unsigned char,20>,vector<unsigned char> > map_dir_sigs; 
  unsigned char consensus_digest[20]; 

  int relays_by_type[NODETYPES];
#ifdef DIR_LOWMEM
  int relays_by_type_ok[NODETYPES];
#endif
  int auth_ok=0;
  int cnt_nodes=0; 
  float refresh_percent=1.;

  bool consensus_sigs_ok=0;
  mbedtls_md_context_t ctx_digest;

  bool digest_done=0;
  
  array<unsigned char,20> dir_sig; //TODO STR
  char strkey[65*10];
  unsigned char pemkey[400];
  int keysize=0;
  bool incomplete=0;
  bool issig=0;

  int accept_line=0;
  int accept_reject=0;
  char accept_bf[16]="";
  bool port_match=0;

  char bf[256];
  char bferr[128];

  bool fail=0;
  char body=0;
  bool start_of_line=1;

  unsigned char tmp_in[513];
  unsigned char tmp_out[513];

 
  consdown_t(consensus_t &a):relays(a) {
    LOG_DEBUG("consdown_t()\n");
    clear();
  }

  ~consdown_t() {
  }

  void copy_est() {
    memcpy(relays.est_relays_by_type,relays_by_type,sizeof(relays_by_type));
  }

  void copy_est(const consensus_t &relays_) {
    memcpy(relays.est_relays_by_type,relays_.est_relays_by_type,sizeof(relays_by_type));
  }

  void clear() {
    auth_ok=0;
    cnt_nodes=0; 
    refresh_percent=1.;
    consensus_sigs_ok=0;
    digest_done=0;
    keysize=0;
    incomplete=0;
    issig=0;
    accept_line=0;
    accept_reject=0;
    port_match=0;
    fail=0;
    body=0;
    start_of_line=1;

    node.kill();
    map_dir_sigs.clear();
    memset(relays_by_type,0,sizeof(relays_by_type));
#ifdef DIR_LOWMEM
    memset(relays_by_type_ok,0,sizeof(relays_by_type_ok));
#endif
  }
  
  void print_stats() const {
    if(dir_dbg>2) relays.print_auths_static();
    //printf("%d relays\n",relays);
    printf("%d auth relays found and selected (pos:%d)\n",auth_ok,relays.auth_pos);
    //print_nodes(relays.nodes_auth,MAX_NODES_AUTH);
#ifdef DIR_LOWMEM
    for(int i=0;i<NODETYPES;i++) {
      printf("%d relays of type %d: %d selected (est:%d, pos: %d)\n",relays_by_type[i],i,relays_by_type_ok[i],relays.est_relays_by_type[i],relays.relays_pos[i]);
    }
#endif
  }
  
#ifdef DIR_LOWMEM
  bool save_node_rand(int type) {
    relays_by_type[type]++;
    //printf("save type %d ???\n",type);
    if(frand(1+relays.est_relays_by_type[type]-relays_by_type[type],refresh_percent*MAX_NODES-relays_by_type_ok[type])) {
      //printf("yes %d %d\n",type,cnt_nodes);
      relays_by_type_ok[type]++;
      relays.nodes[type][relays.relays_pos[type]++]=node;
      relays.relays_pos[type]=relays.relays_pos[type]%MAX_NODES;
      return true;
    }
    return false;
  }

  bool save_dir_node_rand() {
    relays_by_type[DIRTYPE]++;
    if(frand(1+relays.est_relays_by_type[DIRTYPE]-relays_by_type[DIRTYPE],refresh_percent*MAX_NODES_DIR-relays_by_type_ok[DIRTYPE])) {
      relays_by_type_ok[DIRTYPE]++;
      relays.nodes_dir[relays.relays_pos[DIRTYPE]++]=node;
      relays.relays_pos[DIRTYPE]=relays.relays_pos[DIRTYPE]%MAX_NODES_DIR;
      return true;
    }
    return false;
  }
#endif
  
  bool check_auth_list(const consensus_t &oldrelays) {
    int nsame=0;
    int nnew=0;
    for(int i=0;i<MAX_NODES_AUTH;i++) {
      if(relays.nodes_auth[i].isnull())
	continue;
      bool ok=0;
      for(int j=0;!ok && j<MAX_NODES_AUTH;j++) {
	if(samenode(relays.nodes_auth[i],oldrelays.nodes_auth[j]))
	  ok=1;
      }
      if(ok) nsame++;
      else nnew++;
    }
    LOG_INFO("auth list : %d known %d new\n",nsame,nnew);
    return nsame>nnew;
  }

  bool check_consensus_sigs() {
    consensus_sigs_ok=0;
    int nok=0;
    int nbad=0;
    for(auto &it:map_dir_sigs) {
      //auto jt=map_dir_keys.find(it.first);
      int i=0;
      for(i=0;i<MAX_NODES_AUTH;i++) {
	if(0==memcmp(relays.nodes_auth[i].dir,it.first.data(),20))
	  break;
      }
      if(i==MAX_NODES_AUTH) {
	LOG_WARN("ERROR : dir-key is absent\n");
	nbad++;
	continue;
      }
      //int ret = mbedtls_rsa_pkcs1_verify( mbedtls_pk_rsa(jt->second), NULL, NULL MBED_RSA_PUB ,MBEDTLS_MD_NONE, 20, consensus_digest, it.second.data() );
      //int mbedtls_pk_verify( mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg,const unsigned char *hash, size_t hash_len,const unsigned char *sig, size_t sig_len );
      if(relays.nodes_auth[i].dir_key) {
	int ret = mbedtls_pk_verify((relays.nodes_auth[i].dir_key),MBEDTLS_MD_NONE, consensus_digest, 20,it.second.data(),it.second.size() );
	
	if(ret) {
	  mbedtls_strerror(ret, bferr, 127);
	  LOG_WARN("bad sig cons : %s \n",bferr);
	  nbad++;
	} else {
	  nok++;
	}
      } else {
	LOG_WARN("no key\n");
	nbad++;
      }
    }
    LOG_INFO("consensus sigs : %d ok / %d bads\n",nok,nbad);
    if(nok>0 && nok>=(nok+nbad)*2/3) {
      consensus_sigs_ok=1;
    }
    return consensus_sigs_ok;
  }


  bool save_node_rand() {
    if(port_match) node.flags|=info_node_t::FL_PORT_OK;

    if((node.flags&info_relay_t::FL_BAD)) {
      return false;
    }

    auto rd=find_desc(node.fp);
    if(rd==NULL)
      rd=get_free_desc(node.fp);
    if(rd) {
      bool ch=0;

      if(!match(rd->fp,node.fp,20)) {
	LOG_DEBUG("change: set fp\n");
	rd->kill();
	memcpy(rd->fp,node.fp,20);
	ch=1;
      } else {
	ch=ch || (rd->port!=node.port);
	ch=ch || (rd->dirport!=node.dirport);
	ch=ch || (!match(rd->ipv4,node.ipv4,4));
	if(ch || (rd->flags&info_node_t::FL_C_MASK)!=(node.flags&info_node_t::FL_C_MASK)) {
	  LOG_DEBUG("flags change %d %s -> %s (%s)\n",int((info_node_t*)rd-cache_descs),info_node_t::flags2str(rd->flags).c_str(),info_node_t::flags2str(node.flags).c_str(),info_node_t::flags2str(rd->flags^node.flags).c_str());
	  ch=1;
	}
      }
      if(ch) {
	rd->port=node.port;
	rd->dirport=node.dirport;
	rd->flags=(rd->flags&~info_node_t::FL_C_MASK)|(node.flags&info_node_t::FL_C_MASK);
	memcpy(rd->ipv4,node.ipv4,4);
	LOG_DEBUG("mark diff i=%d\n",int(rd-cache_descs));
	rd->mark_diff();
      }
      rd->flags|=info_node_t::FL_CONS;
    }

    cnt_nodes++;
    if(node.flags&info_relay_t::FL_AUTH) {
      return 1;
    }

#ifdef DIR_LOWMEM
    if(node.can_be_exit() && port_match) {
      if(save_node_rand(2)) return 1;
    }
    if(node.can_be_guard()) {
      if(save_node_rand(0)) return 1;
    }
    if(node.can_be_middle()) {
      if(save_node_rand(1)) return 1;
    }
    if(node.can_be_dir()) {
      if(save_dir_node_rand()) return 1;
    }
#endif
    return 0;
  }
  
  void proc_node() {
    save_node_rand();
  }

  void nodeclear() {
    node.clear();
  }

  void digest_init() {
    body=0;
    digest_done=0;
    issig=0;

    mbedtls_md_init(&ctx_digest);
    mbedtls_md_setup(&ctx_digest, mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), 0);
    mbedtls_md_starts(&ctx_digest);
  }

  void digest_free() {
    mbedtls_md_free(&ctx_digest);
  }

  void proc3_accept(int u,int v)
  {
    if(exit_port>=u && exit_port<=v) port_match=1;
  }
  
  void proc2_accept(char *a,char *b)
  {
    strncat(accept_bf,a,b-a);
    //printf("%s\n",accept_bf);
    int i=0;
    for(;accept_bf[i];i++) {
      if(accept_bf[i]=='-') break;
    }
    if(accept_bf[i]=='-') {
      int a=atoi(accept_bf);
      int b=atoi(accept_bf+i+1);
      proc3_accept(a,b);
    } else {
      int a=atoi(accept_bf);
      proc3_accept(a,a);
    }
    
    accept_bf[0]=0;
  }

  void proc_accept(char *bf)
  {
    accept_line++;
    if(accept_line==1) {
      port_match=0;
      accept_reject=3;
      if(strncmp(bf,"p accept ",9)==0)
	accept_reject=1;
      if(strncmp(bf,"p reject ",9)==0)
	accept_reject=2;
      bf+=9;
    }

    //printf("%d,%d <%s>",accept_line,accept_reject,bf);
    
    int i=0;
    while(1) {
      int j=i;
      for(;bf[i];i++)
	if(bf[i]==',' || bf[i]==0 || bf[i]=='\n')
	  break;
      if(bf[i]==0) {
	strcpy(accept_bf,bf+j);
	break;
      }
      proc2_accept(bf+j,bf+i);
      if(bf[i]!=',') break;
      i++;
    }

  }

  void end_accept_line()
  {
    accept_line=0;
    if(accept_reject==2) port_match=!port_match;
    if(accept_reject==3) port_match=0;
    if(exit_port==0) port_match=1;
    //printf("port_match : %d, %d\n",accept_reject, port_match);
  }
  
  void procline_consensus(char *bf,int rr)
  {
    if(rr<=0) return;
    bool incomplete=0;
    if(bf[rr-1]!='\n') //incomplete line
      incomplete=1;
    //if(!start_of_line)      printf("not start : %s\n",bf);
    //printf("(%5d) %s\n",keysize,bf);

    const char dirsigstr[]="directory-signature "; // with space !
    if(start_of_line &&  digest_done==0 && strncmp(bf,dirsigstr,strlen(dirsigstr))==0) {
      assert(incomplete==false);
      mbedtls_md_update(&ctx_digest, (const unsigned char*)dirsigstr,strlen(dirsigstr));
      mbedtls_md_finish(&ctx_digest, consensus_digest);
      // if(dir_dbg>3) {
      // 	printf("consensus_digest: ");print(consensus_digest,20);
      // }
      digest_done=1;
    }

    if(digest_done==0 && body) {
      mbedtls_md_update(&ctx_digest, (const unsigned char*)bf,rr);
    }

    if(accept_line) {
      proc_accept(bf);
      start_of_line=(incomplete==0);
      if(incomplete==0)
	end_accept_line();
      return;
    }
    

    if(start_of_line && (bf[0]=='\n' || bf[0]=='\r')) body=1;

    if(issig) {
      assert(start_of_line);
      if(strncmp(bf,"-----BEGIN",10)==0) {

      } else if(strncmp(bf,"-----END",8)==0) {
	size_t res=0;
	int ret=mbedtls_base64_decode(pemkey,sizeof(pemkey)-1,&res, (const unsigned char*)strkey,keysize);
	if(ret) {
	  LOG_WARN("base64 dec error ret=%d res=%d\n",int(ret),int(res));
	} else {
	  assert(res<sizeof(pemkey)-1);

	  map_dir_sigs[dir_sig].resize(res);
	  memcpy(map_dir_sigs[dir_sig].data(),pemkey,res);
	}
	issig=0;
	keysize=0;
      } else {
	if(keysize+strlen(bf)+1<sizeof(strkey)) {
	  memcpy(strkey+keysize,bf,strlen(bf));
	  keysize+=strlen(bf);
	} else {
	  LOG_SEVERE("OVERFLOW\n");
	}
      }
      
      return;
    }

    if(start_of_line) {
      if(bf[0]=='p' && bf[1]==' ') {
	proc_accept(bf);
	start_of_line=(incomplete==0);
	if(incomplete==0) 
	  end_accept_line();
	return;
      } 
      
      auto r=cut(bf);
      if(r.empty()) return;
      if(r[0]=="directory-signature") {
	issig=1;
	if(r.size()>=3) {
	  int ret=hex_to_tab(r[2],dir_sig.data(),20);
	  if(ret!=20) {
	    LOG_SEVERE("ERROR ret!=20\n");
	  }
	}
      
      }

      //"shared-rand-previous-value" SP NumReveals SP Value NL
      //"shared-rand-current-value" SP NumReveals SP Value NL

      if(r[0]=="valid-after" && r.size()>=3) {
	//"20xx-mo-da hh:00:00";
	auto d=cut(r[1],"-");
	auto t=cut(r[2],":");

	long long cons_unix_time;
  	cons_unix_time=date_to_unix_time(atoi(d[0].c_str()),atoi(d[1].c_str()),atoi(d[2].c_str()),atoi(t[0].c_str()));
	relays.cons_hour=atoi(t[0].c_str());

	relays.srv_period=time_period_from_time(cons_unix_time,&relays.srv_period_f);

	LOG_INFO("TTTTT unix time : %Ld / %Ld  %Ld\n",cons_unix_time,get_unix_time(),get_unix_time()-cons_unix_time);

      }
      
      if(r[0]=="shared-rand-previous-value" && r.size()>=3) {
	size_t len=0;
	mbedtls_base64_decode(relays.srv_previous,32,&len,(const unsigned char*)r[2].c_str(),r[2].size());
      }

      if(r[0]=="shared-rand-current-value" && r.size()>=3) {
	size_t len=0;
	mbedtls_base64_decode(relays.srv,32,&len,(const unsigned char*)r[2].c_str(),r[2].size());
      }

      if(r[0]=="dir-source") {
	//0          1      2                                        3           4             5
	//dir-source tor26 14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4 86.59.21.38 86.59.21.38 80 443
	if(r.size()<6) {
	  LOG_WARN("bad dir-source size\n");
	} else {
	  auth_node_t node;

	  int ret=hex_to_tab(r[2],node.fp,20);
	  if(ret!=20) {
	    LOG_WARN("bad fp\n");
	  } else {
	    if(1!=inet_pton(AF_INET,r[4].c_str(),node.ipv4)) {
	      LOG_WARN("bad ip\n");
	    } else {
	      node.dirport=atoi(r[5].c_str());
	      auth_ok++;
	      relays.nodes_auth[relays.auth_pos]=node;
	      relays.auth_pos++;
	      relays.auth_pos=relays.auth_pos%MAX_NODES_AUTH;
	    }
	  }
	}
      }

      if(r[0]=="r") {
	proc_node();
	nodeclear();
	//r inland hL5AONrZmBXXaxERFtrvGq7iUvc dxv1n2V1XVVlIvChetoOQGSqVKk 2022-03-25 03:51:27 139.162.10.190 443 0
	//  1:name 2:identity 3:digest 4: date 5: time 6:ip 7: port 8:dirport
	if(r.size()<9) {
	  LOG_WARN("bad r size\n");
	  node.flags|=info_relay_t::FL_BAD;
	  return;
	}
	size_t res;
	string x=r[2];
	x+="=";
	mbedtls_base64_decode(node.fp,20,&res, (const unsigned char*)x.c_str(),x.size());
	if(res!=20) {
	  LOG_WARN("bad fp size %zu\n",res);
	  node.flags|=info_relay_t::FL_BAD;
	  return;
	}
	node.port=atoi(r[7].c_str());
	node.dirport=atoi(r[8].c_str());
 
	if(1!=inet_pton(AF_INET,r[6].c_str(),node.ipv4)) {
	  LOG_WARN("bad ip\n");
	  node.flags|=info_relay_t::FL_BAD;
	  return;
	}
      
	return;
      }
      if(r[0]=="s") {
	for(auto &it:r) {
	  if(it=="Exit") node.flags|=info_relay_t::FL_EXIT;
	  if(it=="Guard") node.flags|=info_relay_t::FL_GUARD;
	  if(it=="Authority") node.flags|=info_relay_t::FL_AUTH;
	  if(it=="Stable") node.flags|=info_relay_t::FL_STABLE;
	  if(it=="Valid") node.flags|=info_relay_t::FL_VALID;
	  if(it=="Fast") node.flags|=info_relay_t::FL_FAST;
	  if(it=="V2Dir") node.flags|=info_relay_t::FL_V2DIR;
	  if(it=="HSDir") node.flags|=info_relay_t::FL_HSDIR;
	}
	node.flags|=info_relay_t::FL_CONS;

	return;
      }
    }
    start_of_line=(incomplete==0);
  }
  
  int download_consensus_z(ip_info_node_t &node,int timelimit=1000*10)
  {
    //get_tp();

    
    //auto st1=timer_get_ms();
    
    if(node.dirport<=0) return 0;
    if(node.ipv4[0]+node.ipv4[1]+node.ipv4[2]+node.ipv4[3]==0) return 0;
    socket_raw_t sock;
    sock.set_timeout(3000+52,5000+52);
  
    LOG_INFO("download consensus.z from %s (tl=%d)\n",inet_ntoa(*(in_addr*)node.ipv4),timelimit);
    string req=httprequest("/tor/status-vote/current/consensus.z",inet_ntoa(*(in_addr*)node.ipv4),1);

    if(1!=sock.connect_ipv4(*(in_addr*)node.ipv4,node.dirport)) return 0;

    if(!sock.write_string(req)) return 0;


    z_stream stream;
    //printf("sizeof stream: %d\n",sizeof(stream));
    // Init the z_stream
    memset(&stream, 0, sizeof(stream));
    stream.next_in = tmp_in;
    stream.avail_in = 0;
    stream.next_out = tmp_out;
    stream.avail_out = 512;
    stream.zalloc = my_miniz_def_alloc_func;
    stream.zfree = my_miniz_def_free_func;
    
    if (inflateInit(&stream) != Z_OK) {
      LOG_WARN("deflateInit() failed!\n");
      return -1;
    }

#ifndef ESP
    FILE *out=fopen("cons.txt","w");
#else
    FILE *out=NULL;
#endif

    relays.time=get_unix_time();
    
    auto st=timer_get_ms();
    int oldtime=0;

    digest_init();
  
    int nl=0;
    int tt=0;

    newliner_t nwl;

    bool done=0;
    while(!done) {
      int n=sock.read(tmp_in,512);
      if(n<=0) {
	LOG_WARN("sock.read fails n=%d (h)\n",n);
	fail=1;
	break;
      }
      nwl.update((char*)tmp_in,n);
      while(!done) {
	int r=nwl.read((char*)bf,512);
	if(r==0)  break;
	bf[r]=0;
	//printf("HEAD %s",bf);
	if(strncmp(bf,"Date:",5)==0) { 
	  proc_date(bf,r);
	  continue;
	}
	if(strncmp(bf,"X-Your-Address-Is",17)==0) { 
	  proc_xyouraddress(bf,r);
	  continue;
	}
	if(bf[0]=='\r' || bf[0]=='\n') done=1;
	nl++;

	procline_consensus(bf,r);
      }
    }

    if(!fail) {
      int u=nwl.readall((char*)tmp_in,512);
      assert(u<=512);
      stream.next_in = tmp_in;
      stream.avail_in = u;
    }

    while(!fail) {
      if (!stream.avail_in) {
	int n=sock.read(tmp_in,512);
	//printf("read %d\n",n);
	if(n<0) {
	  LOG_WARN("sock.read fails n=%d (bz)\n",n);
	  fail=1;
	  break;
	}
	stream.next_in = tmp_in;
	stream.avail_in = n;
      }
      auto status = inflate(&stream, Z_SYNC_FLUSH);
      //printf("status=%d\n",status);
      if ((status == Z_STREAM_END) || (!stream.avail_out)) {
	int u=512-stream.avail_out;
	tmp_out[u]=0;
	tt+=u;
	//if(nl<100) printf("write %d (%s)\n",u,tmp_out);
	if(out) fwrite_secure(tmp_out,1,u,out);
	nwl.update((char*)tmp_out,u);

	while(1) {
	  int r=nwl.read(bf,255,255);
	  if(r==0)  break;
	  //fwrite(bf,1,r,out2);
	  nl++;
	  bf[r]=0;
	  procline_consensus(bf,r);
	}

	stream.next_out = tmp_out;
	stream.avail_out = 512;
      }
    
      if (status == Z_STREAM_END)
	break;

      if (status != Z_OK) {
	LOG_WARN("status =%d != Z_OK !\n",status);
	break;
      }

      auto time=timer_get_ms()-st;
      if(time>oldtime+1000) {
	float left=float(timelimit-time);
	float estleft=float(time)/nl*(relays.nblines-nl);
	float per=float(nl)/relays.nblines;
	oldtime=time;
	float a=0.8;
	float left2=left*(a+per*(1-a)); //avoid to be "on the edge"
	// if(dir_dbg>0) {
	//   fprintf(stderr,"%d lines in %d ms %f MB/s \n",nl,int(time),float(tt/(time/1000.)/1e6));
	//   fprintf(stderr,"estimated total time: %f ms \n",float(st-st1)+float(time)*relays.nblines/nl);
	//   fprintf(stderr,"percents: %f\n",per*100.);
	//   fprintf(stderr,"left time: %f ms \n",left);
	//   fprintf(stderr,"estimated left time: %f ms \n",estleft);
	// }
	LOG_INFOV("%d lines in %d ms %f MB/s",nl,int(time),float(tt/(time/1000.)/1e6));
	LOG_INFOV(" est %f left %f left2 %f per %f\n",estleft,left,left2,per*100.);
	if(estleft>left2) {
	  LOG_WARN("download consensus timelimit: abort (%d lines downloaded)\n",nl);
	  fail=1;
	  break;
	}
      }
    }

    if(out) fclose(out);
    relays.nblines=nl;

    digest_free();
  
    if (inflateEnd(&stream) != Z_OK) {
      LOG_WARN("inflateEnd() failed!\n");
      return 0;
    }

    if(fail) {
      LOG_WARN("fail !\n");
      return 0;
    }

    if(auth_ok==0) {
      LOG_WARN("error no auths !\n");
      return 0;
    }

    auto time=timer_get_ms()-st;
    LOG_INFO("download ok %d lines in %d ms %f MB/s \n",nl,int(time),float(tt/(time/1000.)/1e6));
    //if(dir_dbg>0) print_stats();
    return 1;
  }
};

struct descproc_t {
  descproc_t() {  }

  mbedtls_md_context_t ctx_digest;

  consensus_t *relays=NULL;
  
  char strkey[65*10];
  unsigned char pemkey[400];
  int keysize=0;

  char bf[256];

#define DIR_SIG_KEY 5
#define ID_KEY 1
#define SIG 2

  mbedtls_pk_context *dir_key=NULL;
  unsigned char dir[20];

  void del_key() {
    if(dir_key) {
      mbedtls_pk_free(dir_key);
      delete dir_key;
    }
    dir_key=NULL;
  }

  ~descproc_t() {
    del_key();
  }

  void init_key() {
    del_key();
    dir_key=new mbedtls_pk_context();
    mbedtls_pk_init(dir_key);
  }

  char bferr[128];
  //auth_node_t *an=NULL;
  bool port_matched=0;
  char body=1;
  
  unsigned char digest[20];

  mbedtls_pk_context rsa_sig_key;
  int nl=0;
  bool gotntor=0;
  bool idok=0;
  bool sigok=0;
  bool sig_key_ok=0;
  bool dir_sig_key_ok=0;
  int iskey=0;
  bool start_of_line=1;
  
  info_node_t node;
  //info_relay_t *r=NULL;
  bool auth=0;
  

  void process_line_descriptor(char *bf,int rr) {
    assert(rr>0);
    //printf("[%d]\n",rr);
    
    bool incomplete=0;
    if(bf[rr-1]!='\n')
      incomplete=1;
    
    bf[rr]=0;

    //printf("{%s}",bf);

    //printf("%d %d %5d: %s",iskey,body,keysize,bf);

    if(body==1)
      mbedtls_md_update(&ctx_digest, (const unsigned char*)bf,rr);
    
    for(int i=0;bf[i];i++)
      if(bf[i]=='\n' || bf[i]=='\r') bf[i]=0;
    if(strlen(bf)==0 && body==0) body=1;
    
    if(iskey) {
      assert(start_of_line);
      if(strncmp(bf,"-----BEGIN",10)==0) {
      } else if(strncmp(bf,"-----END",8)==0) {
	size_t pemsize;
	int ret=mbedtls_base64_decode(pemkey,sizeof(pemkey)-1,&pemsize, (const unsigned char*)strkey,keysize);
	if(ret==0) {
	  assert(pemsize<sizeof(pemkey)-1);
	  mbedtls_md_context_t c;
	  mbedtls_md_init(&c);
	  mbedtls_md_setup(&c, mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), 0);
	  mbedtls_md_starts(&c);
	  mbedtls_md_update(&c, pemkey,pemsize);
	  unsigned char fp[20];
	  mbedtls_md_finish(&c, fp);
	  mbedtls_md_free(&c);
	  //print(fp,20);
	  if(iskey==DIR_SIG_KEY) { 
	    memcpy(dir,fp,20);
	    init_key();
	    int ret=mbedtls_pk_parse_public_key(dir_key,pemkey,pemsize);
	    if(ret) {
	      mbedtls_strerror(ret, bferr, 127);
	      LOG_WARN("rsa_dir_sig_key load fail: %s \n",bferr);
	    } else {
	      dir_sig_key_ok=1;
	    }
	  }
	  if(iskey==ID_KEY) {
	    memcpy(node.fp,fp,20);
	    //if(memcmp(fp,node.fp,20)==0)
	    //
	    idok=1;
	    
	    int ret=mbedtls_pk_parse_public_key(&rsa_sig_key,pemkey,pemsize);

	    if(ret) {
	      mbedtls_strerror(ret, bferr, 127);
	      LOG_WARN("rsa_sig_key load fail: %s \n",bferr);
	    } else
	      sig_key_ok=1;
	  }
	  if(iskey==SIG) {
	    if(sig_key_ok) {
	      int ret = mbedtls_pk_verify(&rsa_sig_key,MBEDTLS_MD_NONE, digest, 20,pemkey,pemsize);
	      if(ret) {
		mbedtls_strerror(ret, bferr, 127);
		LOG_WARN("bad sig : %s \n",bferr);
	      } else
		sigok=1;
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
    } else if(start_of_line) { //not key
      auto c=cut(bf);
      if(c.size()>1 && c[0]=="ntor-onion-key") {
	string x=c[1]+string("=");
	size_t res=0;
	int ret;
	unsigned char ntor[32];
	ret=mbedtls_base64_decode(ntor,32,&res, (const unsigned char*)x.c_str(),x.size());
	if(ret|| res!=32) {
	  LOG_WARN("error base64 ntor key ret=%d res=%d\n",int(ret),int(res));
	} else 
	  gotntor=1;
	memcpy(node.ntor,ntor,32);
      } else if(c.size()>1 && c[0]=="master-key-ed25519") {
	string x=c[1]+string("=");
	size_t res=0;
	int ret=mbedtls_base64_decode(node.id25519,32,&res, (const unsigned char*)x.c_str(),x.size());
	if(ret || res!=32) {
	  LOG_WARN("error base64 id25519 key ret=%d res=%d\n",int(ret),int(res));
	}
      } else if(c.size()>1 && port_matched==0 && (c[0]=="accept"|| c[0]=="reject")) {
	auto d=cut(c[1],":");
	if(d.size()>=2 && d[0]=="*") {
	  if(strstr(d[1].c_str(),"-")) {
	    auto e=cut(d[1],"-");
	    if(e.size()>1) {
	      if(atoi(e[0].c_str())<=exit_port && atoi(e[1].c_str())>=exit_port) 
		port_matched=1;
	    }
	  } else
	    if(d[1]=="*" || atoi(d[1].c_str())==exit_port)
	      port_matched=1;
	  
	}
	if(port_matched) {
	  //printf("port matched : ");
	  if(c[0]=="accept") {
	    node.flags|=info_relay_t::FL_PORT_OK;
	    //printf("accept\n");
	  } else{
	    //printf("reject\n");
	  }
	}
      } else if(c.size()>0 && c[0]=="identity-ed25519") {
	iskey=14;
      } else if(c.size()>0 && c[0]=="onion-key") {
	iskey=13;
      } else if(c.size()>0 && c[0]=="dir-signing-key") {
	iskey=DIR_SIG_KEY;
      } else if(c.size()>0 && c[0]=="signing-key") {
	iskey=ID_KEY;
      } else if(c.size()>0 && c[0]=="dir-identity-key") {
	iskey=ID_KEY;
      } else if(c.size()>0 && c[0]=="router-signature") {
	mbedtls_md_finish(&ctx_digest, digest);
	body=2;
	iskey=SIG;
      } else if(c.size()>0 && c[0]=="dir-key-certification") {
	mbedtls_md_finish(&ctx_digest, digest);
	body=2;
	iskey=SIG;
      }
    } else {
      //printf("not start of line : %s\n",bf);
    }

    start_of_line=(incomplete==0);
    
    nl++;
  }

  void clear() {
    auth=0;
    port_matched=0;
    nl=0;
    gotntor=0;
    idok=0;
    sigok=0;
    sig_key_ok=0;
    dir_sig_key_ok=0;
    body=1;
    iskey=0;
    start_of_line=1;
    //r=NULL;
    //an=NULL;
  }
  

  int st=0;
  void init(bool authh=0) {
    assert(st==0);
    st=1;
    memset(dir,0,sizeof(dir));
    clear();
    auth=authh;
    node.clear();
    node.kill();
    node.flags=0;
    //r=&rr;
    node.flags&=~info_relay_t::FL_PORT_OK;

    //if(auth)
    //  an=static_cast<auth_node_t*>(&rr);

    mbedtls_md_init(&ctx_digest);
    mbedtls_md_setup(&ctx_digest, mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), 0);
    mbedtls_md_starts(&ctx_digest);

    mbedtls_pk_init(&rsa_sig_key);
  }

  int finish() {
    if(st==0) return DESCR_OK;
    st=0;
    mbedtls_md_free(&ctx_digest);
    mbedtls_pk_free(&rsa_sig_key);

    if(idok==0) {
      LOG_WARN("no/bad fingerprint !!!\n");
      return DESCR_BAD_CRYPTO;
    }

    if(sigok==0) {
      LOG_WARN("no/bad signature !!!\n");
      return DESCR_BAD_CRYPTO;
    }

    if(auth && dir_sig_key_ok==0) {
      LOG_WARN("no/bad dir_sig_key !\n");
      return DESCR_BAD_CRYPTO;
    }
  
    if(auth==0 && gotntor==0) {
      LOG_WARN("no/bad ntor !\n");
      return DESCR_BAD_CRYPTO;
    }

    node.time=get_unix_time()/3600;

    if(!auth) {
      auto r=relays->find_desc(node.fp);
      if(r) {
	r->copy_desc(node);
	LOG_DEBUG("mark diff (2) i=%d\n",int(r-cache_descs));
	r->mark_diff();
      } else {
	LOG_WARN("download desc: find_desc returns NULL \n");
      }
    } else {
      auto r=relays->find_auth_desc(node.fp);
      if(r) {
	r->copy_desc(node);
	memcpy(r->dir,dir,20);
	r->del_key();
	//printf("dir key %p\n",dir_key);
	r->dir_key=dir_key;
	dir_key=NULL;
      } else {
	LOG_WARN("download desc: find_auth_desc returns NULL \n");
      }
    }

    
    return DESCR_OK;
  }
  
};


struct multidescdown_t {
  char bf[256];

  int oldtime=0;

  long long st;
  long long totaltime;

  char fail=0;
  int nl=0;

  descproc_t dp;
  int tt=0;

  unsigned char tmp_in[513];
  unsigned char tmp_out[513];
  bool body=0;
  bool auth;
  int timelimit;

  consensus_t *relays=NULL;
  
  void procline(char *bf,int rr) {
    if(!fail) {
      if(strncmp(bf,start,strlen(start))==0) {
	dp.finish();
	dp.init(auth);
	dp.relays=relays;
	body=1;
      }
    }
    if(!fail && body)
      dp.process_line_descriptor(bf,rr);

    auto time=timer_get_ms()-st;
    if(time>oldtime+1000) {
      LOG_INFOV("%d lines in %d ms %f MB/s",nl,int(time),float(tt/(time/1000.)/1e6));
      oldtime=time;
      if(time>timelimit) {
	LOG_WARN("download timelimit: abort (%d lines downloaded)\n",nl);
	fail=1;
      }
    }
  }

  const char *start;

  int download_descriptor_z(ip_info_node_t &dir,set<info_relay_t*> nodes,bool auth=0,int timelimit=1000*10)
  {
    this->auth=auth;
    this->timelimit=timelimit;

    if(dir.dirport<=0) return DESCR_KO;
    if(dir.ipv4[0]+dir.ipv4[1]+dir.ipv4[2]+dir.ipv4[3]==0) return DESCR_KO;
    if(nodes.empty()) return DESCR_OK;
    
    socket_raw_t sock;
    sock.set_timeout(2000+51,5000+51);

    st=timer_get_ms();

    if(1!=sock.connect_ipv4(*(in_addr*)dir.ipv4,dir.dirport)) {
      LOG_WARN("can't connect\n");
      return DESCR_KO;
    }

    string fps;
    for(auto &it:nodes)
      fps+=it->fingerprint()+"+";
    
    fps.pop_back();
    fps+=".z";

    string req= "/tor/server/fp/"+fps;
    if(auth)
      req= "/tor/keys/fp/"+fps;

    LOG_INFO("download %s descriptor %s from %s\n",auth?"auth":"",fps.c_str(),inet_ntoa(*(in_addr*)dir.ipv4));

    req=httprequest(req,inet_ntoa(*(in_addr*)dir.ipv4),1);

    if(sock.write_string(req)==false) {
      LOG_WARN("sock.write_string fail\n");
      return DESCR_KO;
    }

    int httpcode=0;

    if(auth)
      start="dir-key-certificate-version";
    else
      start="router ";


    newliner_t nwl;

    bool done=0;
    while(!done) {
      int n=sock.read(tmp_in,512);
      if(n<=0) {fail=1;break;}
      nwl.update((char*)tmp_in,n);
      while(!done) {
	int r=nwl.read((char*)bf,512);
	if(r==0)  break;
	bf[r]=0;
	//if(nl<1)	  printf("H %s",bf);
	if(strncmp(bf,"X-Your-Address-Is",17)==0) { 
	  proc_xyouraddress(bf,r);
	  continue;
	}
	if(nl==0) {
	  auto c=cut(bf);
	  if(c.size()>1) httpcode=atoi(c[1].c_str());
	}
	if(bf[0]=='\r' || bf[0]=='\n') done=1;
	nl++;
	//procline(bf,r);
      }
    }

    if(httpcode!=200) fail=1;
    
    if(!fail) {
      z_stream stream;
      //printf("sizeof stream: %d\n",sizeof(stream));
      // Init the z_stream
      memset(&stream, 0, sizeof(stream));
      stream.next_in = tmp_in;
      stream.avail_in = 0;
      stream.next_out = tmp_out;
      stream.avail_out = 512;
      stream.zalloc = my_miniz_def_alloc_func;
      stream.zfree = my_miniz_def_free_func;

      if (inflateInit(&stream) != Z_OK) {
	LOG_WARN("deflateInit() failed!\n");
	return -1;
      }

      int u=nwl.readall((char*)tmp_in,512);
      assert(u<=512);
      stream.next_in = tmp_in;
      stream.avail_in = u;


      while(!fail) {
	if (!stream.avail_in) {
	  int n=sock.read(tmp_in,512);
	  //printf("n=%d\n",n);
	  if(n<0) {fail=1;break;}
	  stream.next_in = tmp_in;
	  stream.avail_in = n;
	}
	auto status = inflate(&stream, Z_SYNC_FLUSH);
	//printf("status=%d\n",status);
	if ((status == Z_STREAM_END) || (!stream.avail_out)) {
	  int u=512-stream.avail_out;
	  tmp_out[u]=0;
	  tt+=u;
	  //fwrite(tmp_out,1,u,out1);
	  //print("out ",tmp_out,u);
	  //if(nl<100)
	  //printf("write %d (%s)\n",u,tmp_out);
	  nwl.update((char*)tmp_out,u);

	  while(1) {
	    int r=nwl.read(bf,255,255);
	    if(r==0)  break;
	    //fwrite(bf,1,r,out2);
	    nl++;
	    bf[r]=0;
	    procline(bf,r);
	  }

	  stream.next_out = tmp_out;
	  stream.avail_out = 512;
	}
    
	if (status == Z_STREAM_END)
	  break;
	if (status != Z_OK) {
	  LOG_WARN("status = %d != Z_OK !\n",status);
	  break;
	}

	auto time=timer_get_ms()-st;
	if(time>oldtime+1000) {
	  LOG_INFOV("%d lines in %d ms %f MB/s \n",nl,int(time),float(tt/(time/1000.)/1e6));
	  oldtime=time;
	  if(time>timelimit) {
	    LOG_WARN("download timelimit: abort (%d lines downloaded)\n",nl);
	    fail=1;
	    break;
	  }
	}
      }

      if (inflateEnd(&stream) != Z_OK) {
	LOG_WARN("inflateEnd() failed!\n");
	fail=1;
      }

    }

    dp.finish();


    LOG_INFO("http code : %d\n",httpcode);

    if(httpcode==404) {
      return DESCR_404;
    }

    if(httpcode!=200) {
      return DESCR_KO;
    }
    
    if(fail) {
      LOG_WARN("sock operation failed\n");
      return DESCR_KO;
    }

    unsigned long long time=timer_get_ms()-st;
    totaltime=time;
    LOG_INFO("%d lines in %Ld ms %f MB/s \n",nl,time,tt/(time/1000.)/1e6);

    
    return DESCR_OK;
  }
  
};


bool download_auth_descriptors(consensus_t &relays) {
  set<info_node_t*> sn;
  for(int j=0;j<MAX_NODES_AUTH;j++) {
    if(relays.nodes_auth[j].is_ok()==false) continue;
    sn.insert(&relays.nodes_auth[j]);
  }
  LOG_INFOV("auth sn.size=%d\n",int(sn.size()));
  for(int i=0;i<5;i++) {
    ip_info_node_t a;
    select_one_dir(a);
    multidescdown_t *mdd=new multidescdown_t;
    mdd->relays=&relays;
    int r=mdd->download_descriptor_z(a,sn,1,1000*10);
    delete mdd;
    if(r==DESCR_OK)
      return 1;
  }

  return 0;
}

int download_descriptors(set<info_node_t*> &nodes,set_dir_t &sd) {
  // static int k=0;
  // k++;
  // if(k<10) {
  //   unsigned long long t=get_unix_time()/3600;
  //   printf("download descr for : (now is %d)\n",int(t));
  //   for(auto &it:nodes)
  //     it->print_info();
  // }
  for(int p=0;p<3;p++) {
    auto dir=sd.select_one_dir();
    assert(dir);
    multidescdown_t *mdd=new multidescdown_t;
    mdd->relays=&relays;
    int r=mdd->download_descriptor_z(*dir,nodes,0,10*1000);
    if(r==DESCR_404) {
      delete mdd;
      return r;
    }
    sd.mark(*dir,r==DESCR_OK,mdd->totaltime);
    delete mdd;
    mdd=NULL;
    if(r==DESCR_OK) {
      LOG_INFO("download OK\n");
      // if(k<10) {
      // 	for(auto &it:nodes)
      // 	  it->print_info();
      // }
      //cache_printtab();
      return r;
    }
  }
  return DESCR_KO;
}

#define DL_BUNCH 32

int download_all_descriptors(float tg) {
  //float to=10; //timeout 10s
  set_dir_t sd;
  sd.init();
  int change=0;
  
  set<info_node_t*> nodes;
#ifdef DIR_LOWMEM
  for(int i=0;i<NODETYPES;i++)
    for(int j=0;j<MAX_NODES;j++) {
      if(relays.nodes[i][j].is_ok()==false) {
	relays.nodes[i][j].kill();
	continue;
      }
      LOG_INFO("download descriptor %d %d\n",i,j);
      //relays.nodes[i][j].print_info();
      if(relays.nodes[i][j].need_refresh_rand(tg)==false) {
	LOG_INFO("no need to refresh it\n");
	continue;
      }
      nodes.insert(&relays.nodes[i][j]);
      change++;
      if(nodes.size()>=DL_BUNCH) {
	download_descriptors(nodes,sd);
	nodes.clear();
      }
    }
#endif
  
#ifndef DISABLE_CACHE
  for(int it=0;it<CACHE_SIZE;it++) {
    if(cache_descs[it].flags&info_node_t::FL_CONS) {
      if(cache_descs[it].is_ok()==false) {
	cache_descs[it].kill();
      }
    }

    if(cache_descs[it].need_refresh_rand(tg)) {
      nodes.insert(&cache_descs[it]);
      change++;
      if(nodes.size()>DL_BUNCH) {
	download_descriptors(nodes,sd);
	nodes.clear();
      }
    }
  }
#endif
  if(nodes.size()>0) {
    download_descriptors(nodes,sd);
    nodes.clear();
  }
  return change;
}

struct intro_node_t : public info_node_t {
  unsigned char auth_key[32],enc_key_c[32],enc_key_e[32];
  unsigned char subcred[32];
  //unsigned char enc_secret[64];
  //unsigned char auth_secret[64];
  
  intro_node_t() {
    memset(auth_key,0,32);
    memset(enc_key_c,0,32);
    memset(enc_key_e,0,32);

    //memset(auth_key_secret,0,64);
    //memset(enc_key_secrey,0,64);
  }
  
  void print_info() const {
    info_node_t::print_info();
    ::print("authkey ",auth_key,32);
    ::print("enckeyC ",enc_key_c,32);
    ::print("enckeyE ",enc_key_e,32);
    ::print("subcred ",subcred,32);
    //::print("enckeysecret  ",enc_key_secret,64);
    //::print("authkeysecret ",auth_key_secret,64);
  }
};

struct intro_keys_t { //Secret pairs of intronodes
  info_node_t node;
  onion_key_t auth,enc;
  unsigned char subcred[32];
  void generate() {
    auth.generate();
    enc.generate();
    memset(subcred,0,32);
  }
};


