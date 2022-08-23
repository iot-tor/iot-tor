#pragma once


#include <assert.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <vector>
#include <list>
#include <algorithm>
#include <array>

using namespace std;

#include <mbedtls/aes.h>
#include <mbedtls/base64.h>
#include <mbedtls/certs.h>
#ifndef ESP
#include <mbedtls/config.h>
#endif
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/sha256.h>
#include <mbedtls/ssl.h>
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string>
#include <assert.h>
#include <inttypes.h>
#include <time.h>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <sys/stat.h>
#include <netinet/in.h>

#include <iostream>
#include <memory>
#include <vector>
#include <sstream>
#include <climits>
#include <cstring>
#include <time.h>
#include <fstream>
#include <iomanip>
#include <algorithm>
#include <future>
#include <mutex>
#include <queue>
#include <map>
#include <mbedtls/aes.h>
#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdarg.h>


#define _LOG_FATAL 0
#define _LOG_SEVERE 1
#define _LOG_BUG 2
#define _LOG_WARN 3
#define _LOG_INFO 4
#define _LOG_INFOV 5
#define _LOG_INFOVV 6
#define _LOG_DEBUG 7
#define _LOG_DEBUGV 8 
#define _LOG_DEBUGVV 9 


map<void*,int> _mn; //DEBUG

const char *loglvlstr[]={"FATAL","SEVERE","BUG","WARN","INFO","INFOV","INFOVV","DEBUG","DEBUGV","DEBUGVV"};

#define LOG(lvl,...) log(__FILE__,__PRETTY_FUNCTION__,__LINE__,lvl,__VA_ARGS__)

#define LOG_FATAL(...) log(__FILE__,__PRETTY_FUNCTION__,__LINE__,_LOG_FATAL,__VA_ARGS__)
#define LOG_SEVERE(...) log(__FILE__,__PRETTY_FUNCTION__,__LINE__,_LOG_SEVERE,__VA_ARGS__)
#define LOG_BUG(...) log(__FILE__,__PRETTY_FUNCTION__,__LINE__,_LOG_BUG,__VA_ARGS__)
#define LOG_WARN(...) log(__FILE__,__PRETTY_FUNCTION__,__LINE__,_LOG_WARN,__VA_ARGS__)
#define LOG_INFO(...) log(__FILE__,__PRETTY_FUNCTION__,__LINE__,_LOG_INFO,__VA_ARGS__)
#define LOG_INFOV(...) log(__FILE__,__PRETTY_FUNCTION__,__LINE__,_LOG_INFOV,__VA_ARGS__)
#define LOG_INFOVV(...) log(__FILE__,__PRETTY_FUNCTION__,__LINE__,_LOG_INFOVV,__VA_ARGS__)
#define LOG_DEBUG(...) log(__FILE__,__PRETTY_FUNCTION__,__LINE__,_LOG_DEBUG,__VA_ARGS__)
#define LOG_DEBUGV(...) log(__FILE__,__PRETTY_FUNCTION__,__LINE__,_LOG_DEBUGV,__VA_ARGS__)
#define LOG_DEBUGVV(...) log(__FILE__,__PRETTY_FUNCTION__,__LINE__,_LOG_DEBUGVV,__VA_ARGS__)

int main_dbg=DBGBASE;

#define never_here() {LOG_FATAL("should never be here\n");assert(0);}

void log(const char *file,const char *fn,int line,int lvl, const char* format, ... )
{
  if(lvl>main_dbg) return;
  va_list arglist;
    
  printf("[%s][%s %s:%d ] ",loglvlstr[lvl],file,fn,line);
  va_start( arglist, format );
  vprintf( format, arglist );
  va_end( arglist );
}

string errno_str(int e) {
  char bf[32]="";
  char *r=strerror_r(e,bf,32);
  //printf("errno %d '%s' '%s' errno=%d\n",e,bf,r,errno);
  if(r==NULL) return "(nil)";
  return r;
}

/* debug things .... */

#ifndef LINUX
void esp_memory_info();
#endif

void list_dir(const char* dir_prefix="/spiffs/")
{
  DIR* dir = opendir(dir_prefix);
  if (dir) {
    while (true) {
      struct dirent* de = readdir(dir);
      if (!de) {
	break;
      }
      printf("file %s %s \n",dir_prefix,de->d_name);

      struct stat sb;

      char fn[100];
      strcpy(fn,dir_prefix);
      strncat(fn,de->d_name,99);
      if (stat(fn, &sb) == -1) {
	LOG_WARN("stat: %s\n", errno_str(errno).c_str());
      } else {
	LOG_DEBUG(" size: %lu bytes\n", sb.st_size);
      }
    }
    closedir(dir);
  } else {
    printf("cannot opendir()\n");
  }
}

void list_dirs(){
  list_dir("/spiffs/");
}

/**********/


long long date_to_unix_time(int y,int m,int d,int h=0,int min=0,int s=0)
{
  if(m<=2) {
    m+=12;
    y--;
  }

  long long t=(365*y)+(y/4)-(y/100)+(y/400);
  t+=(30*m)+(3*(m+1)/5)+d;
  t-=719561;
  t*=86400;
  t+=3600*h+60*min+s;

  return t;
}


inline uint64_t timer_get_ms() { 
#ifdef ESP
    return (unsigned long) (esp_timer_get_time() / 1000ULL);
#else
    struct timespec spec;

    clock_gettime(CLOCK_REALTIME, &spec);

    auto s  = spec.tv_sec;
    auto ms = spec.tv_nsec / 1000000; //ns to ms
    return s*1000+ms;
#endif
}

static void print(const char *a, const void *b, int c)
{
  printf("%s",a);
  const unsigned char *bb=(const unsigned char *)b;
  for(int u=0;u<c;u++)
    printf("%02x ",bb[u]);
  printf("\n");
}


#include "c25519.hpp"

inline void vTaskDelay(int y)
{
  usleep(y*1000);
}

#define DELCLEAR(a) {if (a) delete a; a=NULL;}

struct mutex_t {
  pthread_mutex_t m=PTHREAD_MUTEX_INITIALIZER;
  void lock() {
    pthread_mutex_lock(&m);
  }
  void unlock() {
    pthread_mutex_unlock(&m);
  }
};

struct barrier_t {
  pthread_mutex_t m=PTHREAD_MUTEX_INITIALIZER;
  pthread_cond_t c=PTHREAD_COND_INITIALIZER;
  int n;
  barrier_t(int n=2) {
    this->n=n;
  }

  void kill() {
    pthread_mutex_lock(&m);
    n=0;
    pthread_cond_broadcast(&c);
    pthread_mutex_unlock(&m);
  }
  
  void wait() {
    pthread_mutex_lock(&m);
    n--;
    if(n<=0)
      pthread_cond_broadcast(&c);
    else
      while(n>0)
	pthread_cond_wait(&c,&m);
    pthread_mutex_unlock(&m);
  }
};


struct condvar_t {
  pthread_cond_t c=PTHREAD_COND_INITIALIZER;

  void wait(mutex_t &m) {
    pthread_cond_wait(&c,&(m.m));
  }

  bool timedwait(mutex_t &m,int ms)
  {
    //printf("cond_timedwait %d ms\n",ms);

    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
      LOG_WARN("clock_gettime: %s\n", errno_str(errno).c_str());
      return false;
    }
    ts.tv_sec += ms/1000;
    ms=ms%1000;
    ts.tv_nsec += ms*1000*1000;
    ts.tv_sec += ts.tv_nsec/(1000*1000*1000);
    ts.tv_nsec = ts.tv_nsec%(1000*1000*1000);

    int r=pthread_cond_timedwait(&c,&(m.m),&ts);
    //printf("pthread_cond_timedwait error %s r=%d\n",strerror(errno),r);
    
    return r==0;
  }
  
  void broadcast() {
    pthread_cond_broadcast(&c);
  }
};

template<typename C_t>
struct protected_list {
  mutex_t mut;
  condvar_t cond;

  list<C_t> l;

  bool exit=0;

  bool empty() {
    mut.lock();
    auto r=l.empty();
    mut.unlock();
    return r;
  }
  
  void kill() {
    //printf("protected list kill\n");
    exit=1;
    cond.broadcast();
  }
  
  C_t pop(int to=-1) {
    mut.lock();
    while(!exit) {
      //printf("pop... l.empty()=%d\n",l.empty());
      if(l.empty()) {
	if(to<0)
	  cond.wait(mut);
	else {
	  if(!cond.timedwait(mut,to)) {
	    mut.unlock();
	    return NULL;
	  }
	}
      } else {
	auto r=l.front();
	l.pop_front();
	mut.unlock();
	return r;
      }
    }
    mut.unlock();
    return NULL;
  }

  void push_back(C_t a)
  {
    mut.lock();
    l.push_back(a);
    cond.broadcast();
    mut.unlock();
  }

};
  

struct rec_mutex_t {
  pthread_mutex_t m;

  rec_mutex_t() {
    pthread_mutexattr_t mat;
    pthread_mutexattr_init(&mat);
    
    //The type of lock set is recursive
    pthread_mutexattr_settype(&mat, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&m, &mat);
  }
    
  void lock() {
    pthread_mutex_lock(&m);
  }
  void unlock() {
    pthread_mutex_unlock(&m);
  }
};

#include <stdarg.h>

#ifdef MBEDTLS_SSL_IN_CONTENT_LEN
#undef MBEDTLS_SSL_IN_CONTENT_LEN
#endif
#define MBEDTLS_SSL_IN_CONTENT_LEN 4096
        
#ifdef MBEDTLS_SSL_OUT_CONTENT_LEN
#undef MBEDTLS_SSL_OUT_CONTENT_LEN
#endif
#define MBEDTLS_SSL_OUT_CONTENT_LEN 2048


template<class C_t,int n>
struct cvector_t {
  C_t t[n];
  long long start=0;
  long long end=0;
  void clear() {
    start=end=0;
  }

  //void (*cb)(void*)=NULL;
  //void *cbarg=NULL;
  
  int left() const {
    return n-(end-start);
  }

  void push_back(const C_t *a,int l)
  {
    auto e=end%n;
    end+=l;
    if((end-start)>n) {
      printf("cvector overflow !!! \n");
      printf("cvector push_back l=%d tt=%Ld n=%d\n",l,end-start,n);
      assert(0);
    }
    if(e+l>n) {
      memcpy(t+e,a,n-e);
      memcpy(t,a+n-e,l-(n-e));
    } else 
      memcpy(t+e,a,l);
    //if(cb) cb(cbarg);
  }

  void push_back(const vector<C_t> &a) {
    push_back(a.data(),a.size());
  }

  int read(C_t *a,int l) {
    if(l>end-start) {
      l=end-start;
    }
    auto s=start%n;
    if(s+l>n) {
      memcpy(a,t+s,n-s);
      memcpy(a+n-s,t,l-(n-s));
    } else {
      memcpy(a,t+s,l);
    }
    start+=l;
    return l;
  }

  vector<C_t> read(int l) {
    vector<C_t> r;
    r.resize(l);
    l=read(r.data(),l);
    r.resize(l);
    return r;
  }

  // void rollback(int l) {
  //   start-=l;
  // }

  int size() const {
    return end-start;
  }

  int available() const {
    return n-end+start;
  }
};

vector<string> cut(char *bf,const char *del="\t\r\n ") {
  char *r;
  vector<string> ret;
  char *p=strtok_r(bf,del,&r);
  while(p) {
    ret.push_back(p);
    p=strtok_r(NULL,del,&r);
  }
  return ret;
}

vector<string> cut(const string &s,const char *del="\t\r\n ") {
  char *bf=strdup(s.c_str());
  char *r;
  vector<string> ret;
  char *p=strtok_r(bf,del,&r);
  while(p) {
    ret.push_back(p);
    p=strtok_r(NULL,del,&r);
  }
  free(bf);
  return ret;
}

bool is_ipv4_address(const string &a)
{
  for(int i=0;a[i];i++) {
    if(a[i]>='0' && a[i]<='9') continue;
    if(a[i]=='.') continue;
    return 0;
  }
  return 1;
}

string ipv4_to_string(const in_addr& ip) {
  return string(inet_ntoa(ip));
}

in_addr string_to_ipv4(const string& ip) {
  in_addr temp;
  memset(&temp,0,sizeof(temp));
  inet_aton(ip.c_str(), &temp);
  return temp;
}


unsigned int toint(const unsigned char *buffer)
{
  unsigned int r=(static_cast<unsigned int>(buffer[0]) << 24);
  r+= (static_cast<unsigned int>(buffer[1]) << 16);
  r+= (static_cast<unsigned int>(buffer[2]) << 8);
  r+= (static_cast<unsigned int>(buffer[3]));
  return r;
}

unsigned int toshort(const unsigned char *buffer)
{
  unsigned int r= (static_cast<unsigned int>(buffer[0]) << 8);
  r+= (static_cast<unsigned int>(buffer[1]));
  return r;
}


void put1(unsigned char *w,unsigned char b) {
  w[0]=b;
}

void put_short(unsigned char *w,unsigned short x) {
  w[0]=x>>8;
  w[1]=x;
}

void put_int(unsigned char *w,unsigned int x)
{
  w[0]=x>>24;
  w[1]=x>>16;
  w[2]=x>>8;
  w[3]=x;
}

template<typename C_t>
void append(C_t &a,const unsigned char *t,int l)
{
  for(int i=0;i<l;i++)
    a.push_back(t[i]);
}

template<typename C_t>
void append(C_t &a,const vector<unsigned char> &b)
{
  append(a,b.data(),b.size());
}

template<typename C_t>
void append(C_t &a,const char *b)
{
  append(a,(const unsigned char*)b,strlen(b));
}

template<typename C_t>
void append_short(C_t &a,unsigned short b)
{
  a.push_back(b>>8);
  a.push_back(b);
}

template<typename C_t>
void append_int(C_t &a,unsigned int b)
{
  a.push_back(b>>24);
  a.push_back(b>>16);
  a.push_back(b>>8);
  a.push_back(b);
}

mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_entropy_context entropy;

void random_generator_init() {
  mbedtls_entropy_init( &entropy );
  mbedtls_ctr_drbg_init( &ctr_drbg );
  const char *personalization = "slghlxfbgerbk";
  int ret = mbedtls_ctr_drbg_seed( &ctr_drbg , mbedtls_entropy_func, &entropy,
                 (const unsigned char *) personalization,
			       strlen( personalization ) );
  if( ret != 0 ) {
    printf("ERROR INIT RANDOM GENERATOR\n");
  }
  
}

void random_tab(unsigned char *t,int n)
{
  int r=mbedtls_ctr_drbg_random(&ctr_drbg,t,n);
  assert(r==0);
}

string base64(unsigned char *t,int n,bool teq=1)
{
  char t2[2*n];
  size_t ol=0;
  int r=mbedtls_base64_encode((unsigned char*)t2,2*n,&ol,t,n);
  assert(r==0 &&ol<=2*n);
  if(teq==0) {
    while(t2[ol-1]=='=') ol--;
  }
  t2[ol]=0;
  return t2;
}

string random_b64(int n,bool teq=1)
{
  unsigned char t[n];
  random_tab(t,n);
  return base64(t,n,teq);
}

unsigned short random_short() {
  unsigned short r;
  random_tab((unsigned char*)&r,sizeof(r));
  return r;
}

unsigned short random_byte() {
  unsigned char r;
  random_tab((unsigned char*)&r,sizeof(r));
  return r;
}

unsigned int random_int() {
  unsigned int r;
  random_tab((unsigned char*)&r,sizeof(r));
  return r;
}

float frand() {
  auto u=float(random_int())/65536./65536.;
  return u;
}

bool frand(int l,int s) {
  if(s<=0) return false;
  if(l<=0) l=1;
  if(s>l) return 1;
  return frand()<float(s)/l;
}

string to_str(const unsigned char *buffer,int len) {
  char bf[2*len+1];
  for (unsigned int i=0;i<len;i++) {
    sprintf(bf+2*i,"%02X", buffer[i]);
  }
  return bf;
}

string to_str(const vector<unsigned char>& buffer) {
  return to_str(buffer.data(),buffer.size());
}

void print(const vector<unsigned char>& buffer)
{
  auto r=to_str(buffer);
  printf("%s\n",r.c_str());
}

void print(const unsigned char *buffer,int len)
{
  auto r=to_str(buffer,len);
  printf("%s\n",r.c_str());
}

int h2i(char c)
{
  if(c>='0' && c<='9') return c-'0';
  if(c>='a' && c<='f') return c-'a'+10;
  if(c>='A' && c<='F') return c-'A'+10;
  return -1;
}

int hex_to_tab(const string &str, unsigned char *out,int maxlen ) {
  int p=0;
  for(int i=0;i+1<str.size()&&p<maxlen;i+=2) {
    int a=h2i(str[i]);
    int b=h2i(str[i+1]);
    if(a<0 || b<0) break;
    a=a*16+b;
    out[p]=a;
    p++;
  }
  return p;
}

long long deltatime=0;

void set_unix_time(unsigned long long t) {
#ifndef LINUX
#ifndef USENTP
  unsigned long long tt=timer_get_ms()/1000;
  deltatime=t-tt;
  LOG_INFO("set deltatime to %d = (from cons) %d - (get_ms/1000) %d\n",int(deltatime),int(t),int(tt));
#endif
#endif
}

unsigned long long get_unix_time() {
  time_t now;
#ifdef USENTP
  time(&now);
#else
#ifdef LINUX
  time(&now);
#else
  now=timer_get_ms()/1000;
  now+=deltatime;
#endif
#endif
  return now;
}

unsigned int time_period_from_time(long long ut,float *f=NULL) {
  /*
   Example: If the current time is 2016-04-13 11:15:01 UTC, making the seconds
   since the epoch 1460546101, and the number of minutes since the epoch
   24342435.  We then subtract the "rotation time offset" of 12*60 minutes from
   the minutes since the epoch, to get 24341715. If the current time period
   length is 1440 minutes, by doing the division we see that we are currently
   in time period number 16903.

   Specifically, time period #16903 began 16903*1440*60 + (12*60*60) seconds
   after the epoch, at 2016-04-12 12:00 UTC, and ended at 16904*1440*60 +
  (12*60*60) seconds after the epoch, at 2016-04-13 12:00 UTC.
  */
  unsigned int r=ut/60;
  r-=12*60;
  if(f)
    (*f)=(r%1440)/1440.;
  r/=1440;
  return r;
}

unsigned int l_get_time_period(float *f=NULL) {
  return time_period_from_time(get_unix_time(),f);
}


bool isnull(const unsigned char *p,int q)
{
  int r=0;
  for(int i=0;i<q;i++)
    r=r|p[i];
  return r==0;
}

bool match(const unsigned char *a,const unsigned char *b,int l)
{
  int r=0;
  for(int i=0;i<l;i++)
    r=r|(a[i]^b[i]);
  return r==0;
}

static unsigned long long bswap_64(unsigned long long a)
{
  unsigned long long r;
  for(int i=0;i<8;i++)
    ((unsigned char*)&r)[i]=((unsigned char*)&a)[7-i];
  return r;
}

#include <endian.h>    // __BYTE_ORDER __LITTLE_ENDIAN

static unsigned long long htonll(unsigned long long a)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
  return bswap_64(a);
#elif __BYTE_ORDER == __BIG_ENDIAN
  return a;
#else
#error "__BYTE_ORDER unset"
#endif
}

void SHA256(unsigned char *digest, const unsigned char *input,int len) {	
  mbedtls_md_context_t mdCtx;
  mbedtls_md_init(&mdCtx);
  mbedtls_md_setup(&mdCtx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
  mbedtls_md_starts(&mdCtx);
  mbedtls_md_update(&mdCtx, input, len);
  mbedtls_md_finish(&mdCtx, digest);
  mbedtls_md_free(&mdCtx);
}


// void SHA_1(unsigned char *digest, const unsigned char *input,int len) {	
//   mbedtls_md_context_t mdCtx;
//   mbedtls_md_init(&mdCtx);
//   mbedtls_md_setup(&mdCtx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), 0);
//   mbedtls_md_starts(&mdCtx);
//   mbedtls_md_update(&mdCtx, input, len);
//   mbedtls_md_finish(&mdCtx, digest);
//   mbedtls_md_free(&mdCtx);
// }



#include "sha3.hpp"

void H_SHA3_256(unsigned char *out,const unsigned char *a,int la,const unsigned char *b=NULL,int lb=0,const unsigned char *c=NULL,int lc=0,const unsigned char *d=NULL,int ld=0) {
  sha3_ctx_t ctx;
  sha3_init(&ctx,32); //SHA3_256);
  if(la==-1) la=strlen((const char*)a);
  if(lb==-1) lb=strlen((const char*)b);
  if(lc==-1) lc=strlen((const char*)c);
  if(ld==-1) ld=strlen((const char*)d);
  sha3_update(&ctx,a,la);
  if(b)
    sha3_update(&ctx,b,lb);
  if(c)
    sha3_update(&ctx,c,lc);
  if(d)
    sha3_update(&ctx,d,ld);

  sha3_final(out,&ctx);
}


struct newliner_t {
  int r=0;
  char bf[1024];

  void update(const char *b,int len)
  {
    assert(r+len<=1024);
    memcpy(bf+r,b,len);
    r+=len;
  }

  int read(char *b,int maxlen,int force=-1)
  {
    for(int i=0;i<r;i++) {
      if(bf[i]=='\n'||bf[i]==0||i==force) {
	i+=1;
	memcpy(b,bf,i);
	if(r>i)
	  memmove(bf,bf+i,r-i);
	r-=i;
	return i;
      }
    }
    return 0;
  }

  int readall(char *b,int maxlen)
  {
    auto r2=r;
    memcpy(b,bf,r);
    r=0;
    return r2;
  }

};

int dbg_certs=2;

vector<unsigned char> HMAC_SHA256(const vector<unsigned char>& input, const unsigned char *key,int keylen) {	
  vector<unsigned char> digest(32);
  mbedtls_md_context_t mdCtx;
  memset(&mdCtx,0,sizeof(mdCtx));
  mbedtls_md_setup(&mdCtx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1); // last 1: specify hmac
  mbedtls_md_hmac_starts(&mdCtx, key, keylen);
  mbedtls_md_hmac_update(&mdCtx, input.data(), input.size());
  mbedtls_md_hmac_finish(&mdCtx, digest.data());
  mbedtls_md_free(&mdCtx);
  
  return digest;
}

bool X509_verif(const vector<unsigned char> & x509PeerCertificate, const vector<unsigned char> & x509CACertificate) {
  bool ret=0;
  mbedtls_x509_crt *chain=new mbedtls_x509_crt();
  mbedtls_x509_crt *root_ca=new mbedtls_x509_crt();
  mbedtls_x509_crt_profile profile;

  mbedtls_x509_crt_init(chain);
  mbedtls_x509_crt_init(root_ca);
		
  // Copy the default profile and set it to allow a 1024 RSA key
  // Otherwise will throw "The certificate is signed with an unacceptable key (eg bad curve, RSA too short)."
  memcpy(&profile, &mbedtls_x509_crt_profile_default, sizeof(mbedtls_x509_crt_profile_default) );
  // Allow 1024 RSA keys
  profile.rsa_min_bitlen = 1024;

  // Start to parse the CA and add it to chain
  // CA MUST BE THE FIRST IN THE CHAIN!!!
  // MUST be zero-init
  
  // Parse CA and add to chain
  if (mbedtls_x509_crt_parse(chain, x509CACertificate.data(), x509CACertificate.size()) != 0) {
    if(dbg_certs>1) printf("X509_verif: failed to parse CA certificate.\n");
    goto  x509_validate_end;
  }	

  // Parse CA again but add to ROOTCA chain to verify against
  mbedtls_x509_crt_parse(root_ca, x509CACertificate.data(), x509CACertificate.size());

  // Parse Peer and add to chain
  if ( mbedtls_x509_crt_parse(chain, x509PeerCertificate.data(), x509PeerCertificate.size()) != 0) {
    if(dbg_certs>1) printf("X509_verif: failed to parse peer certificate.\n");
    goto  x509_validate_end;
  }

  unsigned int verification_flags;
		
  if (mbedtls_x509_crt_verify_with_profile(chain, root_ca, NULL,  &profile, NULL, &verification_flags, NULL, NULL) != 0) {
    char *tmp=new char[257];
    mbedtls_x509_crt_verify_info(tmp, 256, "", verification_flags);
    if(dbg_certs>1) printf("X509_verif  failed because %s\n", tmp);
    delete [] tmp;
    goto  x509_validate_end;
  }

  //valid
  ret=1;
  
 x509_validate_end:
  mbedtls_x509_crt_free(chain);
  mbedtls_x509_crt_free(root_ca);
  delete chain;
  delete root_ca;

  return ret;
}

bool CheckSignature_RSASHA256(const vector<unsigned char> & message, const vector<unsigned char> & x509DerCertificate, const unsigned char *signature,int sig_size) {
  bool ok=0;
  int r=0;

  unsigned char hash[32];
  SHA256(hash,message.data(),message.size());

  mbedtls_x509_crt *rsaIde=new mbedtls_x509_crt();
  mbedtls_x509_crt_init(rsaIde);

  // Extract the PK from the certificate
  if ( mbedtls_x509_crt_parse(rsaIde, x509DerCertificate.data(), x509DerCertificate.size()) != 0) {
    if(dbg_certs>1) printf("CheckSignature RSA/SHA256: failed to parse certificate.\n");
    goto check_signature_end;
  }

  // Thanks a lot @gilles-peskine-arm for resolving the problem! ( https://github.com/ARMmbed/mbedtls/issues/4400 )
  // Using MBEDTLS_MD_NONE because this is raw data, and this function expects a signature with added information data
  // about the MD used.
  r=mbedtls_pk_verify(&(rsaIde->pk), MBEDTLS_MD_NONE, hash, 32, signature, sig_size);
  if(r) {
    if(dbg_certs>1) {
      char *tmp=new char[129];
      mbedtls_strerror(r,tmp, 128);
      printf("CheckSignature RSA/SHA256 signature INVALID: %s\n", tmp);
      delete [] tmp;
    }
    goto check_signature_end;
  } else ok=1;

 check_signature_end:
  mbedtls_x509_crt_free(rsaIde);
  delete rsaIde;
  return ok;
}	




struct cert_cross_rsa_ed_t {
  //ED25519_KEY                       [32 bytes]
  //EXPIRATION_DATE                   [4 bytes]
  //SIGLEN                            [1 byte]
  //SIGNATURE                         [SIGLEN bytes]
  unsigned char ed25519[32];
  unsigned int exp=0;

  bool init(const unsigned char *p,int l,const vector<unsigned char> &key) {
    bool ok=1;
    if(l<37) return false;

    vector<unsigned char> tmp;
    append(tmp,"Tor TLS RSA/Ed25519 cross-certificate");
    append(tmp, p,36);

    memcpy(ed25519,p,32);
    exp=htonl(*(unsigned int*)(p+32)); //expiration in hours since epoch 
    if(exp<get_unix_time()/3600) {
      printf("ed25519 certificate expired\n");
      return 0;
    }
    int siglen=p[36];
    l-=37;
    p+=37;
    if(l<siglen) {
      printf("size problem\n");
      return 0;
    }
    
    //print("cert_cross_rsa_ed_t certified key ",ed25519,32);
    //print("cert_cross_rsa_ed_t signature: ",p,l);

    if(CheckSignature_RSASHA256(tmp, key, p,l)) {
      //ok
    } else {
      printf("problem in cross certificate\n");
      ok=0;
    }

    return ok;
  }

  bool verif() {
    return 0;
  }
  
  void print_info() {
    ::print("ED25519 cross signed key ",ed25519,32);
  }

};

struct cert_ed25519_t {
  // see cert-cell.txt
  // see proposal 220

  bool ok=0;
  unsigned char cert_key[32]; // the certified key

  unsigned char key[32];
  unsigned char type=0;
  unsigned int exp=0;
  unsigned char key_type=0;
  
  
  cert_ed25519_t() {
    memset(key,0,32);
    memset(cert_key,0,32);
  }
  /*
    [01] ed25519 key
    [02] SHA256 hash of an RSA key. (Not currently used.)
    [03] SHA256 hash of an X.509 certificate. (Used with certificate type 5.)
  */
  
  /*
    VERSION         [1 Byte]
    CERT_TYPE       [1 Byte]
    EXPIRATION_DATE [4 Bytes]
    CERT_KEY_TYPE   [1 byte]
    CERTIFIED_KEY   [32 Bytes]
    N_EXTENSIONS    [1 byte]
    EXTENSIONS      [N_EXTENSIONS times]
    SIGNATURE       [64 Bytes]

   The EXTENSIONS field contains zero or more extensions, each of
   the format:

   ExtLength [2 bytes]
   ExtType   [1 byte]
   ExtFlags  [1 byte]
   ExtData   [Length bytes]

   The meaning of the ExtData field in an extension is type-dependent.

   The ExtFlags field holds flags; this flag is currently defined:

   1 -- AFFECTS_VALIDATION. If this flag is present, then the
   extension affects whether the certificate is valid; clients
   must not accept the certificate as valid unless they
   understand the extension.

2.2.1. Signed-with-ed25519-key extension [type 04]

ExtLength = 32
ExtData =
An ed25519 key    [32 bytes]

  */

  bool init(const unsigned char *bf,int l,const unsigned char *idkey=NULL) {
    memset(cert_key,0,sizeof(cert_key));
    ok=0;
    int p=0;
    if(l<40) {
      return false;
    }
    if(bf[p++]!=1) {
      printf("cert bad version\n");
      return 0; //version
    }
    type=bf[p++]; //cert_type
    exp=htonl(*(unsigned int*)(bf+p)); //expiration in hours since epoch 
    if(exp<get_unix_time()/3600) {
      printf("ed25519 certificate expired\n");
      return 0;
    }
    p+=4;
    key_type=bf[p++]; //key_type
    memcpy(cert_key,bf+p,32); //key
    p+=32;
    int ne=bf[p++]; //nb ext
    for(int u=0;u<ne;u++) {
      if(p+2>l) {
	return false;
      }
      int s=htons(*(unsigned short*)(bf+p)); //size
      p+=2;
      if(p+2+s>l) {
	return false;
      }
      if(bf[p]==4) { //ext type
	memcpy(key,bf+p+2,32); //signing public key
	//print("pub ",key,32);
      } else {
	if(bf[p+1]&1) return false; //flags
      }
      p+=2+s;
    }
    
    if(p+64>l) {
      return false;
    }
    
    if(idkey==NULL) {
      if(isnull(key,32)) {
	printf("ed25519 check sig fail: key is not known\n");
	return false;
      }
      idkey=key;
    } else {
      if(!isnull(key,32) && !match(key,idkey,32))
	printf("ed25519 check sig fail: idkey != key in cert\n");
    }

    if (!edsign_verify(bf+p, idkey,bf, p)) {
      printf("ed25519 signature is not valid.\n");
      return false;
    }
    
    ok=1;
    return 1;
  }

  void print_info() {
    printf("cert ed25519 key ok=%d type=%x key_type=%x\n",ok,type,key_type);
    print("cert key ",cert_key,32);
    print("sig key  ",key,32);
  }
};

struct sign_cert_ed25519_t :public cert_ed25519_t {
  unsigned char secret[64];

  sign_cert_ed25519_t() {
    memset(secret,0,64);
  }

  void print_info() {
    printf("cert ed25519 key ok=%d type=%x key_type=%x\n",ok,type,key_type);
    print("cert key ",cert_key,32);
    print("sig key  ",key,32);
    print("sec key  ",secret,64);
  }

  void check() {
    //print("sig_ed25519 check sec ",secret,64);
    //print("sig_ed25519 check pub ",key,32);
    unsigned char pub[32];
    sm_pack(pub, secret);
    assert(match(key,pub,32));
  }

  int writebin(unsigned char *bf,int l) {
    int p=0;
    if(l<128+12) return -1;
    bf[p++]=1; //version
    bf[p++]=type;
    auto e2=htonl(exp); //expiration in hours since epoch 
    memcpy(bf+p,&e2,4);
    p+=4;
    bf[p++]=key_type;
    memcpy(bf+p,cert_key,32); //key
    p+=32;

    bf[p++]=1; //nb ext
    bf[p++]=0;
    bf[p++]=32;//size
    bf[p++]=4;// ext type
    bf[p++]=0;
    memcpy(bf+p,key,32); //signing public key
    p+=32;

    unsigned char signature[64];
    //check();
    

    edsign_sign_expanded(signature, key, secret, bf,p);
    memcpy(bf+p,signature,64);

    assert(p<=l);


    return p+64;
  }
};
  

struct digest_t {
  bool sha3=0;
  mbedtls_md_context_t *sha1ctx=NULL;
  sha3_ctx_t *sha3ctx=NULL;
  digest_t(bool s) {
    create(s);
  }

  digest_t() {
  }

  ~digest_t() {
    if(sha1ctx) {
      mbedtls_md_free(sha1ctx);
      delete sha1ctx;
    }
    if(sha3ctx) delete sha3ctx;
  }

  void create(bool s) {
    sha3=s;
    if(sha3) {
      sha3ctx=new sha3_ctx_t();
      sha3_init(sha3ctx,32);
    } else {
      sha1ctx=new mbedtls_md_context_t;
      mbedtls_md_init(sha1ctx);
      mbedtls_md_setup(sha1ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), 0);
      mbedtls_md_starts(sha1ctx);
    }
  }

  void update(const unsigned char *data,int len) {
    if(sha3ctx)
      sha3_update(sha3ctx,data,len);
    if(sha1ctx)
      mbedtls_md_update(sha1ctx,data,len);
  }

  digest_t* copy() const {
    auto r=new digest_t(sha3);
    if(sha1ctx) {
      mbedtls_md_clone(r->sha1ctx, sha1ctx);
    } else {
      memcpy(r->sha3ctx,sha3ctx,sizeof(sha3_ctx_t));
    }
    return r;
  }

  int digest_size() const {
    if(sha3) return 32;
    return 20;
  }
  
  void get_digest(unsigned char *digest) {
    if(sha1ctx) {
      mbedtls_md_context_t tmp;
      mbedtls_md_init(&tmp);
      mbedtls_md_setup(&tmp,mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), 0);
      mbedtls_md_clone(&tmp, sha1ctx);
      mbedtls_md_finish(&tmp, digest);
      mbedtls_md_free(&tmp);
    } else {
      sha3_ctx_t tmp;
      memcpy(&tmp,sha3ctx,sizeof(tmp));
      sha3_final(digest,&tmp);
    }
  }
  
};

struct skin_ctx_t {
  int ok=0;
  
  digest_t *digest_forward=NULL;
  digest_t *digest_backward=NULL;

  mbedtls_cipher_context_t forward_cipher_ctx;
  mbedtls_cipher_context_t backward_cipher_ctx;

  unsigned char KH[32];
  
  void init_v3(unsigned char Df[32],unsigned char Db[32],unsigned char Kf[32],unsigned char Kb[32]) {
    ok=3;
    digest_forward=new digest_t(1);
    digest_backward=new digest_t(1);
    digest_forward->update(Df,32);
    digest_backward->update(Db,32);
 
    int r=0;
    unsigned char zeroiv[16];
    memset(zeroiv,0,16);
    mbedtls_cipher_init( &forward_cipher_ctx );
    mbedtls_cipher_init( &backward_cipher_ctx );
    r=r || mbedtls_cipher_setup( &forward_cipher_ctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CTR));
    r=r || mbedtls_cipher_setup( &backward_cipher_ctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CTR));
    r=r || mbedtls_cipher_setkey( &forward_cipher_ctx,Kf,256,MBEDTLS_ENCRYPT);
    r=r || mbedtls_cipher_setkey( &backward_cipher_ctx,Kb,256,MBEDTLS_ENCRYPT);
    r=r || mbedtls_cipher_set_iv( &forward_cipher_ctx, zeroiv, 16 );
    r=r || mbedtls_cipher_set_iv( &backward_cipher_ctx, zeroiv, 16 );
    r=r || mbedtls_cipher_reset (&forward_cipher_ctx);
    r=r || mbedtls_cipher_reset (&backward_cipher_ctx);

    assert(r==0);
    
  }

  void init_v2(unsigned char *keys) { //unsigned char Df[20],unsigned char Db[20],unsigned char Kf[16],unsigned char Kb[16]) {
    ok=2;
    digest_forward=new digest_t(0);
    digest_backward=new digest_t(0);
    digest_forward->update(keys,20);
    digest_backward->update(keys+20,20);
 
    int r=0;
    unsigned char zeroiv[16];
    memset(zeroiv,0,16);

    mbedtls_cipher_init( &forward_cipher_ctx );
    mbedtls_cipher_init( &backward_cipher_ctx );

    r=r || mbedtls_cipher_setup( &forward_cipher_ctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CTR));
    r=r || mbedtls_cipher_setkey( &forward_cipher_ctx,keys+40,128,MBEDTLS_ENCRYPT);
    r=r || mbedtls_cipher_set_iv( &forward_cipher_ctx, zeroiv, 16 );
    r=r || mbedtls_cipher_reset (&forward_cipher_ctx);

    r=r || mbedtls_cipher_setup( &backward_cipher_ctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CTR));
    r=r || mbedtls_cipher_setkey( &backward_cipher_ctx,keys+56,128,MBEDTLS_ENCRYPT);
    r=r || mbedtls_cipher_set_iv( &backward_cipher_ctx, zeroiv, 16 );
    r=r || mbedtls_cipher_reset (&backward_cipher_ctx);

    assert(r==0);
  }

  void encrypt(unsigned char *data,int len) {
    size_t ol=0;
    unsigned char tmp[len];
    int r=mbedtls_cipher_update( &forward_cipher_ctx, data,len,tmp,&ol ); 
    assert(r==0);
    assert(ol==len);
    memcpy(data,tmp,len);
  }

  void decrypt(unsigned char *data,int len) {
    size_t ol=0;
    unsigned char tmp[len];
    int r=mbedtls_cipher_update( &backward_cipher_ctx, data,len,tmp,&ol );
    assert(r==0);
    assert(ol==len);
    memcpy(data,tmp,len);
  }

  ~skin_ctx_t() {
    if(digest_forward) delete digest_forward;
    if(digest_backward) delete digest_backward;

    if(ok) {
      mbedtls_cipher_free( &forward_cipher_ctx );
      mbedtls_cipher_free( &backward_cipher_ctx );
    }
  }
};


int b32_dec(char c)
{
  if(c>='a' && c<='z') return c-'a';
  if(c>='A' && c<='Z') return c-'A';
  if(c>='2' && c<='7') return 26+c-'2';
  return -1;
}

char b32_enc(unsigned char c)
{
  if(c<26) return 'a'+c;
  if(c<32) return c-26+'2';
  assert(0);
}

bool b32_dec(const char *a,unsigned char *b)
{
  unsigned int r=0;
  int l=0;
  int k=0;
  for(int i=0;i<56;i++) {
    int u=b32_dec(a[i]);
    if(u<0) return false;
    r|=(u<<(11-l));
    l+=5;
    if(l>=8) {
      b[k++]=(r>>8);
      r=(r<<8);
      l-=8;
    }
  }
  assert(k==35);
  return true;
}

bool b32_enc(const unsigned char *b,char *a)
{
  unsigned int r=0;
  int l=0;
  int k=0;
  for(int i=0;i<35;i++) {
    unsigned int u=b[i];
    r|=(u<<(8-l));
    l+=8;
    while(l>=5) {
      a[k++]=b32_enc(r>>11);
      r&=((1<<11)-1);
      r=(r<<5);
      l-=5;
    }
  }
  assert(k==56);
  return true;
}

bool parse_onionv3(const char *a,unsigned char *b)
{
  unsigned char h[32];
  unsigned char bb[35];
  if(!b32_dec(a,bb)) return false;

  memcpy(b,bb,32);
  //print("bb",bb,35);
  
  sha3_ctx_t c;
  sha3_init(&c,32);//SHA3_256);
  sha3_update(&c,".onion checksum",15);
  sha3_update(&c,bb,32);
  sha3_update(&c,bb+34,1);
  
  sha3_final(h,&c);

  if(h[0]!=bb[32]) return false;
  if(h[1]!=bb[33]) return false;
  return true;
}

bool encode_onionv3(const unsigned char *b,char *a)
{
  unsigned char bb[35];
  unsigned char h[32];
  memcpy(bb,b,32);
  bb[34]=3;
  
  sha3_ctx_t c;
  sha3_init(&c,32);//SHA3_256);
  sha3_update(&c,".onion checksum",15);
  sha3_update(&c,bb,32);
  sha3_update(&c,bb+34,1);
  
  sha3_final(h,&c);

  bb[32]=h[0];
  bb[33]=h[1];

  if(!b32_enc(bb,a)) return false;

  return true;
}


void fwrite_secure(const void *ptr, size_t size, size_t nmemb,FILE *stream) {
  int n=fwrite(ptr,size,nmemb,stream);
  if(n!=nmemb) {
    printf("FATAL fwrite error\n");
    LOG_FATAL("fwrite: %s\n", errno_str(errno).c_str());
    assert(0);
  }
}

struct onion_key_t {
  unsigned char secret_key[64];
  unsigned char public_key[32];
  unsigned char public_key_c[32];

  onion_key_t() {
    memset(public_key,0,32);
    memset(secret_key,0,64);
  }
  
  string get_ad() const {
    char address[57];
    encode_onionv3(public_key,address);
    address[56]=0;
    return address;
  }
  
  void fill(sign_cert_ed25519_t &c) {
    memcpy(c.secret,secret_key,64);
    memcpy(c.key,public_key,32);
  }
  
  void print_info() const {
    ::print("sec  ",secret_key,64);
    ::print("pub  ",public_key,32);
    printf("%s\n",get_ad().c_str());
  }
  
  void generate(bool positive=1) // if positive, generate a key with a positive x public key
  {
    unsigned char tmp[32];

    while(1) {
      random_tab(tmp,32);
      expand_key(secret_key,tmp);
      sm_pack(public_key, secret_key);

      if(!positive) break;
      
      ed25519_pt p;
      
      ed25519_smult(&p, &ed25519_base, secret_key);
      uint8_t x[F25519_SIZE];
      uint8_t y[F25519_SIZE];
      ed25519_unproject(x, y, &p);
      f25519_normalize(x);
      uint8_t parity = (x[0] & 1) << 7;
      if(parity) {
	//try again
      } else {
	break;
      }
    }
    c25519_smult(public_key_c, c25519_base_x, secret_key);
      
  }
  
  void check()
  {
    unsigned char pub[32];
    //::print("onion check sec ",secret_key,64);
    //::print("onion check pub ",public_key,32);
    sm_pack(pub, secret_key);
    assert(match(public_key,pub,32));
  }

  
  bool read(const char *path="") {
    char fn[256];
    snprintf(fn,256,"%shs_ed25519_secret_key",path);
    FILE *in=fopen(fn,"r");
    if(!in) return false;
    fread(secret_key,1,32,in);
    fread(secret_key,1,64,in);

    fclose(in);

    snprintf(fn,256,"%shs_ed25519_public_key",path);
    in=fopen(fn,"r");
    if(!in) return false;
    fread(public_key,1,32,in);
    fread(public_key,1,32,in);
    fclose(in);

    return true;
  }

  bool read_spiffs() {
    char fn[256];
    snprintf(fn,256,"/spiffs/hs_secret");
    FILE *in=fopen(fn,"r");
    if(!in) return false;
    fread(secret_key,1,32,in);
    fread(secret_key,1,64,in);

    fclose(in);

    snprintf(fn,256,"/spiffs/hs_public");
    in=fopen(fn,"r");
    if(!in) return false;
    fread(public_key,1,32,in);
    fread(public_key,1,32,in);
    fclose(in);

    return true;
  }

  void write(const char *path="hspath/") {
    char fn[256];
    snprintf(fn,256,"%shs_ed25519_secret_key",path);
    FILE *out=fopen(fn,"w");
    if(out==NULL) {
      LOG_WARN("fopen: %s\n", errno_str(errno).c_str());
      return;
    }
    fwrite_secure("== ed25519v1-secret: type0 ==",1,32,out);
    fwrite_secure(secret_key,1,64,out);
    fclose(out);

    snprintf(fn,256,"%shs_ed25519_public_key",path);
    out=fopen(fn,"w");
    if(out==NULL) {
      LOG_WARN("fopen: %s\n", errno_str(errno).c_str());
      return;
    }
    fwrite_secure("== ed25519v1-public: type0 ==",1,32,out);
    fwrite_secure(public_key,1,32,out);
    fclose(out);

    snprintf(fn,256,"%shostname",path);
    out=fopen(fn,"w");
    if(out==NULL) {
      LOG_WARN("fopen: %s\n", errno_str(errno).c_str());
      return;
    }
    fwrite_secure(get_ad().c_str(),1,56,out);
    fprintf(out,".onion\n");
    fclose(out);
  }

  void write_spiffs() {
    char fn[256];
    snprintf(fn,256,"/spiffs/hs_secret");
    FILE *out=fopen(fn,"w");
    if(out==NULL) {
      LOG_WARN("fopen: %s\n", errno_str(errno).c_str());
      return;
    }
    fwrite_secure("== ed25519v1-secret: type0 ==",1,32,out);
    fwrite_secure(secret_key,1,64,out);
    fclose(out);

    snprintf(fn,256,"/spiffs/hs_public");
    out=fopen(fn,"w");
    if(out==NULL) {
      LOG_WARN("fopen: %s\n", errno_str(errno).c_str());
      return;
    }
    fwrite_secure("== ed25519v1-public: type0 ==",1,32,out);
    fwrite_secure(public_key,1,32,out);
    fclose(out);
  }

};


void MAC_SHA3(unsigned char *MAC,const unsigned char *MAC_KEY,int keylen,const unsigned char *m,int l)
{
  //print("compute mac with payload : ",m,l);
  //print("compute mac with key : ",MAC_KEY,keylen);
  unsigned long long len=htonll(keylen);
  sha3_ctx_t c;
  sha3_init(&c,32);//SHA3_256);
  sha3_update(&c,&len,8);
  //print("len part  : ",&len,8);
  sha3_update(&c,MAC_KEY,keylen);
  sha3_update(&c,m,l);
  sha3_final(MAC,&c);
	
}


struct small_random_set_t {
  unsigned char *t=0;
  int m;
  int l;
  ~small_random_set_t() {
    delete t;
  }
  small_random_set_t(int z) {
    m=l=z;
    assert(m<=256);
    t=new unsigned char[m];
    for(int u=0;u<m;u++)
      t[u]=u;
    for(int i=m-1;i>0;i--) {
      std::swap(t[i], t[random_byte() % (i+1)]);
    }

    random_shuffle(t,t+m);
  }
  bool empty() const {return l==0;}
  int  pick() {
    return t[l--];
  }
};

struct random_set_t {
  int a,m,l,b;
  int next;

  random_set_t(int z) {
    m=z;
    l=16383;
    a=1+random_short()%16383;
    b=random_short()%16384;
    n();
  }

  int aa() {
    if(l<0) {
      if(l==-1) {
	l--;
	return (b+16383)%16384;
      }
      return -1;
    }
    a=a<<1;
    if(a>>14) {
      a=a&((1<<14)-1);
      a=a^0x140f;
    }
    l--;
    return ((a-1)+b)%16384;
  }
  void n() {
    next=aa();
    while(next>=m)
      next=aa();
  }
  
  bool empty() const {return next<0;}
  int  pick() {
    auto r=next;
    n();
    return r;
  }
  
  
};

//alloc for miniz : use psram if any

void *my_miniz_def_alloc_func(void *opaque, size_t items, size_t size)
{
    (void)opaque, (void)items, (void)size;
    void *p=big_malloc(items * size);
    //printf("(my_miniz_def_alloc_func %d %d -> %p)\n",(int)(items),(int)(size),p);
    return p;
}

void my_miniz_def_free_func(void *opaque, void *address)
{
    (void)opaque, (void)address;
    //printf("(my_miniz_def_free_func %p)\n",address);
    big_free(address);
}
