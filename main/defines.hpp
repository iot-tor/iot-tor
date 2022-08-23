#pragma once

#define TOR_REFRESH_TIME 3600*2 //2h
#define TOR_SAVE_TIME 3600*12 //12h 

#define TOR_REFRESH_LOOP_TIME 3600 //1h

#define TOR_HSDIR_REPUBLISH_TIME (120*60) //2h

/*
  some other #defines :
  
  USEFS : #define USEFS to store cacheed descriptors on the filesystem (spiffs on ESP32) 
  USENTP : use NTP or ot on ESP32 : you can #define USENTP to use NTP time instead of time got when downloading the consensus

  ADDCHECK : additionnal checks
  NOTORCHECKS : remove some checks 

  DIR_LOWMEM : set to save only some random relays in memory/fs. not compatible with hidden services
  DISABLE_CACHE : set to save only some random relays in memory/fs. not compatible with hidden services
  ESP : set if you compile for ESP32
  LINUX : set if you compile for linux
  EXIT_PORT : default exit port. used with 'lowmem' mode to keep only exit nodes which accept this exit port
  
  DBGBASE : default log level

*/

#ifdef LINUX

#define USEFS

#else //ESP

#define USEFS

#endif

#ifndef LINUX
#ifndef LINUXLOW
#ifndef FAKEESP
#ifndef FAKEESPPSRAM


#define ESPPSRAM

#endif
#endif
#endif
#endif

#ifdef ESP
#ifndef ESPLOWMEM
#ifndef ESPPSRAM
#define ESPLOWMEM
#endif
#endif
#endif

#ifdef ESPPSRAM
#define ESP
#endif


#include "miniz-esp32/src/miniz.h"


#ifdef ESPLOWMEM
#warning "compile for esp lowmem"
#define ESP_TO_FACT 6
#define BASEPATH "/spiffs/"
#define CONSFILE "lowcons.bin"
#define DISABLE_CACHE
#define DIR_LOWMEM
#endif

#ifdef ESPPSRAM
#warning "compile for esp psram"
#define ESP_TO_FACT 6
#define BASEPATH "/spiffs/"
#define CONSFILE "cons.bin"
#endif

#ifdef LINUX
#warning "compile for linux"
#define ESP_TO_FACT 1
#define BASEPATH ""
#define CONSFILE "cons.bin"
#endif

#ifdef LINUXLOW
#warning "compile for linux"
#define ESP_TO_FACT 1
#define BASEPATH ""
#define CONSFILE "lowcons.bin"
#define DISABLE_CACHE
#define DIR_LOWMEM

#define LINUX
#endif

#ifdef FAKEESP
#warning "compile for fake esp lowmem"
#define ESP_TO_FACT 1
#define BASEPATH ""
#define CONSFILE "lowcons.bin"
#define DISABLE_CACHE
#define DIR_LOWMEM
#endif

#ifdef FAKEESPPSRAM
#warning "compile for fake esp psram"
#define ESP_TO_FACT 1
#define BASEPATH ""
#define CONSFILE "cons.bin"
#endif


#ifdef ESPPSRAM
#include "esp_heap_caps.h"
void *big_malloc(const size_t &a)
{
  return  heap_caps_malloc(a, MALLOC_CAP_SPIRAM);
}

void *big_realloc(void *b,const size_t &a)
{
  return  heap_caps_realloc(b,a, MALLOC_CAP_SPIRAM);
}

void big_free(void *b)
{
  heap_caps_free(b);
}

template<typename a_t>
a_t* PSRAM_NEW(int b) {
  a_t *r=(a_t*)heap_caps_malloc(sizeof(a_t)*b, MALLOC_CAP_SPIRAM);
  for(int i=0;i<b;i++)
    new(r+i) a_t;
  return r;
}

#else
#define big_malloc malloc
#define big_free free
#define big_realloc realloc
template<typename a_t>
a_t* PSRAM_NEW(int b) {
  return new a_t[b];
}

#endif

template<typename C_t>
struct ps_vector {
  unsigned int size_=0;
  unsigned int maxsize_=0;
  C_t *tab;

private:
  ps_vector &operator=(const ps_vector &c) const {  }
  ps_vector(const ps_vector &c) {}

public:  
  void clear() {size_=0;}
  const C_t & operator[](unsigned int u) const { return tab[u];}
  C_t *data() {
    return tab;
  }
  const C_t *data() const {
    return tab;
  }
  unsigned int size() const {return size_;}
  unsigned int maxsize() const {return maxsize_;}
  ps_vector(unsigned int ms=16384) {
    maxsize_=ms;
#ifdef ESP
    tab=(C_t*)heap_caps_malloc(maxsize_*sizeof(C_t), MALLOC_CAP_SPIRAM);
#else
    tab=new C_t[maxsize_];
#endif
  }
  ~ps_vector() {
#ifdef ESP
    heap_caps_free(tab);
#else
    delete[] tab;
#endif
  }
  void resize(unsigned int n) {
    size_=n;
  }
  void push_back(const C_t &c) {
    tab[size_++]=c;
  }
  
};


#ifdef ESP
#include "esp_system.h"
void reset() {
  esp_restart();
}
#else
void reset() {
}
#endif
