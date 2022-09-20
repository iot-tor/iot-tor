// in this file: very nasty things to debug things


#include <stdlib.h>
#include <stdio.h>
#include <new>
#include <map>
#include <limits>
using namespace std;

template <class T> 
struct mallocator {
    typedef size_t size_type;
    typedef ptrdiff_t difference_type;
    typedef T* pointer;
    typedef const T* const_pointer;
    typedef T& reference;
    typedef const T& const_reference;
    typedef T value_type;

    template <class U> struct rebind { typedef mallocator<U> other; };
    mallocator() throw() {}
    mallocator(const mallocator&) throw() {}

    template <class U> mallocator(const mallocator<U>&) throw(){}

    ~mallocator() throw() {}

    pointer address(reference x) const { return &x; }
    const_pointer address(const_reference x) const { return &x; }

    pointer allocate(size_type s, void const * = 0) {
      //printf("mallocate %d %d\n",int(s),int(sizeof(T)));
      if (0 == s) return NULL;
        pointer temp = (pointer)malloc(s * sizeof(T)); 
        if (temp == NULL)
            throw std::bad_alloc();
        return temp;
    }

    void deallocate(pointer p, size_type s) {
      //printf("demallocate %d\n",int(s));
      free(p);
    }

    size_type max_size() const throw() { 
        return std::numeric_limits<size_t>::max() / sizeof(T); 
    }

    void construct(pointer p, const T& val) {
        new((void *)p) T(val);
    }

    void destroy(pointer p) {
        p->~T();
    }
};


int main_dbg=DBGBASE;

map<void*,int,std::less<void*>, mallocator<std::pair<void*, int>>> _mn;
//map<void*,int> _mn; 

int _mn_n=0;
int _mn_d=0;
int _mn_df=0;

void aff_mn() {
  int tt=0;
  for(auto &it:_mn) {
    printf("%p %d\n",it.first,it.second);
    tt+=it.second;
  }
  printf(" total _mn %d\n",tt);
  printf("#n %d #d %d #d! %d\n",_mn_n,_mn_d,_mn_df);
}

//#define MEMDBG

#ifdef MEMDBG 

#if 0
int xx_mem[16384]={0};

void __attribute__((noinline)) mem_newnew(int s) {
  printf("newnew %d\n",s);
}

void mem_new(size_t size) {
  if(size>=16384) {
    mem_newnew(size);
  } else {
    if(xx_mem[size]==0)
      mem_newnew(size);
    xx_mem[size]++;
    if(xx_mem[size]==100) {
      printf("mmm 10 %d\n",int(size));
    }
  }
}

void * operator new(size_t size)
{
  void * p = malloc(size);//MEMDBG
  printf("*** new XXX %p size=%d\n",p,int(size));
  mem_new(size);
  return p;
}
    
void * operator new[](size_t size)
{
  void * p = malloc(size);//MEMDBG
  printf("*** new[] XXX %p size=%d\n",p,int(size));
  mem_new(size);
  return p;
}

void operator delete(void * p)
{
  printf("*** delete XXX %p \n",p);
  free(p);
}

    
void operator delete[](void * p)
{
  printf("*** delete[] XXX %p \n",p);
  free(p);
}
#else

#define DBGMEMAFF 0

void* mynew(size_t size)
{
  _mn_n++;
  void * p = malloc(size);//MEMDBG
  _mn[p]=size;
  if(DBGMEMAFF) printf("*** new XXX %p %d\n",p,int(size));
  return p;
}

void mydelete(void *p) {
  _mn_d++;
  if(_mn.find(p)!=_mn.end()) {
    int x=_mn.at(p);
    _mn.erase(p);
    if(DBGMEMAFF) printf("*** delete XXX %p %d\n",p,x);
  } else {
    _mn_df++;
    printf("*** WARN delete XXX %p not found\n",p);
  }
  
  free(p);
}

void * operator new(size_t size)
{
  return mynew(size);
}

void * operator new[](size_t size)
{
  return mynew(size);
}
    
void operator delete(void * p)
{
  mydelete(p);
}

void operator delete[](void * p)
{
  mydelete(p);
}

    


#endif

#endif

void print_mem_stat() {
}


#ifdef INSTR

#warning "compile with finstrument-functions, very slow..."

char * instr_tab[128];
int instr_pos=0;
//pthread_t instr_watch=0;
volatile char * instr_base=NULL;
extern "C"{
  void  __attribute__((noinline)) __cyg_profile_func_enter (void *, void *) __attribute__((no_instrument_function));
  void __attribute__((noinline)) __cyg_profile_func_exit (void *, void *) __attribute__((no_instrument_function));

  void  __attribute__((noinline)) __cyg_profile_func_enter (void *func,  void *caller)
  {
    //if(instr_watch!=pthread_self()) return;
    char bbb=0;
    char*p=(char*)&bbb;
    auto kk=instr_base-p;
    //if(instr_base)printf("%ld\n",kk);
    if(kk<0 || kk>=16000) return;
    instr_tab[instr_pos++]=p;
    static int mm=0;
    if(kk>mm) {
      mm=kk;
      printf("INSTR p:%d %d enter %p %p\n",instr_pos,int(kk),func,caller);
    }
  }

  void  __attribute__((noinline)) __cyg_profile_func_exit (void *func, void *caller)
  {
    char bbb=0;
    char*p=(char*)&bbb;
    auto kk=instr_base-p;
    if(kk<0 || kk>=32768) return;

    if(instr_pos>0) instr_pos--;
  }
}

#endif



