#include "defines.hpp"

#include "main.hpp"


//cell.hpp:int dbg_cell=DBGBASE;
//hs.hpp:int hsdir_dbg=DBGBASE;


#ifndef ESP

#include "poll.hpp"

int main(int ac, char **av) {
  tor_first_refresh=10;

  while(ac>1 && av[1][0]=='-') {

    if(strcmp(av[1],"-rsk")==0) { 
      FILE *in=fopen(av[2],"r");
      assert(in);
      unsigned char k[64];
      int n=fread(k,1,32,in);
      n=fread(k,1,64,in);
      assert(n==64);
      print("sec ",k,64);
      unsigned char pub[32];
      sm_pack(pub, k);
      print("pub ",pub,32);
      printf("%s\n",base64(pub,32).c_str());
      
      exit(0);
    }

    if(strcmp(av[1],"-cache")==0) { 
      cache_descs=PSRAM_NEW<info_node_t>(CACHE_SIZE);
      read_cache();
      for(int i=0;i<CACHE_SIZE;i++) {
	printf("=== %d ===\n",i);
	cache_descs[i].print_info();
      }
      exit(0);
    }

    if(strcmp(av[1],"-tp")==0) {
      float u;
      auto r=l_get_time_period(&u);
      printf("%d = 0x%x %f (+%f h)\n",r,r,u,u*24);
      exit(0);
    }

    if(strcmp(av[1],"-ri")==0) { 
      tor_refresh_interval=atoi(av[1]);
      ac--;av++;
      ac--;av++;
      continue;
    }

    if(strcmp(av[1],"-r")==0) {
      tor_first_refresh=atoi(av[2]);
      ac-=2;av+=2;
      continue;
    }

    if(strcmp(av[1],"-v")==0) {
      dbgbase=atoi(av[2]);
      dbg_cell=DBGBASE;
      main_dbg=DBGBASE;
      ac-=2;av+=2;
      continue;
    }

    printf("arguments problem\n");
    assert(0);
  }
  
  //test_get_public_ip();

  string arg="";
  if(ac>2) arg=(av[2]);
  main_test(av[1],arg);
  
  return 0;
}

#else

extern "C" void app_main()
{
  tor_first_refresh=10;

  main_test("hs_s");
}

#endif
