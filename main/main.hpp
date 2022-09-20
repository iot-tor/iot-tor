#ifndef DBGBASE

int dbgbase=6;
#define VERBOSE

#define DBGBASE dbgbase
#endif

#include <stdio.h>
#include <stdlib.h>

#include "private.hpp"

#include "tor.hpp"

#include "circuit.hpp"


void test(circuit_t *tc,string host,int port,int a);

#ifndef NOHS
#include "hs.hpp"
#endif

#include "test.hpp"

#ifdef ESP
#include "esp_wifi.hpp"
#endif

#ifdef SRDV
#include "simplerdv.hpp"
#endif

void main_test(string type,string arg="")
{
  //bool download_descriptor(info_node_t &dir,info_relay_t &r,int timelimit=1000*10)
  // info_node_t dir;
  // info_relay_t r;
  // download_descriptor(dir,r);
  // printf("end\n");
  // return 0;

#ifdef ESP
  esp_init(); //init wifi, ntp spiffs
#endif

#ifdef SRDV
  if(type=="srdv_s" || type=="srdv_c" ) {
    simple_rdv_init();
  }
#endif

  tor_init();

#ifdef LINUX
  for(int p=0;p<3;p++)
#else
    while(1)
#endif
      {
#ifndef NOHS
	if(type=="hs_s") {
	  printf("==test HS_SERVER==\n");
	  test_hs_server(arg);
	  
	  break;
	}

	if(type=="hs_c") {
	  printf("==test HS_CLIENT==\n");
	  test_hs_client(arg);
	  exit(0);
	}
#endif
#ifdef SRDV
	if(type=="srdv_s") {
	  printf("==test simple rdv server==\n");
	  simple_rdv_server();
	  exit(0);
	}
#endif

	if(type=="tor") {
	  printf("==test TOR==\n");
	  pthread_t id[2];
	  for(int i=0;i<1;i++) {
	    pthread_create(id+i,NULL,test,NULL);
	  }
    
	  for(int i=0;i<1;i++) {
	    pthread_join(id[i],NULL);
	  }
	}

	if(type=="niet") {
	}

	printf("END main\n");
	sleep(5);
      }

  reset();

  printf("END main\n");

  delete tor;

  sleep(1);
  
  aff_mn();
  
  
  return ;

  //print_cached();

  //test_hdir();
  
  return;
  // testrdv();

#if 0 
  printf("public ip:%s\n", get_public_ip_tls("ifconfig.me",443).c_str());
  printf("Tor ip:%s\n", get_tor_ip("ifconfig.me").c_str());
  printf("Tor ip by tls:%s\n", get_tor_ip_tls("ifconfig.me").c_str());
#endif
  
  
  return;
  
  

  
}

