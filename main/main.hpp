#ifndef DBGBASE

int dbgbase=9;

#define DBGBASE dbgbase
#endif

#include <stdio.h>
#include <stdlib.h>
#include "tor.hpp"

#include "private.hpp"

void test(circuit_t *tc,string host,int port,int a);


#include "hs.hpp"

#include "test.hpp"

#ifdef ESP
#include "esp_wifi.hpp"
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

  tor_init();

#ifdef LINUX
  for(int p=0;p<3;p++)
#else
    while(1)
#endif
      {
	if(type=="hs_s") {
	  printf("==test HS_SERVER==\n");
	  test_hs_server();
	  exit(0);
	}

	if(type=="hs_c") {
	  printf("==test HS_CLIENT==\n");
	  test_hs_client(arg);
	  exit(0);
	}

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
  
  return ;

  //print_cached();

  //test_hdir();
  
  return;
  // testrdv();

  printf("public ip:%s\n", get_public_ip_tls("ifconfig.me",443).c_str());
  printf("Tor ip:%s\n", get_tor_ip("ifconfig.me").c_str());

  printf("Tor ip by tls:%s\n", get_tor_ip_tls("ifconfig.me").c_str());

  
  
  return;
  
  

  
}

