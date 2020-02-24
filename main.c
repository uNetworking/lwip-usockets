#include "lwip/tcp.h"
#include "lwip/init.h"
#include "lwip/timeouts.h"
#include "lwip/etharp.h"
#include "netif/ethernet.h"

#define ETHERNET_MTU 1500

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <linux/if_ether.h>

#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>

int fd;

struct all {
struct ethhdr eh;
struct iphdr ih;
struct tcphdr th;
};

static err_t my_netif_output(struct netif *netif, struct pbuf *p) {
  //printf("Outputting packet of length: %d, %d\n", p->len, p->tot_len);

//printf(p->payload);

	struct all *eh = p->payload;

/*if (eh->eh.h_proto == htons(ETH_P_IP)) {
	//printf("ETH_IP SENDING!\n");

	printf("protocol: %d, length: %d\n", eh->ih.protocol, p->len);

	//if (eh->ih.protocol = )

	if (eh->th.syn && eh->th.ack) {
		printf("We are now sending SYN ACK!\n");
	}

	if (eh->th.rst) {
		printf("We are now sending RST!\n");
	}

}*/

	/*printf("source: ");
	for (int i = 0; i < 6; i++) {
		printf("%x ", eh->eh.h_source[i]);
	}
	printf("\n");

	printf("dest: ");
	for (int i = 0; i < 6; i++) {
		printf("%x ", eh->eh.h_dest[i]);
	}
	printf("\n");

	printf("proto: %x\n", eh->eh.h_proto);

if (eh->eh.h_proto == ETH_P_ARP) {
printf("this packet is ARP!\n");
} else if (eh->eh.h_proto == ETH_P_IP) {
printf("this packet is IP!\n");
}

printf("version: %d\n", eh->ih.version);

printf("protocol: %d\n", eh->ih.protocol);

	printf("SYN: %d\n", eh->th.syn);
	printf("FIN: %d\n", eh->th.fin);*/


  struct msghdr msg = {};

struct sockaddr_ll sin = {};

  //ip_addr_t ip;
  //ipaddr_aton("192.168.168.30", &ip);
  
            sin.sll_family = AF_PACKET;
            sin.sll_protocol = eh->eh.h_proto;

		memcpy(sin.sll_addr, eh->eh.h_source, 6);

            //sin.sll_addr = eh->eh.h_source;
		sin.sll_halen = 6;
		sin.sll_ifindex = 3; // vilket index ska vi egentligen ha? 0?

// cat /sys/class/net/wlp3s0/ifindex

	    struct iovec message;
            message.iov_base = p->payload;
            message.iov_len = p->len;

            msg.msg_iov = &message;
            msg.msg_iovlen = 1;

            msg.msg_name = &sin;
            msg.msg_namelen = sizeof(struct sockaddr_ll);

  /*printf("sendmsg: %d\n", */sendmsg(fd, &msg, 0);//);

  return ERR_OK;
}

static err_t my_netif_init(struct netif *netif) {
  netif->linkoutput = my_netif_output;
  netif->output     = etharp_output;
  netif->mtu        = ETHERNET_MTU;
  netif->flags      = NETIF_FLAG_LINK_UP | NETIF_FLAG_ETHARP | NETIF_FLAG_ETHERNET;

  // mitt wifi
  unsigned char mac[6] = {0xDC, 0x85, 0xDE, 0x3B, 0x8C, 0x89};

  memcpy(netif->hwaddr, mac, ETH_HWADDR_LEN);
  netif->hwaddr_len = ETH_HWADDR_LEN;
  return ERR_OK;
}

err_t tcp_on_connected_fn(void *arg, struct tcp_pcb *tpcb, err_t err) {
	printf("We are connected!\n");
}

err_t tcp_recv_f(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {
	printf("Got tcp data: %s\n", p->payload);

	//printf("got tcp data\n");

	tcp_recved(tpcb, p->len);

	return ERR_OK;
}

// on_open here
err_t accept_fn(void *arg, struct tcp_pcb *newpcb, err_t err) {
	printf("ACCEPTED A CONNECTION!\n");
	//exit(0);

	tcp_recv(newpcb, tcp_recv_f);

	return ERR_OK;
}

void main(void) {

  fd = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(ETH_P_ALL));
  printf("fd: %d\n", fd);

  ip_addr_t ip;
  ipaddr_aton("192.168.10.203", &ip);

  ip_addr_t gw;
  ipaddr_aton("192.168.10.1", &gw);

  ip_addr_t nm;
  ipaddr_aton("255.255.255.0", &nm);

  struct netif netif;
  lwip_init();
  printf("add: %p\n", netif_add(&netif, &ip, &nm, &gw, NULL, my_netif_init, ethernet_input));
  netif.name[0] = 'e';
  netif.name[1] = '0';
  //netif_create_ip6_linklocal_address(&netif, 1);
  //netif.ip6_autoconfig_enabled = 1;
  //netif_set_status_callback(&netif, my_netif_status_callback);
  netif_set_default(&netif);
  netif_set_up(&netif);





// enklare att lyssna på en port och säga åt kernel att dra åt helvete med tcp på alla dest portar som är vår!

  ip_addr_t client_ip;
  ipaddr_aton("97.74.249.1", &client_ip);

  // make a connection - make it send a SYN!
  struct tcp_pcb *t = tcp_new();



// lyssna

if (ERR_OK == tcp_bind(t, IP4_ADDR_ANY, 4000)) {
printf("bound to port 4000\n");
}
t = tcp_listen(t);
tcp_accept(t, accept_fn);

/*
  err_t e;
  if (ERR_OK == (e = tcp_connect(t, &client_ip, 80, tcp_on_connected_fn))) {
		printf("connecting1\n");
	} else {
		printf("something: %d\n", ERR_RTE);
		printf("not connecting! err: %d\n", e);
	}

*/



  
  while(1) {


char buffer[65537];
/*if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) == -1) {
    perror("setsockopt");
    exit(1);
}*/
struct sockaddr_ll src_addr;
socklen_t src_addr_len = sizeof(src_addr);
ssize_t count = recvfrom(fd, buffer, sizeof(buffer), 0, (struct sockaddr*)&src_addr, &src_addr_len);

if (count != -1) {
//printf("Got packet of size: %d\n", count);


struct pbuf* p = pbuf_alloc(PBUF_RAW, count, PBUF_POOL);

pbuf_take(p, buffer, count);

      if(netif.input(p, &netif) != ERR_OK) {
printf("CANNOT INSERT PACKET!\n");
        pbuf_free(p);
      } else {
		//printf("PArsed packet!\n");
	}

}
     
    /* Cyclic lwIP timers check */
    sys_check_timeouts();
     
    /* your application goes here */
  }
}
