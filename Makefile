default:
	gcc -pthread -I ../lwip/src/include -I ../lwip/contrib/ports/unix/port/include -I . ../lwip/src/core/*.c ../lwip/src/core/ipv4/*.c ../lwip/contrib/ports/unix/port/sys_arch.c ../lwip/src/netif/ethernet.c ../lwip/src/api/tcpip.c main.c -o app

