#include <stdio.h>    
#include <stdlib.h>    
#include <string.h>    
#include <fcntl.h>    
#include <errno.h>    
#include <sys/ioctl.h>    
#include <sys/types.h>    
#include <sys/socket.h>    
#include <linux/if.h>    
#include <linux/sockios.h>    
#include <linux/ethtool.h>    

#include <netinet/in.h>
#include <unistd.h>

int get_netlink_status(const char *if_name); 
int state_old=1;
int state_new=1;   
int n;

int main()    
{    
/*
	if(getuid() != 0)    
	{    
		fprintf(stderr, "Netlink Status Check Need Root Power.\n");    
		return 1;    
	}    
	printf("Net link status: %d\n", get_netlink_status("wlan0"));    
	return 0; 
*/

	printf("program start\n");

	struct sockaddr_in addr;
    	int sock;
	int i;

    	if ( (sock=socket(AF_INET, SOCK_DGRAM, 0)) <0)
    	{
        	perror("socket");
        	exit(1);
    	}
    	addr.sin_family = AF_INET;
    	addr.sin_port = htons(9999);
   	addr.sin_addr.s_addr = inet_addr("220.181.111.100");
    	if (addr.sin_addr.s_addr == INADDR_NONE)
    	{
       		printf("Incorrect ip address!");
        	close(sock);
        	exit(1);
    	}
	//n = sendto(sock, "l", 1, 0, (struct sockaddr *)&addr, sizeof(addr));

	while(1)
	{
		state_new=get_netlink_status("wlan0");
		//state_new=get_netlink_status("eth0");
		//printf("state_new: %d\n", state_new);
		if(state_new!=state_old)
		{
			
			if(state_new==0)
			{
				//usleep(50);
				if ( (sock=socket(AF_INET, SOCK_DGRAM, 0)) <0)
    				{
        				perror("socket");
        				exit(1);
    				}
    				addr.sin_family = AF_INET;
    				addr.sin_port = htons(9999);
   				addr.sin_addr.s_addr = inet_addr("220.181.111.100");
				usleep(5);
				n = sendto(sock, "l", 1, 0, (struct sockaddr *)&addr, sizeof(addr));
				close(sock);
			}
			else if(state_new==1)
			{
				if ( (sock=socket(AF_INET, SOCK_DGRAM, 0)) <0)
    				{
        				perror("socket");
        				exit(1);
    				}
				//usleep(5);
    				addr.sin_family = AF_INET;
    				addr.sin_port = htons(9999);
   				addr.sin_addr.s_addr = inet_addr("220.181.111.100");
				n = sendto(sock, "w", 1, 0, (struct sockaddr *)&addr, sizeof(addr));
				close(sock);
			}
			state_old=state_new;
			printf("udp sent:\n");
			if (n < 0)
        		{
           	 		perror("sendto");
            			close(sock);
            			break;
        		}
		}
	}

}  

int get_netlink_status(const char *if_name)     
{    
	int skfd;    
	struct ifreq ifr;    
	struct ethtool_value edata;    
	edata.cmd = ETHTOOL_GLINK;    
	edata.data = 0;    
	memset(&ifr, 0, sizeof(ifr));    
	strncpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name) - 1);    
	ifr.ifr_data = (char *) &edata;    
	if (( skfd = socket( AF_INET, SOCK_DGRAM, 0 )) < 0)    
	return -1;    
	if(ioctl( skfd, SIOCETHTOOL, &ifr ) == -1)    
	{    
		close(skfd);    
		return -1;    
	}    
	close(skfd);    
	return edata.data;    
}
