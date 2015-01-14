#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <string.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/socket.h>

#define NETLINK_TEST 17
#define MAX_PAYLOAD 1024  /* maximum payload size*/
#define SERV_PORT  9999
#define RCVBUF_LEN  64

struct sockaddr_nl src_addr, dest_addr;
struct nlmsghdr *nlh = NULL;
struct iovec iov;
int sock_fd;
struct msghdr msg;

int main(int argc, char* argv[])
{
	int retval;
	int rcvsock_fd;
	char rcv_buf[RCVBUF_LEN];
	int len;
	struct sockaddr_in remote_addr;
	struct sockaddr_in serv_addr;

	rcvsock_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(0 > rcvsock_fd)
	{
		printf("error getting udp socket!\n");
		return -1;
	}
	
	memset(&serv_addr,0,sizeof(struct sockaddr_in));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(SERV_PORT);
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	retval = bind(rcvsock_fd,(struct sockaddr*)&serv_addr,sizeof(struct sockaddr_in));
	if(0 > retval)
	{
		printf("udp binding failed!\n");
		close(rcvsock_fd);		
		return -1;
	}

	/*initialize parameters*/
        sock_fd = socket(AF_NETLINK, SOCK_RAW,NETLINK_TEST);
	if(0 > sock_fd)
	{
		printf("error getting nl socket!\n");
		close(rcvsock_fd);		
		return -1;
	}

        memset(&msg, 0, sizeof(msg));
        memset(&src_addr, 0, sizeof(src_addr));
        src_addr.nl_family = AF_NETLINK;
        src_addr.nl_pid = getpid();  /* self pid */
        src_addr.nl_groups = 0;  /* not in mcast groups */

        retval = bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));
	if(0 > retval)
	{
		printf("binding failed\n");
		close(sock_fd);
		close(rcvsock_fd);
		return -1;
	}

        memset(&dest_addr, 0, sizeof(dest_addr));
        dest_addr.nl_family = AF_NETLINK;
        dest_addr.nl_pid = 0;   /* For Linux Kernel */
        dest_addr.nl_groups = 0; /* unicast */

        nlh=(struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
	
	len = sizeof(struct sockaddr_in);

	while(1)
	{
		memset(rcv_buf,0,sizeof(rcv_buf));
		memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));

		printf("waiting recv!!!\n");
		retval = recvfrom(rcvsock_fd,rcv_buf,RCVBUF_LEN,0,(struct sockaddr*)&remote_addr,&len);
		if(retval == -1)
		{
			printf("recv error!!!\n");
			break;
		}
		
		printf("recved %s\n",rcv_buf);

		/* Fill the netlink message header */
        	nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
        	nlh->nlmsg_pid = getpid();  /* self pid */
        	nlh->nlmsg_flags = 0;
		
        	/* Fill in the netlink message payload */
		strcpy(NLMSG_DATA(nlh), rcv_buf);

		iov.iov_base = (void *)nlh;
        	iov.iov_len = nlh->nlmsg_len;
       		msg.msg_name = (void *)&dest_addr;
        	msg.msg_namelen = sizeof(dest_addr);
        	msg.msg_iov = &iov;
        	msg.msg_iovlen = 1;

        	retval = sendmsg(sock_fd, &msg, 0);
		if(-1 == retval)
		{
			printf("sending error!\n");
		}

        	/* Read message from kernel */
        	memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
        	recvmsg(sock_fd, &msg, 0);
        	printf("Received message payload: %s\n",NLMSG_DATA(nlh));
	}
         /* Close Netlink Socket */
	close(rcvsock_fd);
        close(sock_fd);
}
