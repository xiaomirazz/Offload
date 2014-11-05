#include<linux/kernel.h>
#include<linux/module.h>   
#include<linux/netfilter.h>
#include<linux/netfilter_ipv4.h>
#include<net/netlink.h>
#include<net/sock.h>
#include<linux/ip.h>
#include<linux/tcp.h>
#include<linux/string.h>
#include <linux/netdevice.h>
#include <linux/timer.h>
#include <linux/timex.h>
#include <linux/rtc.h>

unsigned int hook_func(unsigned int hooknum, struct sk_buff * skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *) );

struct net_device *eth3 = NULL;
struct net_device *eth4 = NULL;	
int state_wlan=0;
int state_eth=0;							

//NF_INET_POST_ROUTING
static struct nf_hook_ops myops = { { NULL, NULL }, hook_func, THIS_MODULE, PF_INET, NF_INET_POST_ROUTING , NF_IP_PRI_MANGLE};

MODULE_LICENSE("Dual BSD/GPL");

uint32_t ctou(char * cip){
	char * c;
	uint32_t n=0, t=0;
	c = cip;
	if(c == NULL){
		printk(KERN_ALERT"dest ip didn't be seted!!");
		return 0;
	}

	while(*c != '\0'){
		if((*c >= '0')&&(*c <= '9')){
			t = t*10 + (*c)-'0';
		}
		else if(*c == '.'){
			n += t;
			t=0;
			n = n*256;
		}
		else
			printk(KERN_ALERT"the ip format is wrong!!");
		c++;
	}
	n += t;
	return n;
}
 
int netbase_init_module(void)
{
    struct net_device *dev = NULL;
    for_each_netdev(&init_net,dev){
	printk(KERN_INFO "dev name: %s\n", dev->name);
	if(strcmp(dev->name,"eth3")==0)
	{
		eth3=dev;
	}
	if(strcmp(dev->name,"eth4")==0)
	{
		eth4=dev;
	}
}
printk(KERN_INFO "eth3 name: %s\n", eth3->name);
printk(KERN_INFO "eth4 name: %s\n", eth4->name);
    return 0;
}


/* our own hook function */
unsigned int hook_func(unsigned int hooknum, struct sk_buff * skb, 
		       const struct net_device *in,
	               const struct net_device *out,
	               int (*okfn)(struct sk_buff *) )
{
	struct sk_buff *skb_recv = NULL;
	struct tcphdr *tcpheader= NULL;
	struct iphdr *ipheader= NULL;
	struct ethhdr *ethdr = NULL;
	
	unsigned char SMAC_wlan0[ETH_ALEN]={0x84,0xc9,0xb2,0x74,0x1b,0x2c};         	//eth3
	unsigned char SMAC_eth0[ETH_ALEN]={0x84,0xc9,0xb2,0x74,0x00,0xc4};     		//eth4
	unsigned char DMAC_wlan0[ETH_ALEN]={0x80,0x56,0xf2,0x5a,0x25,0x11};        	//wlan0
	unsigned char DMAC_eth0[ETH_ALEN]={0x28,0xd2,0x44,0x3c,0x08,0xa3};           	//eth0
	//unsigned char DMAC[ETH_ALEN]={0x0c,0x82,0x68,0x66,0x30,0x25};         	//wlan0
	
	uint32_t destination_ip;
	uint32_t source_ip;
	uint32_t test_ip;

	skb_recv = skb_get(skb);
	ipheader = ip_hdr(skb_recv);
	
	struct timex  txc;
	struct rtc_time tm;
	do_gettimeofday(&(txc.time));
	rtc_time_to_tm(txc.time.tv_sec,&tm);
	//printk("UTC time :%d-%d-%d %d:%d:%d\n",tm.tm_year+1900,tm.tm_mon, tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec);


	if(ipheader->protocol==IPPROTO_TCP)
	{
		destination_ip = ntohl(ipheader->daddr);
		source_ip = ntohl(ipheader->saddr);
		test_ip=ctou("172.22.2.43");
		if(destination_ip==test_ip)
		{
			tcpheader=(struct tcphdr *)(skb_transport_header(skb_recv)+20);
			if(tcpheader->syn==1&&tcpheader->ack==1)
			{
				skb_recv->dev=eth3;
				skb_recv->mac_header=skb_push(skb,14);
				ethdr=(struct ethhdr*)skb_recv->mac_header;
				memcpy(ethdr->h_dest,DMAC_wlan0,ETH_ALEN);
				memcpy(ethdr->h_source,SMAC_wlan0,ETH_ALEN);
				ethdr->h_proto=htons(ETH_P_IP);
				dev_queue_xmit(skb_recv);
				return NF_STOLEN;
			}
			else if(state_wlan==1)
			{
				skb_recv->dev=eth4;
				skb_recv->mac_header=skb_push(skb,14);
				ethdr=(struct ethhdr*)skb_recv->mac_header;
				memcpy(ethdr->h_dest,DMAC_eth0,ETH_ALEN);
				memcpy(ethdr->h_source,SMAC_eth0,ETH_ALEN);
				ethdr->h_proto=htons(ETH_P_IP);
				dev_queue_xmit(skb_recv);
				return NF_STOLEN;
			}
			else if(state_wlan==0)
			{
				
				skb_recv->dev=eth3;
				skb_recv->mac_header=skb_push(skb,14);
				ethdr=(struct ethhdr*)skb_recv->mac_header;
				memcpy(ethdr->h_dest,DMAC_wlan0,ETH_ALEN);
				memcpy(ethdr->h_source,SMAC_wlan0,ETH_ALEN);
				ethdr->h_proto=htons(ETH_P_IP);
				dev_queue_xmit(skb_recv);
				return NF_STOLEN;
			}
			/*else if(tcpheader->syn==0&&state_eth==2)
			{
				skb_recv->dev=eth3;
				skb_recv->mac_header=skb_push(skb,14);
				ethdr=(struct ethhdr*)skb_recv->mac_header;
				memcpy(ethdr->h_dest,DMAC_wlan0,ETH_ALEN);
				memcpy(ethdr->h_source,SMAC_wlan0,ETH_ALEN);
				ethdr->h_proto=htons(ETH_P_IP);
				dev_queue_xmit(skb_recv);
				return NF_STOLEN;
			}*/
		}
		else if(source_ip==test_ip)
		{
			//if(strcmp(in->name,"eth4")==0)
			if((ipheader->tos&0x01)==0x01)
			{
				state_wlan=1;
				printk(KERN_INFO "state_wlan: %d\n", state_wlan);
			}
			else if((ipheader->tos&0x00)==0x00)
				state_wlan=0;
				printk(KERN_INFO "state_wlan: %d\n", state_wlan);
			//printk(KERN_INFO "in->name: %s\n", in->name);
			
		}
	}
	return NF_ACCEPT;
}

int init_module(void)
{
	/* register out own hook */
	printk( KERN_ALERT "start hook\n");
	netbase_init_module();
	return nf_register_hook(&myops);
}

void cleanup_module(void)
{
	nf_unregister_hook(&myops);
	printk( KERN_ALERT "stop hook\n");
}
