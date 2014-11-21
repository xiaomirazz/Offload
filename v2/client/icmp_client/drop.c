#include<linux/kernel.h>
#include<linux/module.h>   
#include<linux/netfilter.h>
#include<linux/netfilter_ipv4.h>
#include<net/netlink.h>
#include<net/sock.h>
#include<linux/ip.h>
#include<linux/tcp.h>
#include<linux/string.h>
#include<linux/netdevice.h>

unsigned int hook_func(unsigned int hooknum, struct sk_buff * skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *) );

struct net_device *eth0 = NULL;
struct net_device *wlan0 = NULL;

int       state;					

//NF_INET_POST_ROUTING
static struct nf_hook_ops myops = { { NULL, NULL }, hook_func, THIS_MODULE, PF_INET, NF_INET_POST_ROUTING , NF_IP_PRI_MANGLE};

MODULE_LICENSE("Dual BSD/GPL");

//char_ip to long_ip
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
	if(strcmp(dev->name,"eth0")==0)
	{
		eth0=dev;
	}
	if(strcmp(dev->name,"wlan0")==0)
	{
		wlan0=dev;
	}
}
printk(KERN_INFO "eth0 name: %s\n", eth0->name);
printk(KERN_INFO "wlan0 name: %s\n", wlan0->name);
    return 0;
}


/* our own hook function */
unsigned int hook_func(unsigned int hooknum, struct sk_buff * skb, 
		       const struct net_device *in,
	               const struct net_device *out,
	               int (*okfn)(struct sk_buff *) )
{
	struct sk_buff *skb_recv = NULL;
	struct tcphdr *tcpheader = NULL;
	struct iphdr *ipheader = NULL;
	struct ethhdr *ethdr = NULL;
	int result;
	
	unsigned char DMAC_wlan0[ETH_ALEN]={0x84,0xc9,0xb2,0x74,0x1b,0x2c};     //server_eth3
	unsigned char DMAC_eth0[ETH_ALEN]={0x84,0xc9,0xb2,0x74,0x00,0xc4};     	//server_eth4
	unsigned char SMAC_wlan0[ETH_ALEN]={0x80,0x56,0xf2,0x5a,0x25,0x11};     //client_wlan0
	unsigned char SMAC_eth0[ETH_ALEN]={0x28,0xd2,0x44,0x3c,0x08,0xa3};     	//client_eth0
	//unsigned char DMAC[ETH_ALEN]={0x0c,0x82,0x68,0x66,0x30,0x24};         //172.22.0.240

	skb_recv = skb_get(skb);
	ipheader = ip_hdr(skb_recv);
        if(ipheader->protocol==IPPROTO_ICMP){
		//tcpheader = (struct tcphdr *)(skb_transport_header(skb_recv));
		state=eth0->state;
		if(state==3){
			skb_recv->dev=eth0;
			
			printk(KERN_INFO "net_dev state: %d\n", state);
			//result=dev_get_by_name(skb_recv->dev,"eth0");
			ethdr=(struct ethhdr*)skb_push(skb,14);
			memcpy(ethdr->h_dest,DMAC_eth0,ETH_ALEN);
			memcpy(ethdr->h_source,SMAC_eth0,ETH_ALEN);
			ethdr->h_proto=htons(ETH_P_IP);
			result=dev_queue_xmit(skb_recv);
			return NF_STOLEN;
		}
		else
		{
			skb_recv->dev=wlan0;
			//result=dev_get_by_name(skb_recv->dev,"wlan0");
			ethdr=(struct ethhdr*)skb_push(skb,14);
			memcpy(ethdr->h_dest,DMAC_wlan0,ETH_ALEN);
			memcpy(ethdr->h_source,SMAC_wlan0,ETH_ALEN);
			ethdr->h_proto=htons(ETH_P_IP);
			result=dev_queue_xmit(skb_recv);
			return NF_STOLEN;
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
