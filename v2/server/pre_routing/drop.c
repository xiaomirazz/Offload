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


unsigned int hook_func(unsigned int hooknum, struct sk_buff * skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *) );	

//NF_INET_PRE_ROUTING
static struct nf_hook_ops myops = { { NULL, NULL }, hook_func, THIS_MODULE, PF_INET, NF_INET_FORWARD , NF_IP_PRI_FIRST};

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
 

/* our own hook function */
unsigned int hook_func(unsigned int hooknum, struct sk_buff * skb, 
		       const struct net_device *in,
	               const struct net_device *out,
	               int (*okfn)(struct sk_buff *) )
{
	struct sk_buff *skb_recv = NULL;
	struct tcphdr *tcpheader= NULL;
	struct iphdr *ipheader= NULL;
	uint32_t source_ip;

	skb_recv = skb_get(skb);
	ipheader = ip_hdr(skb_recv);
	if(ipheader->protocol==IPPROTO_TCP){
	tcpheader=(struct tcphdr *)(skb_transport_header(skb_recv)+20);
	source_ip = ntohl(ipheader->saddr);


	printk(KERN_INFO "ipheader->saddr:%u,     ",ntohl(ipheader->saddr));
	if (source_ip == ctou("172.22.2.43") || ntohl(ipheader->daddr) == ctou("218.240.144.219"))
	{
		printk(KERN_INFO "tcpheader->syn:%d  tcpheader->psh:%d  tcpheader->ack:%d  tcpheader->seq:%u\n",tcpheader->syn,tcpheader->psh,tcpheader->ack,ntohl(tcpheader->seq));
		if(tcpheader->psh==1)
		{
			printk(KERN_INFO "http request\n");
		}
	}
	else
	{
		printk(KERN_INFO "**** tcpheader->syn:%d  tcpheader->psh:%d  tcpheader->ack:%d  tcpheader->seq:%u\n",tcpheader->syn,tcpheader->psh,tcpheader->ack,ntohl(tcpheader->seq));
	}
}
	return NF_ACCEPT;
}

int init_module(void)
{
	/* register out own hook */
	printk( KERN_ALERT "******************************************************start hook*******************************************\n");
	printk(KERN_INFO "172.22.2.43:%u\n",ctou("172.22.2.43"));
	printk(KERN_INFO "61.135.169.105:%u\n",ctou("61.135.169.105"));
	printk(KERN_INFO "61.135.169.125:%u\n",ctou("61.135.169.125"));
	return nf_register_hook(&myops);
}

void cleanup_module(void)
{
	nf_unregister_hook(&myops);
	printk( KERN_ALERT "******************************************************stop hook********************************************\n");
}
