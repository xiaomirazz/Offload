#include<linux/kernel.h>
#include<linux/module.h>   
#include<linux/netfilter.h>
#include<linux/netfilter_ipv4.h>
#include<net/netlink.h>
#include<net/sock.h>
#include<linux/ip.h>
#include<linux/tcp.h>
#include<linux/udp.h>
#include<linux/string.h>
#include<linux/netdevice.h>
//#include <linux/timer.h>
//#include <linux/timex.h>
//#include <linux/rtc.h>

#define    SIP     "172.22.2.43" //接口的IP地址

#define    DIP     "180.149.131.210" //要发送UDP报文的目的IP地址

#define    SPORT   39804   //源端口

#define    DPORT   6980    //目的端口

unsigned char DMAC_wlan0[ETH_ALEN]={0x84,0xc9,0xb2,0x74,0x1b,0x2c};     //server_eth3
unsigned char DMAC_eth0[ETH_ALEN]={0x84,0xc9,0xb2,0x74,0x00,0xc4};     	//server_eth4
unsigned char SMAC_wlan0[ETH_ALEN]={0x80,0x56,0xf2,0x5a,0x25,0x11};     //client_wlan0
unsigned char SMAC_eth0[ETH_ALEN]={0x28,0xd2,0x44,0x3c,0x08,0xa3};     	//client_eth0
//unsigned char DMAC[ETH_ALEN]={0x0c,0x82,0x68,0x66,0x30,0x24};         //172.22.0.240

unsigned int hook_func(unsigned int hooknum, struct sk_buff * skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *) );

struct net_device *eth0 = NULL;
struct net_device *wlan0 = NULL;

int	state_old=3;	
int	state_new=3; 					

//NF_INET_POST_ROUTING
static struct nf_hook_ops myops = { { NULL, NULL }, hook_func, THIS_MODULE, PF_INET, NF_INET_POST_ROUTING , NF_IP_PRI_MANGLE};

MODULE_LICENSE("Dual BSD/GPL");

static int build_and_xmit_udp(struct net_device * Net_Device, u_char * smac, u_char * dmac,

             u_char * pkt, int pkt_len,u_long sip, u_long dip,

             u_short sport, u_short dport)

{

  struct sk_buff * skb = NULL;

  struct net_device * dev = NULL;

  struct ethhdr * ethdr = NULL;

  struct iphdr * iph = NULL;

  struct udphdr * udph = NULL;

  u_char * pdata = NULL;

 

  if(NULL == smac || NULL == dmac)

      goto out;

  dev=Net_Device;


  //通过alloc_skb()来为一个新的skb申请内存结构

  skb = alloc_skb(pkt_len + sizeof(struct iphdr) + sizeof(struct udphdr) + LL_RESERVED_SPACE(dev), GFP_ATOMIC);

 

  if(NULL == skb)

      goto out;

  skb_reserve(skb, LL_RESERVED_SPACE(dev));

 

  skb->dev = dev;

  skb->pkt_type = PACKET_OTHERHOST;

  skb->protocol = __constant_htons(ETH_P_IP);

  skb->ip_summed = CHECKSUM_NONE;

  skb->priority = 0;

 

  //skb->network_header = (struct iphdr*)skb_put(skb, sizeof(struct iphdr));

  //skb->transport_header = (struct udphdr*)skb_put(skb, sizeof(struct udphdr));

  skb->network_header = skb_put(skb, sizeof(struct iphdr));

  skb->transport_header = skb_put(skb, sizeof(struct udphdr));

 

  pdata = skb_put(skb, pkt_len); //预留给上层用于数据填充的接口

  {

     if(NULL != pkt)

        memcpy(pdata, pkt, pkt_len);

  }

 

  //“从上往下”填充skb结构，依次是UDP层--IP层--MAC层

  udph = (struct udphdr *)skb->transport_header;

  //udph = (struct udphdr*)skb_put(skb, sizeof(struct udphdr));

  memset(udph, 0, sizeof(struct udphdr));

  udph->source = sport;

  udph->dest = dport;

  skb->csum = 0;

  udph->len = htons(sizeof(struct udphdr)+pkt_len);

  udph->check = 0;

  //填充IP层

  iph = (struct iphdr*)skb->network_header;

  //iph = (struct iphdr*)skb_put(skb, sizeof(struct iphdr));

  iph->version = 4;

  iph->ihl = sizeof(struct iphdr)>>2;

  iph->frag_off = 0;

  iph->protocol = IPPROTO_UDP;

  iph->tos = 0;

  iph->daddr = dip;

  iph->saddr = sip;

  iph->ttl = 0x40;

  iph->tot_len = __constant_htons(skb->len);

  iph->check = 0;

  iph->check = ip_fast_csum((unsigned char *)iph,iph->ihl);

 

  skb->csum = skb_checksum(skb, iph->ihl*4, skb->len - iph->ihl * 4, 0);

  udph->check = csum_tcpudp_magic(sip, dip, skb->len - iph->ihl * 4, IPPROTO_UDP, skb->csum);

  //填充MAC层

  skb->mac_header = skb_push(skb, 14);

  ethdr = (struct ethhdr *)skb->mac_header; 

  //ethdr = (struct ethhdr*)skb_push(skb,14);

  memcpy(ethdr->h_dest, dmac, ETH_ALEN);

  memcpy(ethdr->h_source, smac, ETH_ALEN);

  ethdr->h_proto = __constant_htons(ETH_P_IP);

  //调用dev_queue_xmit()发送报文

  if(0 > dev_queue_xmit(skb))

      goto out;

 

out:

   if(NULL != skb)

   {

        dev_put (dev);

        kfree_skb (skb);

   }

   return(NF_ACCEPT);

}

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
//printk(KERN_INFO "eth0 name: %s\n", eth0->name);
//printk(KERN_INFO "wlan0 name: %s\n", wlan0->name);
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
	

/*
	struct timex  txc;
	struct rtc_time tm;
	do_gettimeofday(&(txc.time));
	rtc_time_to_tm(txc.time.tv_sec,&tm);
	printk(KERN_INFO"UTC time :%d-%d-%d %d:%d:%d\n",tm.tm_year+1900,tm.tm_mon, tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec);
*/
	state_new=wlan0->state;

	printk(KERN_INFO "net_dev state: %d\n", state_new);

	if(state_new==7&&state_old==3)
	{
		build_and_xmit_udp(eth0,SMAC_eth0,DMAC_eth0,"lte",3,ctou(SIP),ctou(DIP),htons(SPORT),htons(DPORT));
	}
	else if(state_new==3&&state_old==7)
	{
		build_and_xmit_udp(eth0,SMAC_eth0,DMAC_eth0,"wifi",4,ctou(SIP),ctou(DIP),htons(SPORT),htons(DPORT));
	}


	skb_recv = skb_get(skb);
	ipheader = ip_hdr(skb_recv);
        if(ipheader->protocol==IPPROTO_TCP)
	{
		tcpheader = (struct tcphdr *)(skb_transport_header(skb_recv));
		//printk(KERN_INFO "tcpheader->seq: %u\n", tcpheader->seq);
	
		//if(tcpheader->psh==1)
		if(state_new==7)
		{
			ipheader->tos=ipheader->tos|0x01;
			ipheader->check=0;
			ipheader->check=ip_fast_csum((unsigned char*)ipheader,ipheader->ihl);
			
			skb_recv->dev=eth0;
			ethdr=(struct ethhdr*)skb_push(skb,14);
			memcpy(ethdr->h_dest,DMAC_eth0,ETH_ALEN);
			memcpy(ethdr->h_source,SMAC_eth0,ETH_ALEN);
			ethdr->h_proto=htons(ETH_P_IP);
			result=dev_queue_xmit(skb_recv);
			return NF_STOLEN;
		}
		else
		{
			
			ipheader->tos=ipheader->tos|0x00;
			ipheader->check=0;
			ipheader->check=ip_fast_csum((unsigned char*)ipheader,ipheader->ihl);
			
			skb_recv->dev=wlan0;
			ethdr=(struct ethhdr*)skb_push(skb,14);
			memcpy(ethdr->h_dest,DMAC_wlan0,ETH_ALEN);
			memcpy(ethdr->h_source,SMAC_wlan0,ETH_ALEN);
			ethdr->h_proto=htons(ETH_P_IP);
			result=dev_queue_xmit(skb_recv);
			return NF_STOLEN;
		}
	}
	state_old=state_new;
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
