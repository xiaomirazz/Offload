#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <net/sock.h>
#include <linux/netlink.h>

#define NETLINK_TEST 17
struct sock *nl_sk = NULL;

/*
void nl_data_ready (struct sock *sk, int len)
{
          wake_up_interruptible(sk->sk_sleep);
}
*/

void test_netlink(struct sk_buff * _skb)
{
        struct sk_buff * skb = NULL;
        struct nlmsghdr * nlh = NULL;
        //int err;
        u32 pid;

        //nl_sk = netlink_kernel_create(NETLINK_TEST, nl_data_ready);
        /* wait for message coming down from user-space */
        //skb = skb_recv_datagram(nl_sk, 0, 0, &err);

	if( (skb = skb_get(_skb)) == NULL )
		return;
        nlh = (struct nlmsghdr *)skb->data;
        printk("%s: received netlink message payload:%s\n", __FUNCTION__, (char*)NLMSG_DATA(nlh));

        pid = nlh->nlmsg_pid; /*pid of sending process */
        //NETLINK_CB(skb).group = 0; /* not in mcast group */
        NETLINK_CB(skb).pid = 0;      /* from kernel */
        //NETLINK_CB(skb).dst_pid = pid;
        NETLINK_CB(skb).dst_group = 0;  /* unicast */
        netlink_unicast(nl_sk, skb, pid, MSG_DONTWAIT);
}

int init_module()
{
        nl_sk = netlink_kernel_create(&init_net, NETLINK_TEST, 0, test_netlink, NULL, THIS_MODULE);
        return 0;
}
void cleanup_module( )
{
	sock_release(nl_sk->sk_socket);
}
MODULE_LICENSE("GPL");
MODULE_AUTHOR("duanjigang");
