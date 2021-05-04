#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <linux/if_packet.h>
#include <poll.h>
#include <net/ethernet.h> /* the L2 protocols */

#include "packet_handle.h"

int main(int argc, char *argv[])
{
    if (2 != argc)
    {
        printf("Usage: %s InterfaceName \n", argv[0]);
        printf("Example: %s eth0 \n", argv[0]);
        return -1;
    }

    char *intfName = argv[1];
    printf("InterfaceName: %s \n", intfName);

    int fd = 0, ret = 0;
    char *buff = NULL;

    fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(fd<0)
    {
        printf("socket create err %d. \n", fd);
        goto failed_2;
    }

//PACKET_VERSION和 SO_BINDTODEVICE可以省略
#if 1
    const int tpacket_version = TPACKET_V1;
    /* set tpacket hdr version. */
    ret = setsockopt(fd, SOL_PACKET, PACKET_VERSION, &tpacket_version, sizeof (int));
    if(ret<0)
    {
        printf("setsockopt packet version err %d. \n", ret);
        goto failed_2;
    }

    /* bind to device. */
    ret = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, intfName, strlen(intfName));
    if(ret<0)
    {
        printf("setsockopt bind device error %d . \n", ret);
        goto failed_2;
    }
#endif

    struct tpacket_req req;
#define PER_PACKET_SIZE 2048
    const int BUFFER_SIZE = 1024*1024*16; //16MB的缓冲区
    req.tp_block_size = 4096;
    req.tp_block_nr = BUFFER_SIZE/req.tp_block_size;
    req.tp_frame_size = PER_PACKET_SIZE;
    req.tp_frame_nr = BUFFER_SIZE/req.tp_frame_size;

    ret = setsockopt(fd, SOL_PACKET, PACKET_RX_RING, (void *)&req, sizeof(req));
    if(ret<0)
    {
        printf("setsockopt rx ring error %d . \n", ret);
        goto failed_2;
    }

    buff = (char *)mmap(0, BUFFER_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if(buff == MAP_FAILED)
    {
        printf("mmap err. \n");
        goto failed_2;
    }

    int nIndex=0, i=0;
    while(1)
    {
        //这里在poll前先检查是否已经有报文被捕获了
        struct tpacket_hdr* pHead = (struct tpacket_hdr*)(buff+ nIndex*PER_PACKET_SIZE);
        //如果frame的状态已经为TP_STATUS_USER了，说明已经在poll前已经有一个数据包被捕获了，如果poll后不再有数据包被捕获，那么这个报文不会被处理，这就是所谓的竞争情况。
        if(pHead->tp_status == TP_STATUS_USER)
            goto process_packet;

        //poll检测报文捕获
        struct pollfd pfd;
        pfd.fd = fd;
        //pfd.events = POLLIN|POLLRDNORM|POLLERR;
        pfd.events = POLLIN;
        pfd.revents = 0;
        ret = poll(&pfd, 1, -1);
        if(ret<0)
        {
            perror("poll");
            goto failed_1;
        }

process_packet:
        //尽力的去处理环形缓冲区中的数据frame，直到没有数据frame了
        for(i=0; i<req.tp_frame_nr; i++)
        {
            struct tpacket_hdr* pHead = (struct tpacket_hdr*)(buff+ nIndex*PER_PACKET_SIZE);

            //XXX: 由于frame都在一个环形缓冲区中，因此如果下一个frame中没有数据了，后面的frame也就没有frame了
            if(pHead->tp_status == TP_STATUS_KERNEL)
                break;

            //处理数据frame
            CallBackPacket((char*)pHead+pHead->tp_mac, pHead->tp_len);
            //char* mac = (char*)pHead+pHead->tp_mac;
            //printf("GetPacket,Len:%d,Mac:%2x-%2x-%2x-%2x-%2x-%2x\n", pHead->tp_len,
            //    mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);

            //重新设置frame的状态为TP_STATUS_KERNEL
            pHead->tp_len = 0;
            pHead->tp_status = TP_STATUS_KERNEL;

            //更新环形缓冲区的索引，指向下一个frame
            nIndex++;
            nIndex%=req.tp_frame_nr;
        }

    }

success:
    close(fd);
    munmap(buff, BUFFER_SIZE);
    return 0;

failed_1:
    munmap(buff, BUFFER_SIZE);
    
failed_2:
    close(fd);
    return -1;
}

