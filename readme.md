# Liberty CTF writeup

Due to the nature of this challange, you can't solve it after competition is over. So
some messages or output strings, or even order could be slightly modified, as I'm
writing from what I remember, and not exact strings. Aslo note that flag can't be 
obtained if you didn't capture all data from same run. You will see also why at the
end.


Liberty was simple client which would allocate 0x2000 memory as RWX, and after that will
read data from socket to this memory and execute it:
```
.text:00000772 loc_772:                                ; CODE XREF: main+42j
.text:00000772                 push    eax
.text:00000773                 push    eax
.text:00000774                 push    0               ; offset
.text:00000776                 push    0FFFFFFFFh      ; fd
.text:00000778                 push    22h             ; flags
.text:0000077A                 push    7               ; prot
.text:0000077C                 push    2000h           ; len
.text:00000781                 push    0               ; addr
.text:00000783                 call    _mmap
.text:00000788                 add     esp, 20h
.text:0000078B                 mov     [ebp-1028h], eax
.text:00000791                 mov     [ebp-104Ch], eax
...
.text:0000086E                 push    0               ; flags
.text:00000870                 push    4               ; n
.text:00000872                 push    [ebp+buf]       ; buf
.text:00000878                 push    [ebp+fd]        ; fd
.text:0000087E                 call    _recv
...
.text:000008EB                 push    0               ; flags
.text:000008ED                 push    edx             ; n
.text:000008EE                 push    eax             ; buf
.text:000008EF                 push    [ebp+fd]        ; fd
.text:000008F5                 call    _recv
...
.text:0000091C                 push    edx
.text:0000091D                 push    edx
.text:0000091E                 push    0
.text:00000920                 lea     edx, [ebp+var_1020]
.text:00000926                 push    edx
.text:00000927                 mov     [ebp+var_1070], edx
.text:0000092D                 call    dword ptr [ebp-1028h]
```
result from executed code will be sent to remote server.

Liberty server also has timing, so if you are debugging, or request takes 
too much time to execute, it will always send back invalid data, and client
will exit, so debugging wasn't an option. 

1st check we encounter is if we are running in debugger, process will fork
and child will try to ptrace parent, on default Ubuntu this would fail, also
it would fail if process is already ptraced. On ubuntu problem comes from Yama
so we need to alter  `/proc/sys/kernel/yama/ptrace_scope` to allow ptrace.

I used **PIN Tool** to instrument binary, and dump chunks of data as those
were coming. 1st few chunks will check if you are running virtualization software,
and if so exit. Checks are done by tryign to parse:

`/proc/bus/pci/devices`, at this point I had to insturment program to read differnet
`/proc/bus/pci/devices`, this was done by checking if buffer has this string, and 
on the fly replace it with hardcoded path to `/home/user/device` which had faked 
version to hide virtualization.

Next comes CPUID check:
```
seg000:00000000                 push    ebp
seg000:00000001                 mov     ebp, esp
seg000:00000003                 push    esi
seg000:00000004                 mov     esi, [ebp+8]
seg000:00000007                 push    ebx
seg000:00000008                 mov     eax, 7
seg000:0000000D                 cpuid
seg000:0000000F                 mov     [esi], ebx
seg000:00000011                 mov     [esi+4], ecx
seg000:00000014                 mov     [esi+8], edx
seg000:00000017                 xor     eax, eax
seg000:00000019                 inc     eax
seg000:0000001A                 cpuid
seg000:0000001C                 mov     [esi+0Ch], ecx
seg000:0000001F                 mov     [esi+10h], edx
seg000:00000022                 pop     ebx
seg000:00000023                 mov     eax, 18h
seg000:00000028                 pop     esi
seg000:00000029                 pop     ebp
seg000:0000002A                 retn
```
Apparently code wanted that VMX instructions are present, and that AES instructions
are present too. From where does this conclusion come? Well if vmx is not present
you will be greated with "Still found your virtualization" or similar message. My trick
in PIN was to instrument code and make CPUID work like on real CPU. Oki, problem
solved, and we continue, and soon, very soon you are greated with PINs message that
it can't handle far ret when code segments are different. You guessed it right, code
was switching to x64 mode:
```
seg000:00000000                 nop
seg000:00000001                 nop
seg000:00000002                 nop
seg000:00000003                 call    $+5
seg000:00000008                 pusha
seg000:00000009                 mov     eax, 0C0h ; '�'
seg000:0000000E                 xor     ebx, ebx
seg000:00000010                 mov     ecx, 1000h
seg000:00000015                 mov     edx, 7
seg000:0000001A                 mov     esi, 22h ; '"'
seg000:0000001F                 xor     edi, edi
seg000:00000021                 dec     edi
seg000:00000022                 xor     ebp, ebp
seg000:00000024                 int     80h             ; LINUX - sys_mmap2
seg000:00000026                 mov     [esp+1Ch], eax
seg000:0000002A                 mov     edi, eax
seg000:0000002C                 mov     esi, [esp+20h]
seg000:00000030                 mov     ecx, 181h
seg000:00000035                 rep movsb
seg000:00000037                 popa
seg000:00000038                 add     esp, 4
seg000:0000003B                 push    eax
seg000:0000003C                 add     eax, 40h ; '@'
seg000:0000003F                 push    33h ; '3'
seg000:00000041                 push    eax
seg000:00000042                 retf
```
From now on, code goes as **x64 only**, and PIN was useless for me. Time to switch to different
method, obviously I needed PIN to instrument CPUID and reading of pci/devices, so next step
came to rescue. 

What I did now was to write `LD_PRELOAD` library which would hook call to exec buffer, dump
chunks, patch device/pci and cpuid check. Obviously for cpuid check I had to write different
code:
```
seg000:0000002B                 mov     dword ptr [esi+0Ch], 7FBAE3BFh
seg000:00000032                 mov     dword ptr [esi+10h], 0BFEBFBFFh
seg000:00000039                 mov     dword ptr [esi], 0
seg000:0000003F                 mov     dword ptr [esi+4], 0
seg000:00000046                 mov     dword ptr [esi+8], 0
```
When cpuid check would come, I would replace it with this code.

Oki, now we are good to go, from messages which follow you could notice what code is doing:
```
Encryption enabled
Root obtained           <--- apprently when this happened code would connect to IRC. I dind't
                             verify this but from dumped chunk we could see it's connecting
                             to IRC and sending private message saying "I trust legbs with my
                             root access" or similar message. I can look for chunk in dumps
                             but no need.
```
And then we get `No ssh access`. At this point I thought that they want to connect to my machine,
so I had to dump these chunks too. Note that these chunks are AES encrypted so you can't see
them in wireshark. Dumped chunk reveled that code was checking if there are `/root/.ssh` and
`/root/.ssh/authorized_keys`. Added 2 files and there we go for next check which tells me that
I'm not hacker as I'm missing debugger, looking at the chunk reveals that code is performing:
 `ls /home/*/ida*/ida.key /opt/ida*/ida.key 2>/dev/null`

Then comes check for kernel version (or it was before IDA), which runs:
```
uname -r 
```
After a bit of expermineting with patched uname it runed out that they wanted latest kernel,
so I patched uname to spit out `4.11.0-rc8` and they were happy. If I used `4.11.0-041100rc8-generic`
they would say `Not close enough` or similar message. 

After they were checking for python version. I'm not sure what they expected but this was
python script they were running:
```
import string
try:
        print(int(string.Formatter().format(format_string='{a}',a=0)))
except:
        print(1)
```
If 0 was returned it would say old python, so I patched `string.py/class Formatter format()` to
`return "1" if format_string='{a}'`

After this they would go and check if certain files are present in `~/legitbs_ctf2017_withlovefromlightning`
using this command:
`ls ~/legitbs_ctf2017_withlovefromlightning -A1F | grep /`

And output of this command will yield what files we need, after a few runs, I got all needed
files in `/root/legitbs_ctf2017_withlovefromlightning`:
```
cgc-docs       finals-2013  LegitBS     public      quals-2015  scorebot
choripan       finals-2014  liberty     quals-2013  quals-2016  website
ctf-registrar  fritas       medianoche  quals-2014  repo        webste
```
LegitBS and liberty I've added on my own, they didn't ask for them. After that code tries to
locate many packages using dpkg -s <packagename>. All these chunks are same but some strings
I remember are `dpkg -s nasm`, `dpkg -s yasm`, `dpkg -s arj`, `dpkg -s git`, `dpkg -s build-essentials`
and many more libraries like libncurses, libdwarf etc... List was huge so instead of installing
all packages I've pached dpkg with my own code:
```
#include        <stdio.h>

int main(){
        printf("Status: install ok installed\n");
}
```
And they were happy, after this they would check for `/sys/devices/system/cpu/cpu0/cache/index0` and
if somethign is missing they would say `Doesn't look like 4.11 kernel` so at this point I looked
over docs to see what can be done to match 4.11.0 kernel, and I gave up. I took kernel images from
kernel.org and installed them on Ubuntu. Now I had 4.11.0-rc5 (at 1st I used rc8) kernel and was ready
for this game. Of course due to the uname -r printing `4.11.0-041100rc5-generic` they would say
`Not close enough` as apprently they expected 4.11.0-rc5 or 8. They also checked 2 more paths for
kernel 4.11 but as now I had 4.11 I didn't care of them, nor I dumped these 2 chunks. Only thing which
I had to properly alter was uname and it's source code is available in git.

After this what happens is upload of LKM source (well not really source) but 4 .o files and Makefile
in `/tmp/lightning_defcon_2017`

If device is properly compiled it will be loaded into kernel and will expose `/dev/decfon_2017` device.

3 more chunks are coming:
1. delete lkm source
2. read from lkm to check if device is registerd
3. write 2 chunks of data to device

And you would be greated with final message (similar to this):

```Thank you for trusting us, now read from /dev/defcon_2017 to get flag!!!```

Oki, you read from there and woops "Invalid argument" error. I dumped driver earlier by killing
chunk which deletes it so all data was there.

Content is : 
`a.o_shipped b.o_shipped c.o_shipped d.o_shipped Makefile`

Looking quickly at the driver we can see that it exports FlagData, and has read/write/ioctl 
handlers.

write handler is called 2 times exactly, 1st time to write `IV` and 2nd time to write `AES256
key` which will be used to decrypt `FlagData` of size 0x80 stored in .ko .

At this point it gets a bit trickier, if you write extra data to driver FlagData will be zeroed,
if you read at this point FlagData it will be zeroed. 
```
.text:00000000000001BD                 mov     r9d, cs:InitialRead
.text:00000000000001C4                 mov     rax, gs:28h
.text:00000000000001CD                 mov     [rbp-28h], rax
.text:00000000000001D1                 xor     eax, eax
.text:00000000000001D3                 test    r9d, r9d
.text:00000000000001D6                 jz      loc_380
.text:00000000000001DC                 cmp     cs:KnockCount, 20h ; ' '
.text:00000000000001E3                 jnz     loc_410
.text:00000000000001E9                 cmp     cs:InitialWrite, 2
.text:00000000000001F0                 jnz     loc_410
.text:00000000000001F6                 add     rdx, 0FFFFFFFFFFFFFF80h
.text:00000000000001FA                 jnz     loc_410
.text:0000000000000200                 lea     rsi, [rbp-128h]
.text:0000000000000207                 lea     rbx, [rbp-1F0h]
.text:000000000000020E                 mov     r14, offset FlagData
.text:0000000000000215                 mov     rdi, offset DecKey
.text:000000000000021C                 mov     [rbp-218h], r14
.text:0000000000000223                 mov     qword ptr [rbp-1F8h], 8
.text:000000000000022E                 mov     [rbp-208h], rsi
.text:0000000000000235                 mov     [rbp-210h], rbx
.text:000000000000023C                 mov     qword ptr [rbp-200h], offset DecIV
.text:0000000000000247                 call    iDecExpandKey256
.text:000000000000024C                 lea     rdi, [rbp-218h]
.text:0000000000000253                 call    iDec256_CBC
.text:0000000000000258                 mov     edx, 80h ; '�'
```
**InitialRead** is used to check if there was check for the driver. As check for presence from chunks
will read from /dev/defcon_2017

**InitialWrite** is incremented any time write is called so 2 means that **IV** and **AES key** are written to
driver.

And then, there is check for **KnockCount**. What is that? Well only place where this code is referenced
is from **ioctl handler**, and it decrypts AES key with xor. Not to bore you with that code, I extracted
it from IDA and used nasm to compile, then called it 0x20 times to get key modification:
```
[BITS 64]
runshellcode:                 
                 push    rbp
                 mov     rax, 2709030E0A00633Ah
                 mov     rbp, rsp
                 sub     rsp, 20h
                 mov     [rbp-20h], rax
                 mov     rax, 370A656D526E0F10h
                 mov     [rbp-18h], rax
                 mov     rax, 42431232C202459h
                 mov     [rbp-10h], rax
                 mov     rax, 342D366D0D2B311Ch
                 mov     [rbp-8], rax
                 mov    rax, rdi        ;counter...
                 cdq
                 mov     r8, 657C4C8663F1749Fh
                 mov     esi, esi
                 shr     edx, 1Dh
                 lea     edi, [rax+rdx]
                 and     edi, 7
                 sub     edi, edx
                 lea     edx, [rax+7]
                 test    eax, eax
                 cmovns  edx, eax
                 sar     edx, 3
                 movsxd  rcx, edx
                 mov     rdx, 0FC38B42EC3023F1Ch
                 xor     rdx, [rbp+rcx*8-20h]
                 mov     ecx, 7
                 sub     ecx, edi
                 shl     ecx, 3
                 shr     rdx, cl
                 lea     ecx, [rdi*8]
                 shr     r8, cl
                 movsxd  rcx, eax
                 xor     rdx, r8
                 movzx   edx, dl
                 movzx   eax, dl
                 leave
                 retn
```                 

```
#include	<stdio.h>
#include	<stdlib.h>
#include	<sys/mman.h>
#include	<sys/stat.h>
#include	<sys/types.h>
#include	<fcntl.h>

typedef unsigned int (*GETMODS)(int counter);

int main(){
	int	fd;
	struct	stat	st;
	GETMODS 	getmods;
	void		*buff;
	unsigned	int rnd;
	unsigned	int	index;


	fd = open("knock.bin", O_RDONLY);
	fstat(fd, &st);

	buff = mmap(0, st.st_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	read(fd, buff, st.st_size);		

	getmods = (GETMODS)buff;
	for (index = 0; index < 0x20; index++)
		printf("%.02X", getmods(index]));
        printf("\n");
}
```
which yields: `444546434F4E20435446202017204C696768746E696E67205761732048657265`

So AES key has to be xored with this value to get final key. Now comes funny part. For every 
compile of module you will get different FlagData, different key and different IV. So 
basically if you didn't grab IV, KEY, FlagData at right time, you were out of the game.

So here is chunk which gives in key and data:
```
seg000:0000000000000000                 push    rbp
seg000:0000000000000001                 lea     rsi, aDevDefcon_2017 ; "/dev/defcon_2017"
seg000:0000000000000008                 xor     ecx, ecx
seg000:000000000000000A                 xor     r9d, r9d
seg000:000000000000000D                 xor     r8d, r8d
seg000:0000000000000010                 mov     edx, 1
seg000:0000000000000015                 mov     rbp, rsp
seg000:0000000000000018                 push    r12
seg000:000000000000001A                 mov     edi, 2
seg000:000000000000001F                 mov     r12, [rbp+10h]
seg000:0000000000000023                 push    rbx
seg000:0000000000000024                 mov     qword ptr [r12], 0
seg000:000000000000002C                 push    rbx
seg000:000000000000002D                 push    0
seg000:000000000000002F                 call    sub_C9          <--- syscall
...
seg000:0000000000000045                 lea     rdx, qword_140  <--- IV
seg000:000000000000004C                 xor     r9d, r9d
seg000:000000000000004F                 xor     r8d, r8d
seg000:0000000000000052                 mov     ecx, 10h
seg000:0000000000000057                 mov     rsi, rbx
seg000:000000000000005A                 push    0
seg000:000000000000005C                 mov     edi, 1
seg000:0000000000000061                 call    sub_C9
seg000:0000000000000066                 pop     r10
seg000:0000000000000068                 cmp     eax, 10h
seg000:000000000000006B                 pop     r11
seg000:000000000000006D                 jnz     short loc_99
seg000:000000000000006F                 push    rsi
seg000:0000000000000070                 lea     rdx, qword_120  <--- key
seg000:0000000000000077                 xor     r8d, r8d
seg000:000000000000007A                 xor     r9d, r9d
seg000:000000000000007D                 mov     edi, 1
seg000:0000000000000082                 mov     ecx, 20h ; ' '
seg000:0000000000000087                 push    0
seg000:0000000000000089                 mov     rsi, rbx
seg000:000000000000008C                 call    sub_C9
```
data which I can show you from chunk is kinda useless, as Key and IV don't match my final run
but here are they anyway:
```
seg000:0000000000000120 qword_120       dq 0E60CF3E51B5C7FC3h   ; DATA XREF: seg000:0000000000000070o
seg000:0000000000000128                 dq 18A456D5588B16F0h
seg000:0000000000000130                 dq 1A3504A01058084Eh
seg000:0000000000000138                 dq 0A16CA0C5042BF442h
seg000:0000000000000140 qword_140       dq 65AB9C82385C46D9h    ; DATA XREF: seg000:0000000000000045o
seg000:0000000000000148                 dq 4F3797916C598F0Bh
```
Compare them later with `IV` and `KEY` I have for final solution, and you will see that they are different.

So at this point, to get right key and right data I was waiting for this chunk to come and execute, 
and for any later chunk I would kill program. Afterwards just came message to read from `/dev/defcon_2017`
to get flag, and that was it.

At this point I've used `/proc/modules` to get address in memory of their module, and to dump stored data
there, eg. `IV/KEY/FlagData` which are:

**key:**
```
00000000  2e c8 da ec a5 4e 6d 5a  86 b0 31 0f 7e 4b 96 5b  |.....NmZ..1.~K.[|
00000010  a6 7e 6b 97 4d c5 ff 92  1c 88 bf 41 1d 35 a7 de  |.~k.M......A.5..|
```
**iv:**
```
00000000  5f 72 af f1 8b 50 fb 27  8b 35 1b 88 12 4c 27 83  |_r...P.'.5...L'.|
```

**FlagData:**
```
00000000  1e f0 3b ea 46 59 4d 4b  0c 95 5a 6b f7 0f 89 62  |..;.FYMK..Zk...b|
00000010  b1 f8 ca 5a 39 c3 33 46  d5 05 5a 38 fc 22 0e a8  |...Z9.3F..Z8."..|
00000020  01 92 06 f2 5d c5 2d c2  db 5d b5 bb b3 a3 b9 be  |....].-..]......|
00000030  2a 36 29 d0 ae 0a 96 70  b1 41 42 21 d2 b5 7a 51  |*6)....p.AB!..zQ|
00000040  9a 52 a8 99 48 05 4b e5  a1 3c 6c e7 40 f5 70 d6  |.R..H.K..<l.@.p.|
00000050  8d 73 0e 3b 3d 47 1d ee  02 34 f9 b8 db fe 86 f1  |.s.;=G...4......|
00000060  24 09 94 2f cb ee cc 26  cc c6 24 bd e8 e7 e1 e8  |$../...&..$.....|
00000070  5a 2d 58 15 2a 85 1c a4  74 3f 4b 15 19 e4 06 b9  |Z-X.*...t?K.....|
```
And running python script:
```
from    Crypto.Cipher import AES

mods = "444546434F4E20435446202017204C696768746E696E67205761732048657265".decode("hex");

raw_data = open("data1", "rb").read();
key      = open("key", "rb").read();
iv       = open("iv", "rb").read();
new_key = "";
for idx, x in enumerate(key):
        x = ord(x) ^ ord(mods[idx]);
        new_key += chr(x);
key = new_key;

aes = AES.new(key, AES.MODE_CBC, iv);
data = aes.decrypt(raw_data);
print(data);
```

We get:

**The flag is: Wouldn't you like to be a pepper too?**

If you wonder how all debugging was done, it was done using gdb and vmware, and if you
want to test these keys agains LKM, make sure to patch .ko FlagData with one provided 
in this readme.















