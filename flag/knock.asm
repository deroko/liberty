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
                 movzx    eax, dl
                 leave
                 retn
