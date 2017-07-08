# LOLILOL CTF 2017 : task-name

**Category:** Reverse
**Points:** 35
**Solves:** 330    
**Description:**

> Can you... Reverse it ? Analyse it ? Calculate it ? Keygen it ? Modify it ? Enjoy yourself :)
> This challenge is separated in four steps with four separate flags to guide you.

> Challenge : [https://quals.nuitduhack.com/challenges/quals-ndh2k17/matriochka-step-1/](https://quals.nuitduhack.com/challenges/quals-ndh2k17/matriochka-step-1/)

## Write-up

The challenge only consist in one binary executable file : [step1](step1.bin). Let's execute this !

```
teamcryptis@debian:/var/ctf/NDH XV/reverse/$ chmod +x step1.bin
teamcryptis@debian:/var/ctf/NDH XV/reverse/$ ./step1.bin
Usage: ./step1.bin <pass>
teamcryptis@debian:/var/ctf/NDH XV/reverse/$ ./step1.bin flag!
Try again :(
```

As often, the program expects the flag as argument and display a message depending on it's value.

We start reversing with the [radare2](teamcryptis@debian:/var/ctf/NDH XV/reverse/$) tool :

```nasm
teamcryptis@debian:/var/ctf/NDH XV/reverse/$ r2 step1.bin
[0x00400570]> aa
[x] Analyze all flags starting with sym. and entry0 (aa)
[0x00400570]> pdf @ sym.
sym.deregister_tm_clones    sym.register_tm_clones      sym.__do_global_dtors_aux   
sym.frame_dummy             sym.__libc_csu_fini         sym.touch                   
sym._fini                   sym.mmm                     sym.you                     
sym.__libc_csu_init         sym._start                  sym.main                    
sym._init                   sym.my                      sym.imp.puts                
sym.imp.strlen              sym.imp.printf              sym.imp.fputc               
sym.imp.__libc_start_main   sym.imp.strcmp              
[0x00400570]> pdf @ sym.main
            ;-- main:
/ (fcn) sym.main 74
|   sym.main ();
|           ; var int local_10h @ rbp-0x10
|           ; var int local_4h @ rbp-0x4
|           ; DATA XREF from 0x0040058d (entry0)
|           0x00400666      55             push rbp
|           0x00400667      4889e5         mov rbp, rsp
|           0x0040066a      4883ec10       sub rsp, 0x10
|           0x0040066e      897dfc         mov dword [rbp - local_4h], edi
|           0x00400671      488975f0       mov qword [rbp - local_10h], rsi
|           0x00400675      837dfc02       cmp dword [rbp - local_4h], 2 ; [0x2:4]=0x102464c
|       ,=< 0x00400679      741b           je 0x400696
|       |   0x0040067b      488b45f0       mov rax, qword [rbp - local_10h]
|       |   0x0040067f      488b00         mov rax, qword [rax]
|       |   0x00400682      4889c6         mov rsi, rax
|       |   0x00400685      bfa0464300     mov edi, 0x4346a0
|       |   0x0040068a      b800000000     mov eax, 0
|       |   0x0040068f      e88cfeffff     call sym.imp.printf        ; int printf(const char *format);
|      ,==< 0x00400694      eb13           jmp 0x4006a9
|      |`-> 0x00400696      488b45f0       mov rax, qword [rbp - local_10h]
|      |    0x0040069a      4883c008       add rax, 8
|      |    0x0040069e      488b00         mov rax, qword [rax]
|      |    0x004006a1      4889c7         mov rdi, rax
|      |    0x004006a4      e807000000     call sym.mmm
|      |    ; JMP XREF from 0x00400694 (sym.main)
|      `--> 0x004006a9      b800000000     mov eax, 0
|           0x004006ae      c9             leave
\           0x004006af      c3             ret
[0x00400570]>
```

We can already notice a ```cmp``` at *0x00400675* which branch after the call of ```printf```. It compares the integer constant 2 with the first main function parameter (```argc```). This block must be the check on the command line argument count (which previously printed the program usage).

Thus, the important part of the main function is located between the offsets *0x00400696* and *0x004006a4*. This block prepares the stack and call the function **mmm**. Now, we have to print this function :

```nasm
[0x00400570]> pdf @ sym.mmm
/ (fcn) sym.mmm 29
|   sym.mmm ();
|           ; var int local_8h @ rbp-0x8
|           ; CALL XREF from 0x004006a4 (sym.main)
|           0x004006b0      55             push rbp
|           0x004006b1      4889e5         mov rbp, rsp
|           0x004006b4      4883ec10       sub rsp, 0x10
|           0x004006b8      48897df8       mov qword [rbp - local_8h], rdi
|           0x004006bc      488b45f8       mov rax, qword [rbp - local_8h]
|           0x004006c0      4889c7         mov rdi, rax
|           0x004006c3      e805000000     call sym.you
|           0x004006c8      83c001         add eax, 1
|           0x004006cb      c9             leave
\           0x004006cc      c3             ret
```

Again, the function doesn't seem to do anything except the call of another function. Here, we just have to continue the program exploration by going to each new called function :

```nasm
[0x00400570]> pdf @ sym.you
/ (fcn) sym.you 29
|   sym.you ();
|           ; var int local_8h @ rbp-0x8
|           ; CALL XREF from 0x004006c3 (sym.mmm)
|           0x004006cd      55             push rbp
|           0x004006ce      4889e5         mov rbp, rsp
|           0x004006d1      4883ec10       sub rsp, 0x10
|           0x004006d5      48897df8       mov qword [rbp - local_8h], rdi
|           0x004006d9      488b45f8       mov rax, qword [rbp - local_8h]
|           0x004006dd      4889c7         mov rdi, rax
|           0x004006e0      e805000000     call sym.touch
|           0x004006e5      83c001         add eax, 1
|           0x004006e8      c9             leave
\           0x004006e9      c3             ret
[0x00400570]> pdf @ sym.touch
/ (fcn) sym.touch 29
|   sym.touch ();
|           ; var int local_8h @ rbp-0x8
|           ; CALL XREF from 0x004006e0 (sym.you)
|           0x004006ea      55             push rbp
|           0x004006eb      4889e5         mov rbp, rsp
|           0x004006ee      4883ec10       sub rsp, 0x10
|           0x004006f2      48897df8       mov qword [rbp - local_8h], rdi
|           0x004006f6      488b45f8       mov rax, qword [rbp - local_8h]
|           0x004006fa      4889c7         mov rdi, rax
|           0x004006fd      e805000000     call sym.my
|           0x00400702      83c001         add eax, 1
|           0x00400705      c9             leave
\           0x00400706      c3             ret
[0x00400570]> pdf @ sym.my
/ (fcn) sym.my 276
|   sym.my ();
|           ; var int local_28h @ rbp-0x28
|           ; var int local_19h @ rbp-0x19
|           ; var int local_18h @ rbp-0x18
|           ; var int local_10h @ rbp-0x10
|           ; var int local_8h @ rbp-0x8
|           ; CALL XREF from 0x004006fd (sym.touch)
|           0x00400707      55             push rbp
|           0x00400708      4889e5         mov rbp, rsp
|           0x0040070b      4883ec30       sub rsp, 0x30               ; '0'
|           0x0040070f      48897dd8       mov qword [rbp - local_28h], rdi
|           0x00400713      488b45d8       mov rax, qword [rbp - local_28h]
|           0x00400717      4889c7         mov rdi, rax
|           0x0040071a      e8f1fdffff     call sym.imp.strlen        ; size_t strlen(const char *s);
|           0x0040071f      488945e8       mov qword [rbp - local_18h], rax
|           0x00400723      48837de801     cmp qword [rbp - local_18h], 1 ; [0x1:8]=0x10102464c45
|       ,=< 0x00400728      766a           jbe 0x400794
|       |   0x0040072a      48c745f80000.  mov qword [rbp - local_8h], 0
|       |   0x00400732      488b45e8       mov rax, qword [rbp - local_18h]
|       |   0x00400736      4883e801       sub rax, 1
|       |   0x0040073a      488945f0       mov qword [rbp - local_10h], rax
|      ,==< 0x0040073e      eb47           jmp 0x400787
|     .---> 0x00400740      488b55d8       mov rdx, qword [rbp - local_28h]
|     |||   0x00400744      488b45f8       mov rax, qword [rbp - local_8h]
|     |||   0x00400748      4801d0         add rax, rdx                ; '('
|     |||   0x0040074b      0fb600         movzx eax, byte [rax]
|     |||   0x0040074e      8845e7         mov byte [rbp - local_19h], al
|     |||   0x00400751      488b55d8       mov rdx, qword [rbp - local_28h]
|     |||   0x00400755      488b45f8       mov rax, qword [rbp - local_8h]
|     |||   0x00400759      4801c2         add rdx, rax                ; '#'
|     |||   0x0040075c      488b4dd8       mov rcx, qword [rbp - local_28h]
|     |||   0x00400760      488b45f0       mov rax, qword [rbp - local_10h]
|     |||   0x00400764      4801c8         add rax, rcx                ; '&'
|     |||   0x00400767      0fb600         movzx eax, byte [rax]
|     |||   0x0040076a      8802           mov byte [rdx], al
|     |||   0x0040076c      488b55d8       mov rdx, qword [rbp - local_28h]
|     |||   0x00400770      488b45f0       mov rax, qword [rbp - local_10h]
|     |||   0x00400774      4801c2         add rdx, rax                ; '#'
|     |||   0x00400777      0fb645e7       movzx eax, byte [rbp - local_19h]
|     |||   0x0040077b      8802           mov byte [rdx], al
|     |||   0x0040077d      488345f801     add qword [rbp - local_8h], 1
|     |||   0x00400782      48836df001     sub qword [rbp - local_10h], 1
|     |||   ; JMP XREF from 0x0040073e (sym.my)
|     |`--> 0x00400787      488b45e8       mov rax, qword [rbp - local_18h]
|     | |   0x0040078b      48d1e8         shr rax, 1
|     | |   0x0040078e      483b45f8       cmp rax, qword [rbp - local_8h]
|     `===< 0x00400792      77ac           ja 0x400740
|       `-> 0x00400794      488b45d8       mov rax, qword [rbp - local_28h]
|           0x00400798      beb2464300     mov esi, str.Tr4laLa___     ; "Tr4laLa!!!" @ 0x4346b2
|           0x0040079d      4889c7         mov rdi, rax
|           0x004007a0      e8abfdffff     call sym.imp.strcmp        ; int strcmp(const char *s1, const char *s2);
|           0x004007a5      85c0           test eax, eax
|       ,=< 0x004007a7      7562           jne 0x40080b
|       |   0x004007a9      bfbd464300     mov edi, str.Well_done_:_   ; "Well done :)" @ 0x4346bd
|       |   0x004007ae      e84dfdffff     call sym.imp.puts           ; loc.imp.__gmon_start__-0x60
|       |   0x004007b3      48c745f80000.  mov qword [rbp - local_8h], 0
|      ,==< 0x004007bb      eb42           jmp 0x4007ff
|     .---> 0x004007bd      488b0d344323.  mov rcx, qword [obj.stderr] ; [0x634af8:8]=0x654428203a434347 LEA obj.stderr ; "GCC: (Debian 4.9.2-10) 4.9.2" @ 0x634af8
|     |||   0x004007c4      488b45f8       mov rax, qword [rbp - local_8h]
|     |||   0x004007c8      480500094000   add rax, obj.nextStep
|     |||   0x004007ce      0fb630         movzx esi, byte [rax]
|     |||   0x004007d1      488b45f8       mov rax, qword [rbp - local_8h]
|     |||   0x004007d5      ba00000000     mov edx, 0
|     |||   0x004007da      48f775e8       div qword [rbp - local_18h]
|     |||   0x004007de      488b45d8       mov rax, qword [rbp - local_28h]
|     |||   0x004007e2      4801d0         add rax, rdx                ; '('
|     |||   0x004007e5      0fb600         movzx eax, byte [rax]
|     |||   0x004007e8      31f0           xor eax, esi
|     |||   0x004007ea      83f030         xor eax, 0x30
|     |||   0x004007ed      0fbec0         movsx eax, al
|     |||   0x004007f0      4889ce         mov rsi, rcx
|     |||   0x004007f3      89c7           mov edi, eax
|     |||   0x004007f5      e836fdffff     call sym.imp.fputc         ; int fputc(int c,
|     |||   0x004007fa      488345f801     add qword [rbp - local_8h], 1
|     |||   ; JMP XREF from 0x004007bb (sym.my)
|     |`--> 0x004007ff      48817df89f3d.  cmp qword [rbp - local_8h], 0x33d9f ; [0x33d9f:8]=0x517c515c04426411
|     `===< 0x00400807      76b4           jbe 0x4007bd
|      ,==< 0x00400809      eb0a           jmp 0x400815
|      |`-> 0x0040080b      bfca464300     mov edi, str.Try_again_:_   ; "Try again :(" @ 0x4346ca
|      |    0x00400810      e8ebfcffff     call sym.imp.puts           ; loc.imp.__gmon_start__-0x60
|      |    ; JMP XREF from 0x00400809 (sym.my)
|      `--> 0x00400815      488b45e8       mov rax, qword [rbp - local_18h]
|           0x00400819      c9             leave
\           0x0040081a      c3             ret
[0x00400570]>
```

4 functions are successively called : ```mmm```, ```you```, ```touch```, ```my```, the last one being clearly more complex than the previous ones.

By looking in the ```my``` function, we notice the use of the string "Tr4laLa!!!" at *0x00400798*. You have here a beautiful example of the French sense of humor ;) : **"mmm you touch my Tr4laLa!!!"**.

This function seems to compare the input flag with the string "Tr4laLa!!!", but many operation are made on the input before the comparison. The ```cmp``` at *0x00400728* after the ```strlen``` call could be a way to skip those operation ?

Anyway, the size of the function is more than 10 instructions and it is clearly too much for our laziness... It's time to summon [IDA](https://www.hex-rays.com/products/ida/) for the rescue !

1 minute too launch the Windows Virtual Machine, another minute to start the completly legal version of IDA Pro and we are. Here is the C pseudo-code of the function ```my``` given by IDA :

TODO() ...

## Other write-ups and resources

* [res1](linkres1)
* [res2](linkres2)
