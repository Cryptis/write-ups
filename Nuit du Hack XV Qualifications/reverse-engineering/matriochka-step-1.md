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

We start reversing with the [radare2](https://github.com/radare/radare2) tool :

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

We can already notice a ```cmp``` at **0x00400675** which branch after the call of ```printf```. It compares the integer constant 2 with the first main function parameter (```argc```). This block must be the check on the command line argument count (which previously printed the program usage).

Thus, the important part of the main function is located between the offsets **0x00400696** and **0x004006a4**. This block prepares the stack and call the function ```mmm```. Now, we have to print this function :

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

By looking in the ```my``` function, we notice the use of the string "Tr4laLa!!!" at **0x00400798**. You have here a beautiful example of the French sense of humor ;) : *"mmm you touch my Tr4laLa!!!"*.

This function seems to compare the input flag with the string "Tr4laLa!!!", but many operation are made on the input before the comparison. The ```cmp``` at **0x00400728** after the ```strlen``` call could be a way to skip those operation ?

Anyway, the size of the function is more than 10 instructions and it is clearly too much for our laziness... It's time to summon [IDA](https://www.hex-rays.com/products/ida/) for the rescue !

1 minute too launch the Windows Virtual Machine, another minute to start the completely legal version of IDA Pro and we are. The following is the C pseudo-code of the ```my``` given by IDA (please note that it's a 64 bit binary, you have to use the ```idaq64``` launcher) :

```c++
unsigned __int64 __fastcall my(const char *a1)
{
  char v1; // ST17_1@3
  unsigned __int64 v3; // [sp+18h] [bp-18h]@1
  signed __int64 v4; // [sp+20h] [bp-10h]@2
  unsigned __int64 v5; // [sp+28h] [bp-8h]@2
  unsigned __int64 i; // [sp+28h] [bp-8h]@6

  v3 = strlen(a1);
  if ( v3 > 1 )
  {
    v5 = 0LL;
    v4 = v3 - 1;
    while ( v3 >> 1 > v5 )
    {
      v1 = a1[v5];
      a1[v5] = a1[v4];
      a1[v4] = v1;
      ++v5;
      --v4;
    }
  }
  if ( !strcmp(a1, "Tr4laLa!!!") )
  {
    puts("Well done :)");
    for ( i = 0LL; i <= 0x33D9F; ++i )
      fputc((char)(*(_BYTE *)(i + 4196608) ^ a1[i % v3] ^ 0x30), _bss_start);
  }
  else
  {
    puts("Try again :(");
  }
  return v3;
}
```

The part of the code situated before the condition (```!strcmp(a1, "Tr4laLa!!!")```) correspond to the operations on the input string. We could read this pseudo-code and try to understand what is the actual effect on the string ```v1```. However, we will first rewrite this code into a valid C program and run it on different string in order to try to understand it.

Few modifications are needed to obtain a compilable C code. The loop inside the if condition can be confusing and is not needed to our tests and can thus be safely removed. You can find the final C source code used [here](main.c).

Next, we compile and execute this code and make try with some strings :

```
teamcryptis@debian:/var/ctf/NDH XV/reverse/$ gcc main.c
teamcryptis@debian:/var/ctf/NDH XV/reverse/$ ./a.out
Enter the string : test
tset   Try again :(
teamcryptis@debian:/var/ctf/NDH XV/reverse/$ ./a.out
Enter the string : a_string
gnirts_a   Try again :(
teamcryptis@debian:/var/ctf/NDH XV/reverse/$ ./a.out
Enter the string : Nuit_du_hack_2017
7102_kcah_ud_tiuN   Try again :(
teamcryptis@debian:/var/ctf/NDH XV/reverse/$ ./a.out
Enter the string : Tr4laLa!!!
!!!aLal4rT   Try again :(
```

This function seems to be a string-reverse function. As the input is compared with the string *"Tr4laLa!!!"*, we will simply try the reverse : *"!!!aLal4rT"* :

```teamcryptis@debian:/var/ctf/NDH XV/reverse/$ ./step1.bin !!!aLal4rT
bash: !aLal4rT: event not found
```
OOPS ! My bad... the '!' symbol have to be escaped :

```
teamcryptis@debian:/var/ctf/NDH XV/reverse/$ ./step1.bin \!\!\!aLal4rT
Well done :)
```

Well played, the flag i s **!!!aLal4rT**.

---

Note that if when the correct flag is passed to the program (i.e. ```./step1.bin \!\!\!aLal4rT```), many symbols are printed to the standard output. This is because the program display the next challenge (matriochka-step2) on **stderr** when the correct flag is given. This operation is done with the loop which was discarded in our C program :

```
for ( i = 0LL; i <= 0x33D9F; ++i )
  fputc((char)(*(_BYTE *)(i + 4196608) ^ a1[i % v3] ^ 0x30), _bss_start);
```
To create the second challenge executable, just redirect the **stderr** output to a file (you can find the second challenge executable [here](step2.bin)):

```
teamcryptis@debian:/var/ctf/NDH XV/reverse/$ ./step1.bin \!\!\!aLal4rT 2> step2.bin
teamcryptis@debian:/var/ctf/NDH XV/reverse/$ chmod +x step2.bin
teamcryptis@debian:/var/ctf/NDH XV/reverse/$ ./step2.bin
Usage: ./step2.bin <pass>
```

Here we go, again ! ;)


## Other write-ups and resources

* [res1](linkres1)
* [res2](linkres2)
