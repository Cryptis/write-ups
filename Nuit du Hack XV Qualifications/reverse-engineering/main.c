#include <stdint.h>
#include <string.h>
#include <stdio.h>

uint64_t my(char *a1)
{
  char v1; // ST17_1@3
  uint64_t v3; // [sp+18h] [bp-18h]@1
  int64_t v4; // [sp+20h] [bp-10h]@2
  uint64_t v5; // [sp+28h] [bp-8h]@2
  uint64_t i; // [sp+28h] [bp-8h]@6

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
  // Here, we display the current value of a1 for determining which modifications has been done ;).
  printf("%s   ", a1);

  if ( !strcmp(a1, "Tr4laLa!!!") )
  {
    puts("Well done :)");

    /*Discarding this part of the code :
    for ( i = 0LL; i <= 0x33D9F; ++i )
      fputc((char)(*(_BYTE *)(i + 4196608) ^ a1[i % v3] ^ 0x30), _bss_start);*/
  }
  else
  {
    puts("Try again :(");
  }
  return v3;
}

int main()
{
    char str[1000];
    printf("Enter the string : ");
    scanf("%s", str);
    my(str);
}
