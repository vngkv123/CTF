# marimo challenge
**write-up**
- Binary's mitigations.

```
asiagaming-> checksec --file marimo
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   marimo
```
- Some hidden function's in main.
```
void __fastcall main(__int64 a1, char **a2, char **a3)
{
  __int64 choice; // [rsp+0h] [rbp-30h]
  __int64 v4; // [rsp+8h] [rbp-28h]
  __int64 v5; // [rsp+10h] [rbp-20h]
  int v6; // [rsp+18h] [rbp-18h]
  __int16 v7; // [rsp+1Ch] [rbp-14h]
  unsigned __int64 canary; // [rsp+28h] [rbp-8h]

  canary = __readfsqword(0x28u);
  choice = 0LL;
  v4 = 0LL;
  v5 = 0LL;
  v6 = 0;
  v7 = 0;
  intro();
  while ( 1 )
  {
    do
    {
      menu();
      fflush(stdout);
      __isoc99_scanf((__int64)" %30[^\n]s", (__int64)&choice);
    }
    while ( (unsigned int)secret((const char *)&choice) );
    switch ( (char)choice )
    {
      case 'A':
        about();                                // nothing
        break;
      case 'B':
        buy();
        break;
      case 'Q':
        puts("bye");
        exit(0);
        return;
      case 'S':
        sell();
        break;
      case 'V':
        view();
        break;
      default:
        puts("wrong input");
        break;
    }
  }
}
```
- I marked it as `secret` function.
- It creates marimo for free.

```
signed __int64 __fastcall happy(const char *a1)
{
  struct marimo *mPtr; // ST18_8

  if ( strcmp(a1, "show me the marimo") )
    return 0LL;
  mPtr = (struct marimo *)malloc(0x18uLL);
  set_marimo(mPtr, 1u, 5u);
  chunk_array[bowl_count++] = (__int64)mPtr;
  return 1LL;
}
```

- As this bianry run on ASLR context, we need to leak some libc pointer.
- Leak vulnerability is in `view()` function.

```
  current_time = time(0LL);
  printf("current time : %d\n", current_time);
  current_size = current_time + marimo_chunk->size - marimo_chunk->birth;
  ...
  
    if ( ans != 'B' )
    {
      if ( ans - 0x30 < 0 || ans - 0x30 >= bowl_count )
        puts("[X] Invalid");
      else
        show_state((struct marimo *)chunk_array[ans - 0x30]);
    }
```

- We can see `marimo` state, and can modify the current value.
- Size for modifying is set by `time(0) - time of marimo creation time`
```
 if ( v4 == 'M' )
  {
    puts("Give me new profile");
    printf(">> ", &v4);
    fflush(stdout);
    get_chunk_input((__int64)marimo_chunk->profile, 0x20 * current_size);
    show_state(marimo_chunk);
  }
```
- So, it can overwrite next marimo's structure. -> lead us to get libc pointer.
- Now, we have libc pointer and as same way, we can control the world.

- flag is `But_every_cat_is_more_cute_than_Marimo`
