# floppy
**write-up**

- stack corruption exploitation
- vulnerabilities is in `floppy_modify` function
```
char *__cdecl floppy_modify(struct floppy *floppy)
{
  char *result; // eax
  char s; // [esp+8h] [ebp-410h]
  int v3; // [esp+408h] [ebp-10h]
  size_t v4; // [esp+40Ch] [ebp-Ch]

  v3 = 0;
  v4 = 0;
  memset(&s, 0, 0x400u);
  if ( !floppy->check )
  {
    puts("Floppy disk is unusable.\n");
    exit(-1);
  }
  puts("Which one do you want to modify? 1 Description | 2 Data\n");
  _isoc99_scanf("%d", &v3);
  IO_getc(stdin);
  if ( v3 == 1 )
  {
    puts("Input Description: \n");
    read(0, &s, 37u);
    v4 = strlen(&s);
    result = strncpy(floppy->description, &s, v4 - 1);
  }
  else
  {
    if ( v3 != 2 )
    {
      puts("Baaaaaaaaaack.\n");
      exit(-1);
    }
    puts("Input Data: ");
    read(0, &s, 0x200u);
    floppy->length = strlen(&s);
    result = strcpy(floppy->data, &s);
  }
  return result;
```
- `Description` is 12byte length, but it modify 37byte.
- It can overwrite `floppy1` structure.
- It lead us to libc leak, stack leak and control the $pc. 

![solve](https://github.com/vngkv123/CTF/blob/master/ctf_in_2016/codegate/floppy/solve.png)
