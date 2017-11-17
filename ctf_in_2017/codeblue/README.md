# House of Force Exploitation

**vulnerability**

- check what `strchr` do.
- all strings terminated with null byte in C language.
- `strchr("blahblah...", 0);` -> return nonzero value !
- it can modify top chunk memory and leak important memory
- I've solve it only local context after the CTF.

```
  while ( *chunk_buffer )
  {
    if ( *chunk_buffer == '%' )                 // data start with %
    {
      if ( strchr("0123456789ABCDEFabcdef", (char)chunk_buffer[1])
        && strchr("0123456789ABCDEFabcdef", (char)chunk_buffer[2]) )
      {
        if ( islower((char)chunk_buffer[1]) )   // if lower, return some nonzero value
          chunk_buffer[1] = toupper((char)chunk_buffer[1]);
        if ( islower((char)chunk_buffer[2]) )
          chunk_buffer[2] = toupper((char)chunk_buffer[2]);
        if ( chunk_buffer[1] <= 0x40 )          // if \x00 -> true and if in numeric range
          chr1 = chunk_buffer[1] - 0x30;
        else
          chr1 = chunk_buffer[1] - 0x37;
        chr2 = 0x10 * chr1;                     // shl 4
        if ( chunk_buffer[2] <= 0x40 )          // if \x00 -> true and if in numeric range
          chr3 = chunk_buffer[2] - 0x30;
        else
          chr3 = chunk_buffer[2] - 0x37;
        *ptr++ = chr2 + chr3;
        chunk_buffer += 2;                      // result is chunk_buffer + 3
      }
    }
    else
    {
      tptr = ptr++;
      *tptr = *chunk_buffer;
    }
    ++chunk_buffer;
  }
```

**Exploitation**

- overwrite `__free_hook` to `system`
