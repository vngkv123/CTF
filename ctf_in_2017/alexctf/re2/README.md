# Description
**Simple Strings index change**
```
  for ( i = std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::begin(&v11); ; sub_400D7A(&i) )
  {
    v13 = std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::end(&v11);
    if ( !sub_400D3D((__int64)&i, (__int64)&v13) )
      break;
    check = *(unsigned __int8 *)sub_400D9A((__int64)&i);
    if ( (_BYTE)check != off_6020A0[dword_6020C0[index]] )
      sub_400B56((__int64)&i, (__int64)&v13, check);
    ++index;
  }
```
