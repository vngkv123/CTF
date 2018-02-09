# Alicrackme_2
**write-up**
```
package com.yaotong.crackme;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

public class MainActivity extends Activity {
    public Button btn_submit;
    public EditText inputCode;

    public native boolean securityCheck(String str);

    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        getWindow().setBackgroundDrawableResource(R.drawable.bg);
        this.inputCode = (EditText) findViewById(R.id.inputcode);
        this.btn_submit = (Button) findViewById(R.id.submit);
        this.btn_submit.setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                if (MainActivity.this.securityCheck(MainActivity.this.inputCode.getText().toString())) {
                    MainActivity.this.startActivity(new Intent(MainActivity.this, ResultActivity.class));
                    return;
                }
                Toast.makeText(MainActivity.this.getApplicationContext(), "验证码校验失败", 0).show();
            }
        });
    }

    static {
        System.loadLibrary("crackme");
    }
}
```
코드자체는 별거 없으며, securityCheck에 대한 리턴 값을 통해 참, 거짓이 나뉘게 된다.
native쪽에서 리버싱과 디버깅을 통해 값을 어떤 값을 넣어야하는지 알아내야한다.
```
root@hammerhead:/data/local/tmp # ps | grep crack
u0_a162   29852 199   949880 61068 ffffffff 400a373c S com.yaotong.crackme
root@hammerhead:/data/local/tmp # ./gdb -q -p 29852
Attaching to process 29852
[New LWP 29854]
[New LWP 29857]
[New LWP 29858]
[New LWP 29859]
[New LWP 29860]
[New LWP 29861]
[New LWP 29862]
[New LWP 29874]
[New LWP 29875]
[New LWP 29876]
[New LWP 29882]
[New LWP 29883]
[New LWP 29904]
[New LWP 31783]
[New LWP 31784]
[New LWP 31786]

warning: Could not load shared library symbols for 8 libraries, e.g. memtrack.msm8974.so.
Use the "info sharedlibrary" command to see the complete listing.
Do you need "set solib-search-path" or "set sysroot"?
0x400a373c in epoll_wait () from /system/lib/libc.so
(gdb) c
Continuing.
[LWP 29876 exited]
[LWP 31786 exited]
[LWP 31784 exited]
[LWP 29883 exited]
[LWP 29882 exited]
[LWP 31783 exited]
[LWP 29859 exited]
[LWP 29861 exited]
[LWP 29857 exited]
[LWP 29904 exited]
[LWP 29875 exited]
[LWP 29854 exited]
[LWP 29874 exited]
[LWP 29858 exited]
[LWP 29862 exited]
[LWP 29860 exited]

Program terminated with signal SIGKILL, Killed.
The program no longer exists.
(gdb)
```
Anti debugging이 어디선가 돌아가고 있어서, 그냥 gdb를 붙이게 되면 죽게된다.
frida-trace를 통해 ptrace를 잡아보았지만 잡히지 않았다.
그러면 아마도 /proc/self/status쪽을 읽어서 task_struct상의 ptrace가 1일 때, 참으로 설정되는 값을 읽고있을 가능성이 크다.

그래서 open을 trace하여 보게되면 아래와 같다.
```
           /* TID 0x6ce5 */
 70134 ms  open(/proc/27855/status, 0)
 81384 ms  open(/proc/27855/status, 0)
 84386 ms  open(/proc/27855/status, 0)
 87386 ms  open(/proc/27855/status, 0)
 90387 ms  open(/proc/27855/status, 0)
107217 ms  open(/proc/27855/status, 0)
110218 ms  open(/proc/27855/status, 0)
```
open을 통해 TracerPid라는 값을 읽고있을 것이다.
따라서, 여기서는 open을 아예 호출안해버리면 안되기때문에, 다른 프로세스를 읽도록 값을 바꾸어준다.
```
  v5 = (unsigned __int8 *)(*(int (__fastcall **)(int, int, _DWORD))(*(_DWORD *)JNIEnv + 676))(JNIEnv, input, 0);
  v6 = off_628C;
  while ( 1 )
  {
    v7 = (unsigned __int8)*v6;
    if ( v7 != *v5 )
      break;
    ++v6;
    ++v5;
    v8 = 1;
    if ( !v7 )
      return v8;
  }
  return 0;
```
native쪽에서 핵심적인 부분을 보면, v5로 리턴되는 값은, Java string객체를 getUtf8String으로 변환하여, c문자열 형태로 받게된다. 그리고 v6의 값과 비교를 하는데, .init_array나 JNI_OnLoad부분에서 기존의 값과는 상이하게 바뀐 것 같다.
그러므로, open의 인자를 바꾸어 이미 안티디버깅을 무력화하였기때문에, 손쉽게 v6의 값이 무엇이 들어가는지를 확인하여 어떤 값을 넣으면되는지 보면 된다.

Answer : aiyou,bucuoo
