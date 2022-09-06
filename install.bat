copy /Y x64\Release\DetectDLL.dll C:\Windows\system32\
rem certutil -addstore "TrustedPublisher" certificate\nccgroup.cer
tools\x64\devcon.exe install x64\Release\DetectUm\DetectUm.inf root\DetectUm
