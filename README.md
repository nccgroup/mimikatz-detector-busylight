# Mimikatz detector driver - Busylight

USB HID driver emulation with PID/VID (0x3bca/0x27bb) of Plenom A/S Busylight Alpha, that is supported by Mimikatz.
When mimikatz is executed, a thread is spwaned by default that tries to locate one of the busylights that is supported. All HID devices are enumerated, if PID/VID is matching then packets are sent to flash the busylight in different colours.  

There are three types of packets that are sent to this device by mimikatz:
* keepalive - sent in every second or so
* start - sent only when device if found
* stop - when mimikatz is terminated or `busylight::off` is called

Since this device emulates a HID device that fully mimics the real USB device, mimikatz cannot distinguish between the two.

## What does the driver do (DetectUm)?

The driver is a umdf2 driver, which means:
* Works from Windows 8.1 and up
* Runs in user-space instead of kernel space
* Runs as NT Authority\Local Serive (low priv)
* Can be signed with a signing certificate

It emulates the behaviour of the busylight transparently. The driver checks if any of the three (start, keepalive, stop) packets have been received, if so, it loads a DLL and calls the three exported functions respectively.
The DLL doesn't need to be signed, although it might help trusted distribution. The functionality of the DLL can be changed easily.

## What does the DLL do (DetectDLL)?

It has three exported functions:
* void start()
* void keepalive()
* void stop()

These are called by the driver respectively. Currently three different reporting modes are implemented:
* Eventlog logging
* Debug message logging (can be seen by a debugger attached to the WUDFhost.exe)
* Remote syslog logging (might require more testing)

## What does the DLL log (DetectDLL)?

The following format is shown in the evenlog (or on the two other logging interface) under Windows Logs\Application

```
Tool started. PID: 13456
```

Pretty basic, but the two most important information is there. It is either started/stopped or keepalive, which means that the tool was running at the moment. PID is the process ID.  
Since the UMDF drivers are running the userspace with a low privileged user, information about other processes cannot be retrived in depth, this should be done by another service with higher privileges.


## Installation
Following needs to be performed as elevated user:
* Execute the following command: `install.bat`

## Uninstallation
Following needs to be performed as elevated user:
* Execute the following command: `uninstall.bat`

## Tests
It was tested on three different Windows 10 installations with rsyslog server.

The following Mimikatz variants were tested: 
* Original version of Mimikatz since *8th of October 2015* (Detected) 
* Original compiled into DLL (Detected) 
* Original compiled into PowerShell (Invoke-Mimikatz) (Detected) 
* PowerSploit - Invoke-Mimikatz (Detected) 
* CrackMapExec - Invoke-Mimikatz (Detected)
* Shellenium - Invoke-Mimikatz (Detected) 
  
  
* Cobalt Strike (NOT Detected)
* Metasploit kiwi module (NOT Detected)
* Pypykatz (NOT Detected)