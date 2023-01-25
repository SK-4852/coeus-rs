# Debugger

## Info

The debugger module in Coeus allows one to debugg the smali code directly. For that a minimal [JDWP](https://docs.oracle.com/en/java/javase/17/docs/specs/jdwp/jdwp-spec.html) is implemented. Currently, the API should allow for stepping, setting breakpoints, and changing primitive values and string values.

Note, the APK needs to be debuggable, either by setting the flag on the `AndroidManifest` or by being root on the device (and setting the flag globally). Since the android device does not implement all functions defined by the JDWP spec we hack around them a bit. 

Further, in this initial draft of the debugger API, all reference types are hardcoded to be u64. This probably leads to problems on 32bit android devices.

## Prerequisites

The APK in this folder needs to be installed on the device, so the Debugger can connect to it. The APK is a minimal example playing arround with the `BiometricPrompt` API. When the APK is installed, and the phone connected to the computer (via USB e.g.), we can ask `adb` to show us all debuggable processes with 

```bash
> adb jdwp
```

Now we need to forward that pid to a tcp port on the host, so that the script is able to connect:

```bash
> adb forward tcp:8000 jdwp:<pid>
```

Now the script should be able to run, and set a breakpoint. After pressing the button and inputting the fingerprint, the breakpoint will be hit and present a ultra minimal UI.

Note that the python stuff is not really threaded, so the wait for a debugger package is blocking (though it will give up after 10s, so that ctrl+c events can be processed anyways :D).
