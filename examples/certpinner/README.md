# Certificate Pinner

This example shows how to auto-generate a Frida hook to disable OkHttp's CertificatePinner.

In non-obfuscated apps, [objection's](https://github.com/sensepost/objection/blob/master/agent/src/android/pinning.ts)
`android sslpinning disable` suffices.

With obfuscated apps, we need to know the new signature of the `CertPinner.check()` method that we need to hook.
With Coeus, we can automate the process of finding the this signature.

Then the steps of MITMing an app becomes:

1. Use https://github.com/NVISOsecurity/MagiskTrustUserCerts to get your CA into the system trust store.
   This removes the need of having to modify the `network-security-config.xml` to trust user CAs.
   (Alternatively, you can also hook the TrustManager similar to how objection does it.)

2. Use [certpinner.py](certpinner.py) to generate a Frida hook to disable the OkHttp cert pinner.

