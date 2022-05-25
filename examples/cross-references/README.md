# Cross-References

This example show cases how Coeus can be used, to perform certain static analysis on the binary to warn, when certain methods are obfuscated, when they should not have been. In this concrete example we want to add the BouncyCastle provider, which for example is needed if targeting older Android versions. Before Android API level 24 (Nougat/7), RSA 2048 for example was not mandatory to be provided by mobile manufacturers.

The APKs provided, are three APKs built with 

- proguard enabled ([test-proguard.apk](test-proguard.apk))
- proguard disabled ([test-noproguard.apk](test-noproguard.apk))
- proguard enabled, but with BouncyCastle exception ([test-proguard-bc-exception.apk](test-proguard-bc-exception.apk))

The code used is an basic starter project with the following snippet added:

```java
Security.removeProvider("BC")
Security.addProvider(BouncyCastleProvider())
```

The `BouncyCastleProvider` uses [put](https://docs.oracle.com/javase/8/docs/api/java/security/Provider.html#put-java.lang.Object-java.lang.Object-) to register certain providers, where the second argument represents the concrete class, implementing the specified provider. Since this is a string, proguard has no way of knowing that the BouncyCastle functions are actually used, and hence obfuscates them or even strips them off the binary.

Obviously this only presents an issue during runtime, when the BouncyCastle providers are simply not found and an exception will be thrown, when access to certain algorithms is needed.

Here we can actually use coeus to discover usages of `addProvider` and trace them back until we find the argument of `put`, from which we can then deduce, if it will fail at runtime (if the class is actually named like the argument, and found within the binary).