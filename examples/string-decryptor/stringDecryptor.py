# Copyright (c) 2022 Ubique Innovation AG <https://www.ubique.ch>
# 
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from coeus_python import AnalyzeObject;

# Import the dex file
ao = AnalyzeObject("classes.dex", False, 1)

# search for our xor function
xor = ao.find_methods("xor")[0]

# since we know it is a method cast it as a method
# this would throw an exception if it was anything else
xorMethod = xor.as_method()
# now we invoke the VM to emulate the code
# primitive types and strings are automagically converted to Java VM types
encryptedBytes  = xorMethod("hallo", "p12")
# get_value as well tries to cast the result to python native types (string, integers, bytes, ...)
theBytes = encryptedBytes.get_value()
print("XOR encrypted bytes (from java function): ", theBytes)
# now we "decrypt" the encrypted bytes in python
key = b"p12"
resultBytes= []
# reverse our java xor cipher
for i in range(0,len(theBytes)):
    resultBytes += [theBytes[i] ^ key[i % 3]]
# since we know it was a string, decode as utf8
print("XOR decrypted bytes (from python): ", bytes(resultBytes).decode('utf8'))