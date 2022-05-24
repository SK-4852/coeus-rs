# Copyright (c) 2022 Ubique Innovation AG <https://www.ubique.ch>
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from coeus_python import AnalyzeObject

# Import the dex file
ao = AnalyzeObject("classes.dex", False, 1)

# search for our xor function
xor = ao.find_methods("xor")[0]

# cast what we found in the dex file to a method
# this would throw an exception if it was anything else
xorMethod = xor.as_method()

# you can print the byte code of the method
#print(xorMethod.code())

# "invoke" the method
# this causes coeus' VM to emulate the code
# primitive types and strings are automagically converted to Java VM types
encryptedBytes = xorMethod("secretmessage", "secretkey")

# try to cast the result to python native types (string, integers, bytes, ...)
outputBytes = encryptedBytes.get_value()
print(f"XOR Java-encrypted bytes: {outputBytes}")

# revert the xor cipher in python
key = b"secretkey"
decryptedBytes = []
for i in range(0, len(outputBytes)):
    decryptedBytes.append(outputBytes[i] ^ key[i % len(key)])

print(f"XOR Python-decrypted bytes: {bytes(decryptedBytes).decode()}")
