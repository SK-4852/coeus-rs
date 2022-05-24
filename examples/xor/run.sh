#!/bin/bash
# Copyright (c) 2022 Ubique Innovation AG <https://www.ubique.ch>
# 
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Compile the Java class down to a dexfile (thus imitating an APK)
javac Xor.java
d8 Xor.class

# Analyse the dexfile with Coeus
python3 xor.py