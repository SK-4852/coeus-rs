#!/bin/bash
# Copyright (c) 2022 Ubique Innovation AG <https://www.ubique.ch>
# 
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

javac ./ch/ubique/Xor.java 
d8 ./ch/ubique/Xor.class

python3 stringDecryptor.py