// Copyright (c) 2022 Ubique Innovation AG <https://www.ubique.ch>
// 
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

public class Xor {
    public byte[] xor(String plaintext, String key) {
        byte[] plaintextBytes = plaintext.getBytes();
        byte[] keyBytes = key.getBytes();
        byte[] encryptedBytes = new byte[plaintextBytes.length];

        for(var i =0; i< plaintextBytes.length; i++ ) {
            encryptedBytes[i] = (byte)(plaintextBytes[i] ^ keyBytes[i % keyBytes.length]);
        }
        return encryptedBytes;
    } 
 }