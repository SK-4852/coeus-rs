// Copyright (c) 2022 Ubique Innovation AG <https://www.ubique.ch>
// 
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

public class DeadBranch {
    public boolean deadBranch() {
        int eins = 1;
        int zwei = 2;
        if (eins < zwei) {
            return true;
        } else {
            return false;
        }
    }
    public boolean thisIsLoop() {
        int i =0;
        while (i < 10) {
            int b = 2;
            b *= 3;
            i += 1;
        }
        return true;
    }
}