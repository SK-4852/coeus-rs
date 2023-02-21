// Copyright (c) 2023 Ubique Innovation AG <https://www.ubique.ch>
// 
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

import ch.ubique.SuperClass;

public class Test {
    public static void doPrint() {
        var arg = SuperClass.getArgument();
        SuperClass.print(arg);
    }
}