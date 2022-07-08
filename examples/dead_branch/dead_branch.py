# Copyright (c) 2022 Ubique Innovation AG <https://www.ubique.ch>
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from coeus_python import AnalyzeObject, DexVm, Flow

# Import the dex file
ao = AnalyzeObject("classes.dex", False, 1)
# Find all classes (should be one)
clazzes = ao.find_classes(".*")
# Initialize a vm for one shot emulation (e.g. string decryption and such)
vm = DexVm(ao)
for clazz in clazzes:
    # check every method
    for m in clazz.as_class().get_methods():
        # find all branch decision
        branches = m.find_all_branch_decisions(vm)
        for b in branches:
            # a dead branch is defined to evalute to a constant expression and only be visited once (no loops)
            if b.has_dead_branch():
                print(f"Found dead branch in {m.signature()}")
