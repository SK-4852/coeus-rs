
# Copyright (c) 2022 Ubique Innovation AG <https://www.ubique.ch>
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from coeus_python import AnalyzeObject


def check_proguard_enabled(apk_path: str, custom_ignores=[]) -> bool:
    """Heuristic to check whether proguard is enabled on an APK
    """
    ao = AnalyzeObject(apk_path, False, 1)

    num_short_classnames = 0
    num_classnames = 0

    # Count the classes with short names
    classes = ao.find_classes(".*")
    for c in classes:
        c = c.as_class()
        name = c.name()

        # Ignore standard classes (which are often not obfuscated). Note the trailing /!
        ignores = ["Landroid/", "Landroidx/", "Ljava/", "Lcom/google/", "Lj$/util/", "Lj$/time/"] + custom_ignores
        if any(name.startswith(x) or name.startswith("["+x) for x in ignores):
            continue

        # Ignore classes that don't have any definition in the dexfile
        if c.code(ao) == "NO CLASS DEF FOUND":
            continue

        num_classnames += 1

        # Obfuscated class names are of the form "Lab/c$d;" or "Lbb/b$a$a$a;". Real names are much longer, e.g. "Lcom/example/myapp/FirstFragment;"
        if len(name) < 15:
            num_short_classnames += 1
        #else:
        #    print(name)

    # Proguard/obfuscation is likely enabled if a large fraction of classes have short names.
    fraction = round(num_short_classnames / num_classnames, 4)
    enabled = fraction > 0.8

    print(f"{num_short_classnames} / {num_classnames} = {fraction} classes have short names (ignoring stdlib).")
    if enabled:
        print(f"==> Proguard is present for {apk_path}\n")
    else:
        print(f"==> Proguard is MISSING for {apk_path}\n")

    return enabled


if __name__ == "__main__":
    check_proguard_enabled("../cross-references/test-proguard.apk")
    check_proguard_enabled("../cross-references/test-noproguard.apk")

    # In this apk we asked ProGuard not to obfuscated BouncyCastle. Thus ignore it in our analysis.
    check_proguard_enabled("../cross-references/test-proguard-bc-exception.apk", custom_ignores=["Lorg/bouncycastle"])
