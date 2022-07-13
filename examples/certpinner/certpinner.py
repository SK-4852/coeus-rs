
# Copyright (c) 2022 Ubique Innovation AG <https://www.ubique.ch>
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import re
from pathlib import Path
from typing import Optional
from coeus_python import AnalyzeObject
from xml.dom.minidom import parseString


def find_pinner(apk) -> Optional[tuple[str,str,str,str]]:
    """Finds the CertificatePinner.check() function.
    https://github.com/square/okhttp/blob/3ad1912f783e108b3d0ad2c4a5b1b89b827e4db9/okhttp/src/jvmMain/kotlin/okhttp3/CertificatePinner.kt#L149

    This is a very basic approach. It can be thrawted e.g. by an app including the indicator strings at other places in the app.

    :returns: classname, functionname, var1, var2
    """
    ao = AnalyzeObject(apk, False, 20)
    indicators = [
        ".*Certificate pinning failure.*",
        ".*Pinned certificates for.*",
    ]

    for indi in indicators:
        strings = ao.find_strings(indi)
        for str in strings:
            references = str.cross_references(ao)
            for ref in references:
                try:
                    method = ref.as_method()
                    class_name = method.get_class().friendly_name()
                    method_name = method.name()
                    arg1, arg2 = method.get_argument_types_string()
                    return class_name, method_name, arg1, arg2
                except:
                    pass
    return None


def find_package_name(apk) -> Optional[str]:
    ao = AnalyzeObject(apk, False, 20)
    for manifest in ao.get_manifests():
        xml = parseString(manifest.get_xml())
        packagename = xml.getElementsByTagName('manifest')[0].attributes['package'].value
        return packagename
    return None


def create_hook(apk):
    pinner_result = find_pinner(apk)
    if pinner_result is None:
        return
    classname, functionname, var1, var2 = pinner_result
    packagename = find_package_name(apk)
    if packagename is None:
        return
    print(f"Found: packagename={packagename}, classname={classname}, functionname={functionname}, var1={var1}, var2={var2}")

    with open('hook.js.j2') as f:
        template = f.read()
        template = template.replace("{{ PACKAGENAME }}", packagename)
        template = template.replace("{{ CLASSNAME }}", classname)
        template = template.replace("{{ FUNCTIONNAME }}", functionname)
        template = template.replace("{{ VAR1 }}", var1)
        template = template.replace("{{ VAR2 }}", var2)

    filename = f'hook-{Path(apk).stem}.js'
    with open(filename, 'w') as f:
        f.write(template)
    print(f"Wrote hook to {filename}")


if __name__ == "__main__":
    create_hook("wallet-prod-4.1.0-4010000-signed.apk")
