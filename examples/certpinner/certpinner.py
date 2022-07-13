
# Copyright (c) 2022 Ubique Innovation AG <https://www.ubique.ch>
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import re
from pathlib import Path
from coeus_python import AnalyzeObject
from xml.dom.minidom import parseString


def find_pinner(apk):
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
                signature = ref.downcast().signature()
                # E.g. Lokhttp3/CertificatePinner;->check$okhttp(Ljava/lang/String;Lkotlin/jvm/functions/Function0;)V
                r = re.match(r"L(.+);->(.+)\(L(.+);L(.+);\)V", signature)
                return r.groups()


def find_package_name(apk) -> str:
    ao = AnalyzeObject(apk, False, 20)
    for manifest in ao.get_manifests():
        xml = parseString(manifest.get_xml())
        packagename = xml.getElementsByTagName('manifest')[0].attributes['package'].value
        return packagename


def create_hook(apk):
    classname, functionname, var1, var2 = find_pinner(apk)
    packagename = find_package_name(apk)
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
