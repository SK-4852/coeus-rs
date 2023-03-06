# Copyright (c) 2023 Ubique Innovation AG <https://www.ubique.ch>
# 
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from coeus_python import AnalyzeObject

ao = AnalyzeObject("../certpinner/wallet-prod-4.1.0-4010000-signed.apk", True, -1)

cd = ao.find_classes("CertificateDecoder;")[0].as_class()
decode =cd["decode"]
from graphviz import Source
ao.build_supergraph(["Lcom/upokecenter"])
graph = decode.callgraph([""], ao)
s = Source(graph.to_dot(), format="pdf")
s.render("test")