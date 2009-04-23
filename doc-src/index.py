import os, os.path, subprocess
import countershape.widgets
import countershape.layout
import countershape.grok
from countershape.doc import *

this.layout = countershape.layout.Layout("_layout.html")
this.markdown = "rst"
ns.docTitle = "Packetpy Manual"
ns.docMaintainer = "Aldo Cortesi"
ns.docMaintainerEmail = "aldo@nullcube.com"
ns.copyright = "Copyright Nullcube 2008"
ns.head = countershape.template.File(None, "_header.html")
ns.sidebar = countershape.widgets.SiblingPageIndex(
                '/index.html',
                exclude=['countershape']
            )
ns.cs = countershape.grok.parse("../packet")

# This should be factored out into a library and tested...
class Examples:
    def __init__(self, d):
        self.d = os.path.abspath(d)

    def _wrap(self, proc, path):
        f = file(os.path.join(self.d, path)).read()
        if proc:
            f = proc(f)
        post = "<div class=\"fname\">(%s)</div>"%path
        return f + post

    def py(self, path, **kwargs):
        return self._wrap(ns.pySyntax.withConf(**kwargs), path)

    def _preProc(self, f):
        return "<pre class=\"output\">%s</pre>"%f

    def plain(self, path):
        return self._wrap(self._preProc, path)

ns.examples = Examples("..")


pages = [
    Page("index.html", "Introduction"),
    Page("packet.html", "Packet"),
    Directory("packet"),
    Page("pcap.html", "P Cap"),
    Directory("pcap"),
    Page("examples.html", "Examples"),
    Page("admin.html", "Administrivia")
]
