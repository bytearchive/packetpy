import shutil, os, sys
from distutils.core import setup, Extension
from distutils.command import build_scripts

"""
    TODO:
        Don't install pfreport if cubictemp and pygdchart don't exist.
"""

class MyBuildScripts(build_scripts.build_scripts):
    """
        This class extends the normal distutils to copy install scripts minus
        their .py extensions. That is, a script "foo.py" would be installed as
        simply "foo".
    """
    def copy_scripts(self):
        copies = []
        for i in self.scripts:
            if os.path.exists(i + ".py"):
                shutil.copyfile(i + ".py", i)
                copies.append(i)
        build_scripts.build_scripts.copy_scripts(self)
        for i in copies:
            os.remove(i)

CFLAGS=["-Wundef", "-Wall", "-D%s" % sys.platform.upper()]

pcap        = Extension(
                            "packet._pcap",
                            sources = ["packet/_pcap.c"],
                            libraries = ["pcap"],
                            extra_compile_args=CFLAGS
                       )
setup (
        name = 'Python packet capture and manipulation bindings',
        version = '0.1.1',
        description = 'An extensive set of Python bindings for packet handling.',
        ext_modules = [ pcap ],
        packages=["packet"],
        cmdclass = {"build_scripts": MyBuildScripts}
    )
