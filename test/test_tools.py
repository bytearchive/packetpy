import StringIO, os.path
import libpry
import packet.tools as tools
        
class uSplitter(libpry.TmpDirMixin, libpry.AutoTree):
    def test_nonexistent(self):
        libpry.raises(
            "no such file", tools.Splitter,
            4,
            self["tmpdir"],
            ["nonexistent"]
        )
        
    def test_init(self):
        s = tools.Splitter(
                4,
                self["tmpdir"],
                [
                    "data/dump.sequence1",
                    "data/dump.sequence2"
                ]
            )
        assert s.totalsize == 44848
                    
    def test_call(self):
        io = StringIO.StringIO()
        s = tools.Splitter(
                4,
                self["tmpdir"],
                [
                    "data/dump.sequence1",
                    "data/dump.sequence2"
                ],
                out = io
            )
        files = s()
        for i in files:
            assert os.path.isfile(i)
        
        
tests = [
    uSplitter()
]
