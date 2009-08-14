import os.path
import libpry
import packet.tools as tools
        
class uSplitter(libpry.AutoTree):
    def test_init(self):
        tools.Splitter()

    def test_nonexistent(self):
        s = tools.Splitter()
        libpry.raises(
            "no such file",
            s, ["nonexistent"], 4, self.tmpdir(),
        )
        
    def test_call(self):
        s = tools.Splitter()
        files = s(
            [
                "splitterdata/dump.sequence1",
                "splitterdata/dump.sequence2"
            ],
            4,
            os.path.join(self.tmpdir(), "pack"),
        )
        assert len(files) == 4
        for i in files:
            assert os.path.isfile(i)
        
        
tests = [
    uSplitter()
]
