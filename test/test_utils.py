import libpry
import packet.utils as utils


class uMultiord(libpry.AutoTree):
    def test_convert(self):
        assert utils.multiord("\x11") == 0x11
        assert utils.multiord("\x11\x11") == (256 * 0x11) + 0x11
        assert utils.multiord("") == 0
        assert utils.multiord("\x00") == 0
        assert utils.multiord("\x01") == 1


class uMultichar(libpry.AutoTree):
    def test_convert(self):
        libpry.raises("too wide", utils.multichar, 999999999, 2)


tests = [
    uMultiord(),
    uMultichar(),
]
