
import libpry
import packet.utils as utils


class Multiord(libpry.AutoTree):
    def test_convert(self):
        assert utils.multiord("\x11") == 0x11
        assert utils.multiord("\x11\x11") == (256 * 0x11) + 0x11
        assert utils.multiord("") == 0
        assert utils.multiord("\x00") == 0
        assert utils.multiord("\x01") == 1


tests = [
    Multiord()
]

