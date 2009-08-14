
import libpry
import packet.address as address


class u_getBlocks(libpry.AutoTree):
    def test_get(self):
        assert address.getBlocks("00:01:a0") == [0, 1, 160]
        assert address.getBlocks("a0") == [160]

    def test_errs(self):
        libpry.raises("malformed address", address.getBlocks, "xx")
        libpry.raises("malformed address", address.getBlocks, "aaaaa")


class u_MaskMixin(libpry.AutoTree):
    def test_countPrefix(self):
        m = address._MaskMixin()
        assert m._countPrefix("\xff") == 8
        assert m._countPrefix("\xff\xff") == 16
        assert m._countPrefix("\xff\xf0") == 12

    def test_countPrefix_err(self):
        m = address._MaskMixin()
        libpry.raises("invalid mask", m._countPrefix, "\xff\xaa")
        libpry.raises("invalid mask", m._countPrefix, "\xff\x00\00\aa")
    

class uEthernetAddress(libpry.AutoTree):
    def test_init(self):
        a = address.EthernetAddress("00:00:00:00:00:00")
        b = address.EthernetAddress("00:00:00:00:00:00")
        repr(a)
        assert a == b
        assert a == "00:00:00:00:00:00"

    def test_err(self):
        libpry.raises(
            "malformed ethernet",
            address.EthernetAddress, "00:00:00:00:00"
        )
        libpry.raises(
            "must have 6 bytes",
            address.EthernetAddress.fromBytes, "\xaa"
        )


class uIPAddress(libpry.AutoTree):
    def test_init(self):
        a = address.IPAddress("192.168.0.1")
        a.mask("255.255.0.0")
        repr(a)

    def test_inNetwork(self):
        a = address.IPAddress("192.168.0.1")
        m = a.mask("255.255.0.0")
        assert address.IPAddress("192.168.0.5").inNetwork(a, m)
        assert address.IPAddress("192.168.255.5").inNetwork(a, m)
        assert not address.IPAddress("192.169.0.5").inNetwork(a, m)

    def test_err(self):
        libpry.raises(
            "must have 4 bytes",
            address.IPAddress.fromBytes, "\xaa"
        )


class uIPMask(libpry.AutoTree):
    def test_init(self):
        a = address.IPMask(None)
        assert a == "255.255.255.255"
        a = address.IPMask(24)
        assert a == "255.255.255.0"
        a = address.IPMask(25)
        assert a == "255.255.255.128"

    def test_err(self):
        libpry.raises(
            "must be between 0 and 32",
            address.IPMask, 64
        )


class uIP6Address(libpry.AutoTree):
    def test_init(self):
        a = address.IP6Address("ff::01")
        assert a == "ff::01"
        repr(a)
        a.mask("ffff::")

    def test_err(self):
        libpry.raises(
            "must have 16 bytes",
            address.IP6Address.fromBytes, "\xff"
        )


class uIP6Mask(libpry.AutoTree):
    def test_init(self):
        a = address.IP6Mask(None)
        assert a == "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
        a = address.IP6Mask(9)
        assert a == "ff80::"

    def test_err(self):
        libpry.raises(
            "must be between 0 and 128",
            address.IP6Mask, 129
        )
        

class uAddress(libpry.AutoTree):
    def test_init(self):
        a = address.Address("192.168.0.1")
        assert isinstance(a, address.IPAddress)
        a = address.Address(a)
        assert isinstance(a, address.IPAddress)
        a = address.Address("ffff::")
        assert isinstance(a, address.IP6Address)
        a = address.Address("00:00:00:00:00:00")
        assert isinstance(a, address.EthernetAddress)
        libpry.raises("not a valid address", address.Address, "foo")


class uAddressFromBytes(libpry.AutoTree):
    def test_init(self):
        a = address.Address("192.168.0.1")
        assert isinstance(address.AddressFromBytes(a.bytes), address.IPAddress)
        a = address.Address("ffff::")
        assert isinstance(address.AddressFromBytes(a.bytes), address.IP6Address)
        a = address.Address("00:00:00:00:00:00")
        assert isinstance(address.AddressFromBytes(a.bytes), address.EthernetAddress)
        libpry.raises("not a valid address", address.AddressFromBytes, "foo")


class uMask(libpry.AutoTree):
    def test_init(self):
        m = address.Mask("255.255.0.0")
        assert m == "255.255.0.0"
        m = address.Mask("ffff::")
        assert m == "ffff::"
        libpry.raises("not a valid mask",  address.Mask, "foo")


tests = [
    u_getBlocks(),
    u_MaskMixin(),
    uEthernetAddress(),
    uIPAddress(),
    uIPMask(),
    uIP6Address(),
    uIP6Mask(),
    uAddress(),
    uAddressFromBytes(),
    uMask(),
]
    


