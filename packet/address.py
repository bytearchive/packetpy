# Copyright (c) 2003-2008, Nullcube Pty Ltd
# All rights reserved.
# 
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import utils

def getBlocks(addr):
    """
        Get the 16-bit hexadecimal blocks from a ":"-delimited address definition.
        Applicable to Ethernet and IPv6 addresses.
    """
    numstrs = addr.split(":")
    nums = []
    for i in numstrs:
        if not i:
            continue
        try:
            num = int(i, 16)
        except ValueError:
            raise ValueError, "Malformed address."
        if num > 0xffff:
            raise ValueError, "Malformed address."
        nums.append(num)
    return nums
            

class _MaskMixin(object):
    _prefTable = {
        0:   0,
        128: 1,
        192: 2,
        224: 3,
        240: 4,
        248: 5,
        252: 6,
        254: 7
    }
    def _countPrefix(self, bytes):
        num = 0
        itr = iter(bytes)
        for b in itr:
            if b == "\xff":
                num += 8
            else:
                break
        else:
            return num
        try:
            num += self._prefTable[ord(b)]
        except KeyError:
            raise ValueError, "Invalid mask."
        for b in itr:
            if not b == "\x00":
                raise ValueError, "Invalid mask."
        return num


class _AddrBase(object):
    def __eq__(self, other):
        if not isinstance(other, _AddrBase):
            other = Address(other)
        return (self.bytes == other.bytes)

    @property
    def integer(self):
        return utils.multiord(self.bytes)

    @classmethod
    def fromInteger(klass, i):
        bytes = utils.multichar(i, klass.WIDTH)
        return klass.fromBytes(bytes)


class EthernetAddress(_AddrBase):
    def __init__(self, address):
        self.address = address
        self.bytes = self._bytes()

    @staticmethod
    def fromBytes(addr):
        if len(addr) != 6:
            raise ValueError, "Ethernet address must have 6 bytes."
        octets = []
        for i in addr:
            next = "%x"%ord(i)
            if len(next) == 1:
                next = "0"+next
            octets.append(next)
        return EthernetAddress(":".join(octets))

    def _bytes(self):
        nums = getBlocks(self.address)
        if len(nums) != 6:
            raise ValueError, "Malformed Ethernet address."
        return "".join([chr(i) for i in nums])

    def __repr__(self):
        return self.address


class _IPBase(_AddrBase):
    WIDTH = 4
    def inNetwork(self, address, mask):
        """
            Is this address in the given network?
        """
        for i in zip(self.bytes, address.bytes, mask.bytes):
            s, a, m = ord(i[0]), ord(i[1]), ord(i[2])
            if not (a&m) == (s&m):
                return False
        return True

    def __repr__(self):
        return self.address


class IPAddress(_IPBase):
    def __init__(self, address):
        self.address = address
        self.bytes = self._bytes()

    @classmethod
    def fromBytes(klass, bytes):
        """
            Converts a sequence of 4 bytes to an IPv4 address.
        """
        if len(bytes) != klass.WIDTH:
            raise ValueError, "IP Address must have %s bytes."%klass.WIDTH
        octets = []
        for i in bytes:
            val = ord(i)
            octets.append(str(val))
        addr = ".".join(octets)
        return IPAddress(addr)

    def _bytes(self):
        nums = self.address.split(".")
        if len(nums) != self.WIDTH:
            raise ValueError, "Mal-formed IP address."
        ret = []
        for i in nums:
            num = int(i)
            if num > 255 or num < 0:
                raise ValueError, "Mal-formed IP address."
            ret.append(chr(num))
        return "".join(ret)

    def mask(self, *args, **kwargs):
        """
            Instantiate a mask object of the appropriate type.
        """
        return IPMask(*args, **kwargs)


class IPMask(IPAddress, _MaskMixin):
    def __init__(self, mask):
        if mask is None:
            mask = 32
        if utils.isNumberLike(mask):
            mask = self._ipFromPrefix(mask)
        IPAddress.__init__(self, mask)
        self.prefix = self._countPrefix(self.bytes)

    def _bytesFromIPPrefix(self, prefix):
        """
            Produce a binary IPv4 address (netmask) from a prefix length.
        """
        if (prefix > 32) or (prefix < 0):
            raise ValueError, "Prefix must be between 0 and 32."
        addr = "\xff" * (prefix/8)
        if prefix%8:
            addr += chr((255 << (8-(prefix%8)))&255)
        addr += "\0"*(4 - len(addr))
        return addr

    def _ipFromPrefix(self, prefix):
        """
            Produce an IPv4 address (netmask) from a prefix length.
        """
        return IPMask.fromBytes(self._bytesFromIPPrefix(prefix)).address


class IP6Address(_IPBase):
    WIDTH = 16
    def __init__(self, address):
        self.address = address
        # Conformance check: raises on error.
        self.bytes = self._bytes()

    @classmethod
    def fromBytes(klass, addr):
        """
            Converts a standard 16-byte IPv6 address to a human-readable string.
        """
        if len(addr) != klass.WIDTH:
            raise ValueError, "IPv6 address must have %s bytes: %s"%(klass.WIDTH, repr(addr))
        octets = []
        for i in range(8):
            octets.append(hex(utils.multiord(addr[2*i:2*i+2]))[2:])
        start, finish = utils.findLongestSubsequence(octets, "0")
        if finish:
            return IP6Address(
                ":".join(octets[0:start]) + "::" + ":".join(octets[finish+1:])
            )
        else:
            return IP6Address(":".join(octets))

    def _bytes(self):
        """
            Converts a standard IPv6 address to 16 bytes.
        """
        abbr = self.address.count("::")
        if self.address.find("::") > -1:
            if (self.address.count("::") > 1):
                s = "Mal-formed IPv6 address: only one :: abbreviation allowed."
                raise ValueError(s)
            first, second = self.address.split("::")
            first = getBlocks(first)
            second = getBlocks(second)
            padlen = 8 - len(first) - len(second)
            nums = first + [0]*padlen + second
        else:
            nums = getBlocks(self.address)
        if len(nums) != 8:
            raise ValueError, "Mal-formed IPv6 address."
        return "".join([utils.multichar(i, 2) for i in nums])

    def mask(self, *args, **kwargs):
        """
            Instantiate a mask object of the appropriate type.
        """
        return IP6Mask(*args, **kwargs)


class IP6Mask(IP6Address, _MaskMixin):
    def __init__(self, mask):
        if mask is None:
            mask = 128
        if utils.isNumberLike(mask):
            mask = self._ip6FromPrefix(mask)
        IP6Address.__init__(self, mask)
        self.prefix = self._countPrefix(self.bytes)

    def _bytesFromIP6Prefix(self, prefix):
        """
            Produce a binary IPv6 address (netmask) from a prefix length.
        """
        if (prefix > 128) or (prefix < 0):
            raise ValueError, "Prefix must be between 0 and 128."
        addr = "\xff" * (prefix/8)
        if prefix%8:
            addr += chr((255 << (8-(prefix%8)))&255)
        addr += "\0"*(16 - len(addr))
        return addr

    def _ip6FromPrefix(self, prefix):
        """
            Produce an IPv6 address (netmask) from a prefix length.
        """
        return IP6Mask.fromBytes(self._bytesFromIP6Prefix(prefix)).address


def Address(address):
    """
        Create an address, and auto-detecting the type.
    """
    if isinstance(address, _AddrBase):
        return address
    try:
        return IPAddress(address)
    except ValueError:
        pass
    try:
        return IP6Address(address)
    except ValueError:
        pass
    try:
        return EthernetAddress(address)
    except ValueError:
        pass
    raise ValueError, "Not a valid address."


def AddressFromBytes(bytes):
    if len(bytes) == 4:
        return IPAddress.fromBytes(bytes)
    elif len(bytes) == 6:
        return EthernetAddress.fromBytes(bytes)
    elif len(bytes) == 16:
        return IP6Address.fromBytes(bytes)
    else:
        raise ValueError, "Not a valid address."


def Mask(address):
    """
        Create a nework mask object, and auto-detecting the type.
    """
    try:
        return IPMask(address)
    except ValueError:
        pass
    try:
        return IP6Mask(address)
    except ValueError:
        pass
    raise ValueError, "Not a valid mask."
