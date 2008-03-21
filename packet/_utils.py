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

def multiord(x):
    """
        Like ord(), but takes multiple characters. I.e. calculate the
        base10 equivalent of a string considered as a set of base-256 digits.
    """
    num = 0
    scale = 1
    for i in range(len(x)-1, -1, -1):
        num = num + (ord(x[i])*scale)
        scale = scale*256
    return num


def multichar(a, width):
    """
        Like chr(), but takes a large integer that could fill many bytes,
        and returns a string. I.e. calculate the base256 equivalent string,
        from a given base10 integer.

        The return string will be padded to the left to ensure that it is of
        length "width".
    """
    a = int(a)
    chars = []
    while (a != 0):
        chars.insert(0, chr(a%256))
        a = a/256
    if len(chars) > width:
        raise ValueError, "Number too wide for width."
    ret = ["\0"]*(width-len(chars)) + chars
    return "".join(ret)


def cksum16(data):
    """
        Calculates the 16-bit CRC checksum accross data.
    """
    sum = 0
    try:
        for i in range(0, len(data), 2):
            a = ord(data[i])
            b = ord(data[i+1])
            sum = sum + ((a<<8) + b)
    except IndexError:
        sum = sum + (a<<8)
    while (sum >> 16):
        sum = (sum & 0xFFFF) + (sum >> 16)
    return (~sum & 0xFFFF)


def isStringLike(anobj):
    try:
        anobj + ''
    except:
        return 0
    else:
        return 1


def isNumberLike(s):
    try:
        s+0
    except:
        return False
    else:
        return True


def findLongestSubsequence(seq, value):
    """
        Find the longest subsequence consisting only of "value".
    """
    itr = iter(range(len(seq)))
    maxseq = (0, 0)
    for i in itr:
        if seq[i] == value:
            start = i
            for j in itr:
                if not seq[j] == value:
                    j -= 1
                    break
            if (j-start) > (maxseq[1]-maxseq[0]):
                maxseq = (start, j)
    return maxseq


class DoubleAssociation(dict):
    """
        A double-association is a broadminded dictionary - it goes both ways.
            
        DoubleAssociation requires the keys and values to be two disjoint sets.
        That is, if a given value is both a key and a value in a
        DoubleAssociation, you get unexpected behaviour.
    """
    # FIXME:
    #   While DoubleAssociation is adequate for our use, it is not entirely complete:
    #       - Deletion should delete both associations
    #       - Other dict methods that set values (eg. setdefault) will need to be over-ridden.
    def __init__(self, idict=None):
        if idict:
            for k, v in idict.items():
                self[k] = v

    def __setitem__(self, key, value):
        dict.__setitem__(self, key, value)
        dict.__setitem__(self, value, key)


def i2b(n):
     """ Convert an integer to its binary text representation """
     if n <= 0:
         if n < 0:
             return '-' + i2b(-n)
         return '0'
     octaldigits = '000','001','010','011','100','101','110','111'
     octaltext = oct(n).rstrip('L')
     a = [octaldigits[int(digit)] for digit in octaltext]
     return ''.join(a).lstrip('0')
