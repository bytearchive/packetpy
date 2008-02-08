#    Copyright (c) 2003-2008 Nullcube Pty Ltd 
#    All rights reserved.
#
#    Redistribution and use in source and binary forms, with or without
#    modification, are permitted provided that the following conditions are met:
#
#    *   Redistributions of source code must retain the above copyright notice, this
#        list of conditions and the following disclaimer.
#    *   Redistributions in binary form must reproduce the above copyright notice,
#        this list of conditions and the following disclaimer in the documentation
#        and/or other materials provided with the distribution.
#    *   Neither the name of Nullcube nor the names of its contributors may be used to
#        endorse or promote products derived from this software without specific
#        prior written permission.
#
#    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
#    ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
#    WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#    DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
#    ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
#    (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
#    LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
#    ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
#    SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

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


