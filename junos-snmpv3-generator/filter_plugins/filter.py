#!/usr/bin/python
"""
Kaon Thana 8-24-2022

Filter file to generate junos compatible snmpv3 key plus encode it as a $9$ key for configuration

Source #1 for the snmpv3 hashgen:
https://github.com/TheMysteriousX/SNMPv3-Hash-Generator/blob/master/snmpv3_hashgen/hashgen.py

Source #2 for the junos $9$ key encryption
https://github.com/peering-manager/peering-manager/blob/main/devices/crypto/juniper.py

https://metacpan.org/pod/Crypt::Juniper
"""


import hashlib
import string
import secrets

from itertools import repeat
from functools import partial

P_LEN = 32
E_LEN = 16

import random



MAGIC = "$9$"

FAMILY = [
    "QzF3n6/9CAtpu0O",
    "B1IREhcSyrleKvMW8LXx",
    "7N-dVbwsY2g4oaJZGUDj",
    "iHkq.mPf5T",
]
EXTRA = {}
for counter, value in enumerate(FAMILY):
    for character in value:
        EXTRA[character] = 3 - counter

NUM_ALPHA = [x for x in "".join(FAMILY)]
ALPHA_NUM = {NUM_ALPHA[x]: x for x in range(0, len(NUM_ALPHA))}

ENCODING = [
    [1, 4, 32],
    [1, 16, 32],
    [1, 8, 32],
    [1, 64],
    [1, 32],
    [1, 4, 16, 128],
    [1, 32, 64],
]

class FilterModule:
    """
    Defines a filter module object.
    """

    @staticmethod
    def filters():
        """
        Return a list of hashes where the key is the filter
        name exposed to playbooks and the value is the function.
        """
        return {
            'gen_snmp_9key': FilterModule.gen_snmp_9key
        }
    @staticmethod
    def gen_snmp_9key(engine_id, snmp_pass):
        """
        Takes two inputs (engine_id and snmp password).
        Hashes the password and engine id together to create a localized key.
        Then encodes the key with the juniper $9$ algorithm to be used in junos configuration
        """

        hash = Hashgen.algs["sha1"]

        Kul_auth = Hashgen.derive_msg(snmp_pass, engine_id, hash)
        Kul_priv = Hashgen.derive_msg(snmp_pass, engine_id, hash)

        localized_key = hash(Kul_auth)

        snmp_9key = encrypt(localized_key)

        return snmp_9key

class Hashgen(object):
    @staticmethod
    def hash(bytes, alg=hashlib.sha1, name=None, raw=False):
        digest = alg(bytes).digest()
        return digest if raw else digest.hex()

    @staticmethod
    def expand(substr, target_len):
        reps = target_len // len(substr) + 1  # approximation; worst case: overrun = l + len(s)
        return "".join(list(repeat(substr, reps)))[:target_len]

    @staticmethod
    def kdf(password, alg=None):
        alg = Hashgen.algs["sha1"] if alg is None else alg

        data = Hashgen.expand(password, 1048576).encode("utf-8")
        return alg(data, raw=True)

    @staticmethod
    def random_string(len=P_LEN, alphabet=(string.ascii_letters + string.digits)):
        return "".join(secrets.choice(alphabet) for _ in range(len))

    @staticmethod
    def random_engine(len=E_LEN):
        return secrets.token_hex(len)

    @staticmethod
    def derive_msg(passphrase, engine, alg):
        # Parameter derivation á la rfc3414
        Ku = Hashgen.kdf(passphrase, alg)
        E = bytearray.fromhex(engine)

        return b"".join([Ku, E, Ku])


# Define available hash algorithms
Hashgen.algs = {
    "md5":    partial(Hashgen.hash, alg=hashlib.md5,    name='md5'),
    "sha1":   partial(Hashgen.hash, alg=hashlib.sha1,   name='sha1'),
    "sha224": partial(Hashgen.hash, alg=hashlib.sha224, name='sha224'),
    "sha256": partial(Hashgen.hash, alg=hashlib.sha256, name='sha256'),
    "sha384": partial(Hashgen.hash, alg=hashlib.sha384, name='sha384'),
    "sha512": partial(Hashgen.hash, alg=hashlib.sha512, name='sha512'),
}


def __nibble(cref, length):
    nib = cref[0:length]
    rest = cref[length:]

    if len(nib) != length:
        raise Exception(f"Ran out of characters: hit '{nib}', expecting {length} chars")

    return nib, rest


def __gap(c1, c2):
    return (ALPHA_NUM[str(c2)] - ALPHA_NUM[str(c1)]) % (len(NUM_ALPHA)) - 1


def __gap_decode(gaps, dec):
    num = 0

    if len(gaps) != len(dec):
        raise Exception("Nibble and decode size not the same.")

    for x in range(0, len(gaps)):
        num += gaps[x] * dec[x]

    return chr(num % 256)


def __reverse(current):
    reversed = list(current)
    reversed.reverse()
    return reversed


def __gap_encode(pc, prev, encode):
    __ord = ord(pc)

    crypt = ""
    gaps = []
    for mod in __reverse(encode):
        gaps.insert(0, int(__ord / mod))
        __ord %= mod

    for gap in gaps:
        gap += ALPHA_NUM[prev] + 1
        prev = NUM_ALPHA[gap % len(NUM_ALPHA)]
        crypt += prev

    return crypt


def __randc(counter=0):
    return_value = ""
    for _ in range(counter):
        return_value += NUM_ALPHA[random.randrange(len(NUM_ALPHA))]
    return return_value


def is_encrypted(value):
    return value.startswith(MAGIC)


def decrypt(value):
    if not value:
        return ""

    if not is_encrypted(value):
        return value

    chars = value.split("$9$", 1)[1]
    first, chars = __nibble(chars, 1)
    toss, chars = __nibble(chars, EXTRA[first])
    previous = first
    decrypted = ""

    while chars:
        decode = ENCODING[len(decrypted) % len(ENCODING)]
        nibble, chars = __nibble(chars, len(decode))
        gaps = []
        for i in nibble:
            g = __gap(previous, i)
            previous = i
            gaps += [g]
        decrypted += __gap_decode(gaps, decode)

    return decrypted


def encrypt(value, salt=None):
    if not value:
        return ""

    if is_encrypted(value):
        return value

    # if not salt:
    #     salt = __randc(1)
    # rand = __randc(EXTRA[salt])

    salt = '7'
    rand = '7'

    position = 0
    previous = salt
    crypted = MAGIC + salt + rand

    for x in value:
        encode = ENCODING[position % len(ENCODING)]
        crypted += __gap_encode(x, previous, encode)
        previous = crypted[-1]
        position += 1

    return crypted
