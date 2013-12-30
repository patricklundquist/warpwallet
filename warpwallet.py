#!/usr/bin/env python
#
# Author: patricklundquist@gmail.com
#
# Description: Implements the WarpWallet algorithm as descibed below:
#
# s1 = scrypt(key=(passphrase||0x1), salt=(salt||0x1), N=2^18, r=8, p=1, dkLen=32)
# s2 = pbkdf2(key=(passphrase||0x2), salt=(salt||0x2), c=2^16, dkLen=32, prf=HMAC_SHA256)
# keypair = generate_bitcoin_keypair(s1 xor s2)
#

import argparse
import binascii
import json
import scrypt
import sys
from passlib.utils import pbkdf2
from pycoin import ecdsa, encoding
from pycoin.ecdsa import secp256k1

class WarpWallet(object):

  def __init__(self, pbkdf2_count, derived_key_len, scrypt_power, scrypt_p,
               scrypt_r):
    self.dklen = derived_key_len
    self.pbkdf2_count = pbkdf2_count
    self.scrypt_power = scrypt_power
    self.scrypt_r = scrypt_r
    self.scrypt_p = scrypt_p

  def warp(self, passphrase, salt=""):
    """
    Return dictionary of WarpWallet public and private keys corresponding to
    the given passphrase and salt.
    """
    s1 = binascii.hexlify(self._scrypt(passphrase, salt))
    out = self._pbkdf2(passphrase, salt)
    s2 = binascii.hexlify(out)
    base = binascii.unhexlify(s1)
    s3 = binascii.hexlify(self._sxor(base,out))
    secret_exponent = int(s3, 16)
    public_pair = ecdsa.public_pair_for_secret_exponent(secp256k1.generator_secp256k1, secret_exponent)
    private_key = encoding.secret_exponent_to_wif(secret_exponent, compressed=False)
    public_key = encoding.public_pair_to_bitcoin_address(public_pair, compressed=False)
    out = { "keys" : { "private_key" : private_key,
                       "public_key" : public_key },
            "seeds" : [s1, s2, s3],
            "passphrase" : passphrase,
            "salt" : salt }
    return out

  def _scrypt(self, passphrase, salt=""):
    scrypt_key = passphrase + "\x01"
    scrypt_salt = salt + "\x01"
    out = scrypt.hash(scrypt_key, scrypt_salt, N=2**self.scrypt_power,
                      r=self.scrypt_r, p=self.scrypt_p, buflen=self.dklen)
    return out

  def _pbkdf2(self, passphrase, salt=""):
    hexlified_key = binascii.hexlify(passphrase) + "02"
    pbkdf2_key = binascii.unhexlify(hexlified_key)
    hexlified_salt = binascii.hexlify(salt) + "02"
    pbkdf2_salt = binascii.unhexlify(hexlified_salt)
    out = pbkdf2.pbkdf2(secret=pbkdf2_key, salt=pbkdf2_salt, keylen=self.dklen,
                        rounds=self.pbkdf2_count, prf='hmac_sha256')
    return out

  def _sxor (self, s1, s2):
    # Convert strings to a list of character pair tuples,
    # go through each tuple, converting them to ASCII code (ord),
    # perform exclusive or on the ASCII code,
    # then convert the result back to ASCII (chr),
    # merge the resulting array of characters as a string.
    return ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(s1,s2))

def parse_args():
  parser = argparse.ArgumentParser()
  parser.add_argument("-c", "--pbkdf2_count",
                      help="iteration count",
                      type=int,
                      default=2**16)
  parser.add_argument("-d", "--dklen",
                      help="derived key length",
                      type=int,
                      default=32)
  parser.add_argument("-n", "--scrypt_power",
                      help="2^n passed as the 'N' param to scrypt",
                      type=int,
                      default=18)
  parser.add_argument("-p", "--scrypt_p",
                      help="'p' param to scrypt",
                      type=int,
                      default=1)
  parser.add_argument("-r", "--scrypt_r",
                      help="'r' param to scrypt",
                      type=int,
                      default=8)
  parser.add_argument("-P", "--passphrase" ,
                      help="passphrase",
                      type=str)
  parser.add_argument("-S", "--salt" ,
                      help="salt",
                      type=str)
  args = parser.parse_args()

  if not args.passphrase:
    print "Must provide passphrase (-P)"
    sys.exit(1)
  if not args.salt:
    print "Must provide salt (-S)"
    sys.exit(1)

  return args

if __name__ == "__main__":
  args = parse_args()
  wallet = WarpWallet(args.pbkdf2_count, args.dklen, args.scrypt_power,
                      args.scrypt_p, args.scrypt_r)
  print json.dumps(wallet.warp(args.passphrase, args.salt), indent=4,
                   sort_keys=True)
