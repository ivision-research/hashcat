#!/bin/bash python3
import base64
import hashlib
import struct
import sys

import hcmp
import hcshared


def inner_hash(rounds1, email, password):
  masterkey = hashlib.pbkdf2_hmac("sha256", password, email, rounds1)
  masterpasswordhash = hashlib.pbkdf2_hmac("sha256", masterkey, password, 1)
  return masterpasswordhash


def outer_hash(password, inner_rounds, outer_rounds, email, salt):
  subkey = base64.b64encode(inner_hash(inner_rounds, email, password))
  keyHash = hashlib.pbkdf2_hmac("sha256", subkey, salt, outer_rounds)
  return keyHash


#ST_HASH = "$bitwarden-server$1*10000*10000*bm9yZXBseUBoYXNoY2F0Lm5ldA==*0ANf7tTj2zwkl3/hf5Zohg==*5ynxBxAsJJ95vgEL/uDVcXseLbyIsHRGFdTXCVvbRlo="
ST_HASH = "5ynxBxAsJJ95vgEL/uDVcXseLbyIsHRGFdTXCVvbRlo=*10000$10000$bm9yZXBseUBoYXNoY2F0Lm5ldA==$0ANf7tTj2zwkl3/hf5Zohg=="
ST_PASS = "hashcat"

# In theory, you only have to re-implement this function...
def calc_hash(password: bytes, salt: dict) -> str:
  inner_rounds, outer_rounds, email, outer_salt = hcshared.get_salt_buf(salt).split(b"$")
  out_hash = outer_hash(password, int(inner_rounds), int(outer_rounds), base64.b64decode(email), base64.b64decode(outer_salt))
  return base64.b64encode(out_hash).decode()

# ...except when using an esalt. The esalt void* structure is both dynamic and specific to a hash mode.
# If you use an esalt, you must convert its contents into Python datatypes.
# If you don't use esalt, just return []
# For this example hash-mode, we kept it very general and pushed all salt data in a generic format of generic sizes
# As such, it has to go into esalt
def extract_esalts(esalts_buf):
  esalts=[]
  for hash_buf, hash_len, salt_buf, salt_len in struct.iter_unpack("1024s I 1024s I", esalts_buf):
    hash_buf = hash_buf[0:hash_len]
    salt_buf = salt_buf[0:salt_len]
    esalts.append({ "hash_buf": hash_buf, "salt_buf": salt_buf })
  return esalts

# From here you really can leave things as they are
# The init function is good for converting the hashcat data type because it is only called once
def kernel_loop(ctx,passwords,salt_id,is_selftest):
  return hcmp.handle_queue(ctx,passwords,salt_id,is_selftest)

def init(ctx):
  # Uncomment this line below to dump the hashcat ctx for your salted hash
  # hcshared.dump_hashcat_ctx(ctx, source=__name__)
  hcmp.init(ctx,extract_esalts)

def term(ctx):
  hcmp.term(ctx)


if __name__ == '__main__':
  # Main is only run when debugging this python script and never when -m 73000 is called directly from hashcat cli

  hcshared.add_hashcat_path_to_environment()
  # Load hashcat ctx from a file dumped when running -m 73000 . Optional argument is a Path() object to ctx file.
  ctx = hcshared.load_ctx(ST_HASH)
  init(ctx)

  hashcat_passwords = 256
  passwords = []
  for line in sys.stdin:
    passwords.append(bytes(line.rstrip(), 'utf-8'))
    if(len(passwords) == hashcat_passwords):
      hashes = kernel_loop(ctx,passwords,0,False)
      passwords.clear()
  hashes = kernel_loop(ctx,passwords,0,False) # remaining entries
  if hashes:
    print(hashes[-1])
  term(ctx)
