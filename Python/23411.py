#!/bin/bash python3
import base64
import hashlib
import struct

import hcmp


def inner_hash(rounds1, email, password):
  masterkey = hashlib.pbkdf2_hmac("sha256", password, email, rounds1)
  masterpasswordhash = hashlib.pbkdf2_hmac("sha256", masterkey, password, 1)
  return masterpasswordhash


def outer_hash(password, inner_rounds, outer_rounds, email, salt):
  subkey = base64.b64encode(inner_hash(inner_rounds, email, password))
  keyHash = hashlib.pbkdf2_hmac("sha256", subkey, salt, outer_rounds)
  return keyHash

def calc_hash(password: bytes, salt: dict) -> str:
  out_hash = outer_hash(password, salt["salt_iter"], salt["salt_iter2"], salt["esalt"]["inner_salt_buf"], salt["esalt"]["outer_salt_buf"])
  return base64.b64encode(out_hash).decode()

def extract_esalts(esalts_buf):
  esalts=[]
  for inner_salt_buf, inner_salt_len, outer_salt_buf, outer_salt_len, hash_buf in struct.iter_unpack("256s I 256s I 44s", esalts_buf):
    esalts.append({ "inner_salt_buf": inner_salt_buf[:inner_salt_len], "outer_salt_buf": outer_salt_buf[:outer_salt_len]})
  return esalts

def kernel_loop(ctx,passwords,salt_id,is_selftest):
  return hcmp.handle_queue(ctx,passwords,salt_id,is_selftest)

def init(ctx):
  # Uncomment these lines below to dump the hashcat ctx for your salted hash
  # import hcshared
  # hcshared.dump_hashcat_ctx(ctx, source=__name__)
  hcmp.init(ctx,extract_esalts)

def term(ctx):
  hcmp.term(ctx)
