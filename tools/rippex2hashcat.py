#!/usr/bin/env python3

# Author:  philsmd
# Date:    April 2021
# License: public domain, credits go to philsmd and hashcat

import os
import sys
import base64

try:
  import json
  assert json
except ImportError:
  try:
    sys.path.append (".")

    import simplejson as json
  except ImportError:
    sys.stderr.write ("Please install json / simplejson module which is currently not installed.\n")
    sys.exit (-1)

def process_file (path):
  file_name = os.path.basename (path)

  try:
    f = open (path, "rb")
    wallet = f.read ()
  except IOError:
      e = sys.exc_info ()[1]
      sys.stderr.write ("%s\n" % str (e))
      return

  data = base64.b64decode (wallet)

  try:
    json_data = json.loads (data)
  except:
    sys.stderr.write ("%s: Unable to parse the wallet file!\n" % file_name)
    sys.exit (-1)

  iv = json_data.get ("iv")

  if iv == None:
    sys.stderr.write ("%s: No IV found within the wallet!\n" % file_name)
    sys.exit (-1)

  if len (base64. b64decode (iv)) != 16:
    sys.stderr.write ("%s: IV must be 16 bytes!\n" % file_name)
    sys.exit (-1)

  iterations = json_data.get ("iter")

  if iterations == None:
    sys.stderr.write ("%s: No iter found within the wallet!\n" % file_name)
    sys.exit (-1)

  iterations = int (iterations)

  if iterations < 1 or iterations > 999999:
    sys.stderr.write ("%s: Invalid iteration count in wallet!\n" % file_name)
    sys.exit (-1)

  key_size = json_data.get ("ks")

  if key_size == None:
    sys.stderr.write ("%s: No key size found within the wallet!\n" % file_name)
    sys.exit (-1)

  key_size = int (key_size)

  if key_size != 256:
    sys.stderr.write ("%s: Invalid key size in wallet!\n" % file_name)
    sys.exit (-1)

  tag_size = json_data.get ("ts")

  if tag_size == None:
    sys.stderr.write ("%s: No tag size found within the wallet!\n" % file_name)
    sys.exit (-1)

  tag_size = int (tag_size)

  if tag_size != 64:
    sys.stderr.write ("%s: Invalid tag size in wallet!\n" % file_name)
    sys.exit (-1)

  aes_mode = json_data.get ("mode")

  if aes_mode == None:
    sys.stderr.write ("%s: No AES mode found within the wallet!\n" % file_name)
    sys.exit (-1)

  if aes_mode != "ccm":
    sys.stderr.write ("%s: Invalid AES mode in wallet!\n" % file_name)
    sys.exit (-1)

  adata = json_data.get ("adata")

  if adata == None:
    sys.stderr.write ("%s: No adata found within the wallet!\n" % file_name)
    sys.exit (-1)

  if adata != "":
    sys.stderr.write ("%s: Non empty adata in wallet!\n" % file_name)
    sys.exit (-1)

  cipher = json_data.get ("cipher")

  if cipher == None:
    sys.stderr.write ("%s: No cipher found within the wallet!\n" % file_name)
    sys.exit (-1)

  if cipher != "aes":
    sys.stderr.write ("%s: Invalid cipher in wallet!\n" % file_name)
    sys.exit (-1)

  salt = json_data.get ("salt")

  if salt == None:
    sys.stderr.write ("%s: No salt found within the wallet!\n" % file_name)
    sys.exit (-1)

  if len (base64.b64decode (salt)) != 8:
    sys.stderr.write ("%s: Invalid salt length in wallet!\n" % file_name)
    sys.exit (-1)

  ct = json_data.get ("ct")

  if ct == None:
    sys.stderr.write ("%s: No ciphertext found within the wallet!\n" % file_name)
    sys.exit (-1)

  ct_len = len (ct)

  if ct_len < 128 or ct_len > 512:
    sys.stderr.write ("%s: Invalid ciphertext length in wallet!\n" % file_name)
    sys.exit (-1)

  print ("$rippex$*%i*%s*%s*%s" % (iterations, salt, iv, ct))

if __name__ == "__main__":
  if len (sys.argv) < 2:
    sys.stderr.write ("Usage: %s [Rippex Wallet files]\n" % sys.argv[0])
    sys.exit (-1)

  for i in range (1, len (sys.argv)):
    process_file (sys.argv[i])
