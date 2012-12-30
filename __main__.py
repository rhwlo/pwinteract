from __future__ import print_function

from Crypto.Cipher import AES
from Crypto import Random
from argparse import ArgumentParser
from pbkdf2 import PBKDF2

import getpass
import os
import re
import subprocess
import sys
import tempfile

PASSWORD_FILE = '{0}/.passwordpy'.format(os.environ['HOME'])

def pad(data, block_size, interrupt=u'\u0001', padding=u'\u0000'):
  return ''.join([data, interrupt, 
                  padding * (block_size - len(data) % block_size - 1)])

def unpad(data, interrupt=u'\u0001'):
  return data.split(interrupt)[0]

def decrypts(ciphertext, salt=None, iv=None, key=None):
  """
  decrypts takes a ciphertext, and optionally salt, initialization vector, and
  key. If salt or iv are omitted, they're read as the first 24 characters of 
  the string; if key is omitted, it's obtained using the PBKDF2.
  """
  if salt is None:
    salt = ciphertext[:8]
    ciphertext = ciphertext[8:]
  if iv is None:
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
  if key is None:
    key = PBKDF2(getpass.getpass('Password: '), salt).read(32)
  cipher = AES.new(key, AES.MODE_CBC, iv)
  return unpad(cipher.decrypt(ciphertext))

def decryptf(filename):
  """
  decryptf takes a filename and passes its contents to decrypts.
  """
  with open(filename, 'rb') as cipherfile:
    return decrypts(cipherfile.read())

def read_command():
  print(decryptf(PASSWORD_FILE), end='')

def edit_command(initialize=False):
  """
  edit_command takes one argument: initialize (defaulting to False); if not set
  to initialize, it decrypts the password file to a temporary file for editing;
  in either case, it encrypts the tempfile to be the new password file after 
  the user has finished writing.
  """
  file_descriptor, filename = tempfile.mkstemp()
  if not initialize:
    with os.fdopen(file_descriptor, 'wb') as temp_handle:
      temp_handle.write(decryptf(PASSWORD_FILE))
  editor_process = subprocess.Popen([os.environ['EDITOR'], filename])
  editor_process.wait()
  salt = Random.new().read(8)
  iv = Random.new().read(16)
  key = PBKDF2(getpass.getpass('Password (for encryption): '), salt).read(32)
  if PBKDF2(getpass.getpass('Repeat password: '), salt).read(32) != key:
    raise Exception('Encryption passwords do not match.')
  cipher = AES.new(key, AES.MODE_CBC, iv)
  with open(filename, 'rb') as temp_handle:
    ciphertext = ''.join([salt, iv, 
                          cipher.encrypt(pad(temp_handle.read(), 16))])
  with open(PASSWORD_FILE, 'wb') as password_handle:
    password_handle.write(ciphertext)
  shred_proc = subprocess.Popen(['shred', '-u', filename])
  shred_proc.wait()

def append_command():
  """
  append_command takes no arguments; it opens a tempfile for writing the 
  text to append, and then decrypts the password file, appends the appendum,
  and re-encrypts the file. To change the password, you want to use edit.
  """

  # collect the appendum
  file_descriptor, filename = tempfile.mkstemp()
  editor_process = subprocess.Popen([os.environ['EDITOR'], filename])
  editor_process.wait()
  with os.fdopen(file_descriptor, 'rb') as temp_handle:
    appendum = temp_handle.read()

  # collect the ciphertext and decrypt it
  with open(PASSWORD_FILE, 'rb') as password_handle:
    salt = password_handle.read(8)
    iv = password_handle.read(16)
    ciphertext = password_handle.read()
  key = PBKDF2(getpass.getpass('Password: '), salt).read(32)
  cipher = AES.new(key, AES.MODE_CBC, iv)
  plaintext = ''.join([unpad(cipher.decrypt(ciphertext)), appendum])

  # create a new cipher for encryption and then write the full plaintext out
  # (should this be done with entirely new password+salt+iv? Or the old one?)
  salt = Random.new().read(8)
  iv = Random.new().read(16)
  key = PBKDF2(getpass.getpass('Password (for encryption): '), salt).read(32)
  if PBKDF2(getpass.getpass('Repeat password: '), salt).read(32) != key:
    raise Exception('Encryption passwords do not match.')
  cipher = AES.new(key, AES.MODE_CBC, iv)
  with open(PASSWORD_FILE, 'wb') as password_handle:
    password_handle.write(''.join([salt, iv, cipher.encrypt(pad(plaintext,
                                                                16))]))

  # clean up after yourself.
  shred_proc = subprocess.Popen(['shred', '-u', filename])
  shred_proc.wait()

def _main():
  # TODO:
  # - create a 'search' subcommand to search for a key
  # - more configuration: change password file(?)
  # - allow a (removable) first-line template for the 'append' tempfiles, so
  #   that passwords all line up nicely.
  subcommand_functions = { 
    'edit': edit_command, 
    'read': read_command,
    'initialize': (lambda: edit_command(initialize=True)),
    'append': append_command }
  parser = ArgumentParser(description='Interact with a password file')
  subcommands = parser.add_subparsers(dest='subcommand')
  subcommands.add_parser('initialize')
  subcommands.add_parser('edit')
  subcommands.add_parser('read')
  subcommands.add_parser('append')
  args = parser.parse_args()
  subcommand_functions[args.subcommand]()

if __name__ == '__main__':
  _main()
