#!/usr/bin/env python
"""
ffpassdecrypt - Decode the passwords stored using Firefox browser. The script currently works only on Linux.

Author : Pradeep Nayak (pradeep1288@gmail.com)
usage: ./ffpassdecrypt.py [paths_to_location_of_files]

Run it with no parameters to extract the standard passwords from all profiles of the current logged in user,
or with an optional '-P' argument (before any path) to query the master password for decryption.

Required files:
   + key3.db
   + signons.sqlite
   + cert8.db
are used and needed to collect the passwords.

"""

import sys
import os

try:
	# try to use the python-nss lib from mozilla
#	import nss
#except ImportError:
	# fall back to dlopen of libnss3.so
	from ctypes import (
		CDLL, Structure,
		c_void_p, c_int, c_uint, c_ubyte, c_char_p,
		byref, cast, string_at,
	)

	#### libnss definitions
	class SECItem(Structure):
		_fields_ = [('type',c_uint),('data',c_void_p),('len',c_uint)]

	class secuPWData(Structure):
		_fields_ = [('source',c_ubyte),('data',c_char_p)]

	(PW_NONE, PW_FROMFILE, PW_PLAINTEXT, PW_EXTERNAL) = (0, 1, 2, 3)
	# SECStatus
	(SECWouldBlock, SECFailure, SECSuccess) = (-2, -1, 0)
	#### end of libnss definitions

	#except ImportError as e:
	#	print 'Failed to find either nss or ctypes library.'
	#	raise
except ImportError: pass

try:
	from sqlite3 import dbapi2 as sqlite
except ImportError:
	from pysqlite2 import dbapi2 as sqlite

import base64
import struct
import glob
import re
import time

import getopt
from getpass import getpass


def findpath_userdirs(profiledir='~/.mozilla/firefox'):
	usersdir = os.path.expanduser(profiledir)
	userdir = os.listdir(usersdir)
	res=[]
	for user in userdir:
		if os.path.isdir(usersdir + os.sep + user):
			res.append(usersdir + os.sep + user)
	return res

def errorlog(row, path, libnss):
	print "----[-]Error while Decoding! writting error.log:"
	print libnss.PORT_GetError()
	try:
		f=open('error.log','a')
		f.write("-------------------\n")
		f.write("#ERROR in: %s at %s\n" %(path,time.ctime()))
		f.write("Site: %s\n"%row[1])
		f.write("Username: %s\n"%row[6])
		f.write("Password: %s\n"%row[7])
		f.write("-------------------\n")
		f.close()
	except IOError:
		print "Error while writing logfile - No log created!"



# reads the signons.sqlite which is a sqlite3 Database (>Firefox 3)
def readsignonDB(directory, dbname, use_pass, libnss):
	profile = os.path.split(directory)[-1]

	if libnss.NSS_Init(directory) != 0:
		print 'Could not initialize NSS for "%s"' % profile

	print "Profile directory: %s" % profile

	keySlot = libnss.PK11_GetInternalKeySlot()
	libnss.PK11_CheckUserPassword(keySlot, getpass() if use_pass else '')
	libnss.PK11_Authenticate(keySlot, True, 0)

	uname = SECItem()
	passwd = SECItem()
	dectext = SECItem()

	pwdata = secuPWData()
	pwdata.source = PW_NONE
	pwdata.data = 0

	signons_db = directory+os.sep+dbname
	conn = sqlite.connect(signons_db)
	c = conn.cursor()
	c.execute("SELECT * FROM moz_logins;")
	for row in c:
		print "--Site(%s):"%row[1]
		uname.data  = cast(c_char_p(base64.b64decode(row[6])),c_void_p)
		uname.len = len(base64.b64decode(row[6]))
		passwd.data = cast(c_char_p(base64.b64decode(row[7])),c_void_p)
		passwd.len=len(base64.b64decode(row[7]))
		if libnss.PK11SDR_Decrypt(byref(uname),byref(dectext),byref(pwdata))==-1:
			errorlog(row, signons_db, libnss)
		print "----Username %s" % string_at(dectext.data,dectext.len)
		if libnss.PK11SDR_Decrypt(byref(passwd),byref(dectext),byref(pwdata))==-1:
			errorlog(row, signons_db, libnss)
		print "----Password %s" % string_at(dectext.data,dectext.len)
	c.close()
	conn.close()
	libnss.NSS_Shutdown()


def main():

	try:
		optlist, args = getopt.getopt(sys.argv[1:], 'P')
	except getopt.GetoptError as err:
		# print help information and exit:
		print str(err) # will print something like "option -a not recognized"
		usage()
		sys.exit(2)


	if len(args)==0:
		ordner = findpath_userdirs()
	else:
		ordner = args

	use_pass = False
	for o, a in optlist:
		if o == '-P':
			use_pass = True

	# dlopen libnss3
	libnss = CDLL("libnss3.so")

	# Set function profiles

	libnss.PK11_GetInternalKeySlot.restype = c_void_p
	libnss.PK11_CheckUserPassword.argtypes = [c_void_p, c_char_p]
	libnss.PK11_Authenticate.argtypes = [c_void_p, c_int, c_void_p]

	for user in ordner:
		signonfiles = glob.glob(user + os.sep + "signons*.*")
		for signonfile in signonfiles:
			(filepath,filename) = os.path.split(signonfile)
			filetype = re.findall('\.(.*)',filename)[0]
			if filetype.lower() == "sqlite":
				readsignonDB(filepath, filename, use_pass, libnss)
			else:
				print 'Unhandled signons file "%s", skipping' % filename

if __name__ == '__main__':
	main()
