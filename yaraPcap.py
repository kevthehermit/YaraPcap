#!/usr/bin/env python
'''
Copyright (C) 2012-2013 Kevin Breen.
YaraMail
Python script to YaraScan HTTP Streams From a PCAP
'''
__description__ = 'Yara HTTP PCAP Scanner, Scans HTTP Streams from a PCAP with YARA'
__author__ = 'Kevin Breen'
__version__ = '0.1'
__date__ = '2013/06/11'

import os
import sys
import tempfile
import shutil
import subprocess
from optparse import OptionParser, OptionGroup
import platform
try:
	import yara
except:
	print "Failed to Import Yara"
	sys.exit()
osType = platform.system()
if osType == "Windows":
	tcpFlowPath = "C:\\Users\\Kevin\\Documents\\Projects\\YaraPcap\\tcpflow64.exe"
	if not os.path.exists(tcpFlowPath):
		print "TCPFlow not found Please Check Path (https://github.com/simsong/tcpflow)"
		sys.exit
if osType == "Linux":
	tcpFlowPath = "/usr/local/bin/tcpflow"
	if not os.path.exists(tcpFlowPath):
		print "TCPFlow Not Found, Please check path or Install (https://github.com/simsong/tcpflow)"
		sys.exit

def main():
	parser = OptionParser(usage='usage: %prog [options] rulefile pcapfile\n' + __description__, version='%prog ' + __version__)
	parser.add_option("-r", "--report", dest="report", help="Write Results To File", metavar="FILE")
	parser.add_option("-s", "--save", action='store_true', default=False, help="DIR To Save Processed Files after Scanning")
	(options, args) = parser.parse_args()
	
	if len(args) != 2:
		parser.print_help()
	if not options.report:
		parser.error("Please Specify Report Location")
		sys.exit()
	if options.save:
		tmpDir = options.save
	elif not options.save:
		tmpDir = tempfile.mkdtemp()
	processPcap().Process(args[0], tmpDir)
	yaraRules = yara.compile(args[1])
	print "Scanning Files With Yara"
	for object in os.listdir(tmpDir):
		yaraScan().scanner(os.path.join(tmpDir, object), yaraRules)
	print "Scanning Complete"
	'''if not options.save:
		print "Removing Temporary Directories"
		shutil.rmtree(tmpDir)'''

class processPcap:
	def Process(self, pcap, tmpDir):
		shutil.copyfile(pcap, os.path.join(tmpDir, "raw.pcap"))
		print "Processing PCAP File For HTTP Streams"
		retcode = subprocess.call("(cd %s && %s -AH -r %s)"%(os.path.join(tmpDir), tcpFlowPath, "raw.pcap"), shell=True)
		return tmpDir

			
class yaraScan:
	def scanner(self, scanfile, yaraRules):
		matches = []
		if os.path.getsize(scanfile) > 0:
			for match in yaraRules.match(scanfile):
				matches.append({"name" : match.rule, "meta" : match.meta})
		return matches
		
class reportMain:
	def __init__(self, report, att, results):
		with open(report, "a") as f:
			f.write("----------\n")
			f.write("From: %s\n" % att["from"])
			f.write("Subject: %s\n" % att["subject"])
			f.write("Att Name: %s\n" % att["msg"])
			f.write("Matched Rules: \n")
			for m in results:
				f.write(m["name"] + "\n")
			f.write("----------\n")
			
if __name__ == "__main__":
	main()