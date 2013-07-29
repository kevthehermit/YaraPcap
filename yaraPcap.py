#!/usr/bin/env python
'''
Copyright (C) 2013 Kevin Breen.
YaraPCAP
Yara HTTP PCAP Scanner, Scans HTTP Streams from a PCAP with YARA
'''
__description__ = 'Yara HTTP PCAP Scanner, Scans HTTP Streams from a PCAP with YARA'
__author__ = 'Kevin Breen'
__version__ = '0.1'
__date__ = '2013/07/29'

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


# SET THE PATH FOR TCPFLOW
if osType == "Windows":
	tcpFlowPath = "C:\\Users\\Kevin\\Documents\\Projects\\YaraPcap\\tcpflow64.exe"
	if not os.path.exists(tcpFlowPath):
		print "TCPFlow not found Please Check Path or Install (https://github.com/simsong/tcpflow)"
		sys.exit()
if osType == "Linux":
	tcpFlowPath = "/usr/local/bin/tcpflow"
	if not os.path.exists(tcpFlowPath):
		print "TCPFlow Not Found, Please check path or Install (https://github.com/simsong/tcpflow)"
		sys.exit()
# End

def main():
	parser = OptionParser(usage='usage: %prog [options] rulefile pcapfile\n' + __description__, version='%prog ' + __version__)
	parser.add_option("-r", "--report", dest="report", help="Report File", default="report.txt", metavar="FILE")
	parser.add_option("-s", "--save", dest='saveDir', help="DIR To Save Matching Files")
	(options, args) = parser.parse_args()
	
	if len(args) != 2:
		parser.print_help()
		sys.exit()
	if options.saveDir:
		reportFile = os.path.join(options.saveDir, "report.txt")
	else:
		reportFile = options.report
	tmpDir = tempfile.mkdtemp()
	processPcap().Process(args[1], tmpDir)
	yaraRules = yara.compile(args[0])
	print "Scanning Files With Yara"
	for httpReq in os.listdir(tmpDir):
		results = yaraScan().scanner(os.path.join(tmpDir, httpReq), yaraRules)
		if results and options.saveDir:
			if not os.path.exists(options.saveDir):
				os.mkdir(options.saveDir)
			shutil.copyfile(os.path.join(tmpDir, httpReq), os.path.join(options.saveDir, httpReq))
		if results:
			print "   Match Found ", httpReq
			reportMain(reportFile, httpReq, results)
	print "Scanning Complete"
	print "Report Written to ", reportFile
	if options.saveDir:
		print "Matching Files Written to ", options.saveDir
	print "Removing Temporary Directories"
	shutil.rmtree(tmpDir)		

class processPcap:
	def Process(self, pcap, tmpDir):
		print pcap
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
	def __init__(self, report, fileName, results):
		with open(report, "a") as f:
			f.write("----------\n")
			f.write("File: %s\n" % fileName)
			f.write("Matched Rules: \n")
			for m in results:
				f.write(m["name"] + "\n")
			f.write("----------\n")
			
if __name__ == "__main__":
	main()