yaraPCAP
========

Yara Scanner For IMAP Feeds and saved Streams

###What it does:
- Reads a PCAP File and Extracts Http Streams. 
- gzip deflates any compressed streams
- Scans every file with yara
- writes a report.txt
- optionally saves matching files to a Dir


###Usage
- Simple report
 "python yaraPcap.py -r sampleReport.txt sample.yar sample.pcap"
- Save Matching Files
 "python yaraPcap.py -s SampleDir sample.yar sample.pcap"

###Requirements
- Python
- Yara / PyYara
- TCPFlow 1.3 - https://github.com/simsong/tcpflow
- For windows edit the Script to point to your copy of the tcpflow binary. Line 29

###ToDo
- Save Report as XML
- Add More Detail to the Report




