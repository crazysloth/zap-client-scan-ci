#!/usr/bin/python
import time
from pprint import pprint
from zapv2 import ZAPv2
import argparse
import re

HIGH = 'High'
MED = 'Medium'
LOW = 'Low'
RANKING = {HIGH: 2, MED: 1, LOW: 0}

parser = argparse.ArgumentParser(description='Zap security scanner')
parser.add_argument("target", type=str, help="Target to scan")
parser.add_argument("-H", "--high", help="Filter to show alerts with a high risk level", action='store_true')
parser.add_argument("-M", "--medium", help="Filter to show alerts with a medium risk level", action='store_true')
parser.add_argument("-L", "--low", help="Filter to show alerts with a low risk level", action='store_true')
args = parser.parse_args()

url = args.target
if not re.match("^http(s|)://", url):
    url = 'http://'+ url
    
target = url
zap = ZAPv2() # Default client localhost port 8080
#zap = ZAPv2(proxies={'http': 'http://10.10.25.208:8090', 'https': 'http://10.10.25.208:8090'})

print 'Accessing target %s' % target
# try have a unique enough session...
zap.urlopen(target)
# Give the sites tree a chance to get updated
time.sleep(2)

print 'Spidering target %s' % target
scanid = zap.spider.scan(target)
# Give the Spider a chance to start
time.sleep(2)
while (int(zap.spider.status(scanid)) < 100):
    print 'Spider progress %: ' + zap.spider.status(scanid)
    time.sleep(2)

print 'Spider completed'
# Give the passive scanner a chance to finish
time.sleep(5)

print 'Scanning target %s' % target
scanid = zap.ascan.scan(target)
while (int(zap.ascan.status(scanid)) < 100):
    print 'Scan progress %: ' + zap.ascan.status(scanid)
    time.sleep(5)

print 'Scan completed'

# Report the results
warningFilter = list()

if args.high:
    warningFilter.append(HIGH)

if args.medium:
    warningFilter.append(MED)

if args.low:
    warningFilter.append(LOW)

results = zap.core.alerts()

if len(warningFilter) > 0:
    results = filter(lambda res: res['risk'] in warningFilter, results)  

results.sort(key=lambda res: RANKING[res['risk']], reverse=True)

for res in results:
    print ''
    print 'Id: %s' % res['id']
    print 'Url: %s' % res['url']
    print 'Risk: %s' % res['risk']   
    print 'Confidence: %s' % (res['confidence'] if res['confidence'] else 'N/A')
    print 'Name: %s' % res['name']
    print 'Solution: %s' % res['solution']
    print 'More information at %s' % res['reference']
    print ''
    print '---'

print '' 
print 'Scan Id: %s' % scanid
print 'Results: %s' % len(results)



    


