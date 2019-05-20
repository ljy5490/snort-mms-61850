# snort-mms
example Snort Plugin for iec61850 mms decoding
## Getting Started
### Test Platform:
Ubuntu 18.10
### Installing:
1. Install Snort3.0 and Snort_extra\
Reference: https://www.snort.org/documents/snort-3-on-ubuntu-14-16-17-18
2. Copy all files and folders into snort3_extra/src/inspectors/
3. Compile and install Snort_extra again
4. Update Snort config file snort.lua:\
Add ```iec61850 = {}``` in section 3.\
Add ```{ when = { proto = 'tcp', ports = '102' }, use = { type = 'iec61850' } }``` in section 4.

### Running:
```
snort --plugin-path /usr/local/lib/snort_extra/ -c /usr/local/etc/snort/snort.lua -R rules.txt -r iec61850.pcap -A cmg
```
note:
1. ```/usr/local/lib/snort_extra/``` is the location of installed plugin, you may have a different location
2. ```iec61850.pcap``` is example pcap file, you can find it in pcap folder
3. ```rules.txt``` is example rule file for this plugin, you can find it in rule folder
