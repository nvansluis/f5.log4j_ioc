# f5.log4j_ioc
iRule that helps to mitigate the Log4j vulnerability with use of public available IOCs. Currently the following IOCs can be used:

| Note | Links |
|------|-------|
| cert-agid.gov.it (Contains scan IP's) | https://cert-agid.gov.it/download/log4shell-iocs.txt |
| NLD Police | https://thanksforallthefish.nl/log4j_blocklist.txt (line-by-line) Not Verified |

The plan is to add some more IOCs soon.

## How to use this snippet
### Prepare F5 BIG-IP
* Create LX Workspace: log4j_ioc
* Add iRule: log4j_ioc_irule
* Add Extension: log4j_ioc_extension (index.js)
* Add LX Plugin: log4j_ioc_plugin (from Workspace log4j_ioc)

### Install NodeJS modules
```
cd /var/ilx/workspaces/Common/log4j_ioc/extensions/log4j_ioc_extension
nmp install https lokijs --save
```
