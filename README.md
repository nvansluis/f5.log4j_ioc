# f5.log4j_ioc
iRule that helps to mitigate the Log4j vulnerability with use of public available IOCs. Currently it only uses the IOC from the NLD Police which is available here: https://thanksforallthefish.nl/log4j_blocklist.txt

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
