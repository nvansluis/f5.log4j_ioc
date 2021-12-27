/**
*** Name       : log4j_ioc_extension
*** Authors    : Niels van Sluis, <niels@van-sluis.nl>
*** Version    : 0.2
*** Date       : 2021-12-27
***
*** Changes
***            : v0.2 - added cert-agid.gov.it IOC list.
***            : v0.1 - initial version
**/

// NodeJS uses a statically compiled, manualy updated, hardcoded list of
// certificate authorities. The nodejs version BIG-IP uses (v6.9.1) is
// doesn't include the updated Let's Encrypt DST Root CA X3 and R3
// intermediate that expired on Sept 30th 2021. So we need to disable
// TLS verification, because the https://thanksforallthefish.nl uses a
// Let's Encrypt certificate.
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

'use strict';
 
// Import the f5-nodejs module and others.
var f5 = require('f5-nodejs');
var https = require('https');
var loki = require('lokijs');

// Create a new rpc server for listening to TCL iRule calls.
var ilx = new f5.ILXServer();

// Create (in-memory) LokiJS database and collections.
var db = new loki('db.json');
var ipAddressesDB = db.addCollection('ipAddresses', { 
    unique: ['ipaddress'],
    autoupdate: true
});

// IOC class
class IOC {
    constructor(name, url, status) {
        this.name = name;
        this.url = url;
        this.status = status;
    }
}

// Add IOCs to array. Set status to 'enabled' if you want to make use it.
const IOCs = {
    "nld_police": new IOC("nld_police", "https://thanksforallthefish.nl/log4j_blocklist.txt", "enabled"),
    "cert-agid.gov.it": new IOC("cert-agid.gov.it", "https://cert-agid.gov.it/download/log4shell-iocs.txt", "enabled")
};

// helper to retrieve data from url
function getDataFromUrl(url, callback) {
 
    var req = https.get(url, function(res) {
        var data = '';
 
        res.on('data', function(chunk) {
            data += chunk;
        });
 
        res.on('error', function(e) {
            callback(e, null);
        }); 
 
        res.on('timeout', function(e) {
            callback(e, null);
        }); 
 
        res.on('end', function() {
            if(res.statusCode == 200) {
                callback(null, data);
            }
        });
    }).on('error', function(e) {
        console.log("Got error: " + e.message);
    });
}

// Function that uses the Log4j block list to create a database
// that can be used to perform IP address lookups.
function updateLog4jBlockList() {
    
    // cert-agid.gov.it
    if(IOCs['cert-agid.gov.it'].status == 'enabled') {
        var url = IOCs['cert-agid.gov.it'].url;
        getDataFromUrl(url, function(err,data) {
            if(err) {
                console.log("error: failed to fetch " + url);
                return;
            }
        
            if(!data) {
                console.log("error: " + url + " contains no data");
                return;
            }
        
            var cert_agid_json = JSON.parse(data);
        
            for(var i in cert_agid_json) {
                var ipAddresses = cert_agid_json[i].ioc_list.ipv4;
                for (let x=0; x < ipAddresses.length; x++) {
                    updateIPAddress(ipAddresses[x]);
                }
            }
        });
    }

    // NLD Police
    if(IOCs['nld_police'].status == 'enabled') {
        var url = IOCs['nld_police'].url
        getDataFromUrl(url, function(err,data) {
            if(err) {
                console.log("error: failed to fetch " + url);
                return;
            }
        
            if(!data) {
                console.log("error: " + url + " contains no data");
                return;
            }
 
            const ipAddresses = data.toString().split('\n');

            for(let ipAddress of ipAddresses) {
                updateIPAddress(ipAddress);
            }
        
        });
    }
}

function updateIPAddress(ipAddress) {
    // check if IP address is already in database.
    var result = ipAddressesDB.findOne( { 'ipaddress': ipAddress});
    
    // if it's a new IP address, add it to the database.
    if(!result) {
        ipAddressesDB.insert({ ipaddress: ipAddress, timestamp: Date.now() });
    }
    else {
        result.timestamp = Date.now();
    }
}

function removeOldIPAddresses() {
    // remove all IP addresses with a timestamp older than 1 hour
    var timestamp = Date.now() - (1000 * 60 * 60);
    //var result = ipAddressesDB.find({ timestamp: { $lt: timestamp}});
    var result = ipAddressesDB.chain().find({ timestamp: { $lt: timestamp}}).remove();
}

function logStatistics() {
    console.log('info: ' + ipAddressesDB.count() + ' IP addresses found in the database.');
}

// run at start
updateLog4jBlockList();

// run once, 30 seconds after start
setTimeout(function() { logStatistics();}, 1000 * 30);

// run every 15 minutes
setInterval(updateLog4jBlockList, 1000 * 60 * 15);
setInterval(logStatistics, 1000 * 60 * 15);

// run every 30 minutes
setInterval(removeOldIPAddresses, 1000 * 60 * 30);

ilx.addMethod('checkIP', function(objArgs, objResponse) {
    const ipAddress = objArgs.params()[0];
    
    var verdict = 'benign';
    
    var result = ipAddressesDB.findObject( { 'ipaddress':ipAddress});
    if(result) {
        verdict = 'malicous';
    }
    
    objResponse.reply(verdict);
    
    //console.log('debug: looked up ' + ipAddress + ' and verdict is: ' + verdict);
});

ilx.listen();
