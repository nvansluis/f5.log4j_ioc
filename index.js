/**
*** Name       : log4j_ioc_extension
*** Authors    : Niels van Sluis, <niels@van-sluis.nl>
*** Version    : 0.1
*** Date       : 2021-12-26
***
*** Changes
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
var ipAddressDB = db.addCollection('ipAddresses');

// helper to call the log4j_blocklist.txt from NLD Police
function getLog4jBlockList(callback) {
    var url ="https://thanksforallthefish.nl/log4j_blocklist.txt";
    
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

    getLog4jBlockList(function(err,data) {
        if(err) {
            console.log("error: failed to fetch log4j_blocklist.txt");
            return;
        }
        
        if(!data) {
            console.log("error: log4j_blocklist.txt contains no data");
            return;
        }
        
        // clear current collections
        ipAddressDB.clear();
        
        const ipAddresses = data.toString().split('\n');

        for(let ipAddress of ipAddresses) {
            ipAddressDB.insert({ ipaddress: ipAddress });
        }
        
        // log statistics
        logStatistics();
        
        });
}

function logStatistics() {
    console.log('info: ' + ipAddressDB.count() + ' IP addresses found in database.');
}

// run at start
updateLog4jBlockList();
// run every 15 minutes
setInterval(updateLog4jBlockList, 1000 * 60 * 15);

ilx.addMethod('checkIP', function(objArgs, objResponse) {
    const ipAddress = objArgs.params()[0];
    
    var verdict = 'benign';
    
    var req = ipAddressDB.findObject( { 'ipaddress':ipAddress});
    if(req) {
        verdict = 'malicous';
    }
    
    objResponse.reply(verdict);
    
    //console.log('debug: looked up ' + ipAddress + ' and verdict is: ' + verdict);
});

ilx.listen();
