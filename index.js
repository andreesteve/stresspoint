var net = require('net');
var xmlbuilder = require('xmlbuilder');
var argv = require('minimist')(process.argv.slice(2));
var NodeRSA = require('node-rsa');
var XmlReader = require('xml-reader');
var crypto = require('crypto');
var util = require('util');
var fs = require('fs');
var ip = argv._[0];
var port = argv.p || 5025;

if (!ip) {
    log("Incorrect arguments.");
    log("Usage stresspoint [-p <port>] <destination_ip>");
    process.exit(-1);
}

var client = new net.Socket();
var rsaKey = null;
var state = '';
var hmaclabel = '';
var macKey = null;
var counter = 1;
var xmlReceived = [];

const reader = XmlReader.create({ stream: true });
reader.parse("<stream>");

process.on('exit', function() {
    if (client) {
        client.destroy();
    }
});

reader.on('tag', function (name, data) {
    if (name != 'RESPONSE') {
        xmlReceived.push(data);
    } else {
        data.children = xmlReceived;
        handleResponse(data);
        xmlReceived = [];
    }
});
 
// reader.on('done', function(data) {
//     data.children = xmlReceived;
//     handleResponse(data);
// });

function handleResponse(data) {
//    log('RESPONSE: \n' + util.inspect(data));
    log('State: ' + state);
    
    switch (state) {
    case 'registering':
        log("Handle register");
        handleRegisterResponse(data);
        break;

    case 'beginTran':
        log("Handle trans begin");
        handleTransactionBegin(data);
        break;

    case 'endTran':
        log("Handle trans end");
        handleTransactionEnd(data);
        break;

    case 'capturing':
        log("Handle capture");
        handleCapture(data);
        break;
    }    
}

log("Connecting to " + ip);

client.connect(port, ip, function() {
    log("Connected to " + ip);
    register();
});

client.on('data', function(data) {
    var dataStr = data.toString();
    log('RECEIVED: \n' + dataStr);
    reader.parse(dataStr);
});

client.on('close', function() {
	log('Connection closed');
});

function register() {
    var code = "1234";
    var format = 'private';
    
    rsaKey = new NodeRSA(null, null, {
        encryptionScheme: 'pkcs1'
    });

    var tp = "/tmp/pointrsa";
    var encoding = 'utf-8';
    if (fs.existsSync(tp)) {
        log("Found keys at " + tp);
        var keys = fs.readFileSync(tp, encoding);
        rsaKey.importKey(keys, format);
        log("Keys imported");
    } else {
        log("Generating RSA pair");
        rsaKey.generateKeyPair();        
        var exptKeys = rsaKey.exportKey(format);
        fs.writeFileSync(tp, exptKeys, encoding);
    }

    var publicKey = rsaKey.exportKey("pkcs8-public-der");

    log("Sending register request");
    var msg = registerMessage(code, publicKey.toString('base64'));

    state = 'registering';
    
    write(msg);
}

function handleRegisterResponse(data) {
    var result = getValue(data, "Result_Code");
    var responseText = getValue(data, "Response_Text");
    if (result == "-1") {
        hmaclabel = getValue(data, "mac_label");
        var macKeyCrypt = getValue(data, "mac_key");

        log("MACKEYCRYPT = " + macKeyCrypt);
        log("MACLABEL = " + hmaclabel);
        
        macKey = rsaKey.decrypt(macKeyCrypt);
        log('HMAC ' + hmaclabel + " = " + macKey.toString('base64'));
        
        state = 'beginTran';

        write(beginTransaction());
        
    } else {
        state = 'none';
        log("Register error: " + result + " - " + responseText);
    }
}

function handleTransactionBegin(data) {
    var result = getValue(data, "Result_Code");
    var responseText = getValue(data, "Response_Text");
    if (result == "-1") {
        state = 'capturing';

        write(captureTransaction());
       
    } else if (result == "59003" /*session open*/) {
        state = 'endTran';
        write(endTransaction());
    } else {
        state = 'none';
        log("Begin error: " + result + " - " + responseText);
    }
}

function handleTransactionEnd(data) {
    var result = getValue(data, "Result_Code");
    var responseText = getValue(data, "Response_Text");
    if (result == "-1") {
        state = 'beginTran';

        write(beginTransaction());
       
    } else {
        state = 'error';
        log("End transaction error: " + result + " - " + responseText);
    }
}

function handleCapture(data) {
    var result = getValue(data, "Result_Code");
    var responseText = getValue(data, "Response_Text");

    log("Capture result: " + result + " - " + (responseText || ""));

    state = 'endTran';
    write(endTransaction());    
}

function registerMessage(code, key) {
    return functionMessage("SECURITY", "REGISTER", { ENTRY_CODE: code, KEY: key });
}

var invoice = 0;
var invoicePrefix = new Date().getTime().toString() + "_";
function beginTransaction() {
    return functionMessage("SESSION", "START", authData({
        INVOICE: invoicePrefix + (++invoice).toString()
    }));
}

function endTransaction() {
    return functionMessage("SESSION", "FINISH", authData({}));
}

function captureTransaction() {
    return functionMessage("PAYMENT", "CAPTURE", authData({
        'TRANS_AMOUNT': '1.00'        
    }));
}

function authData(data) {
    var c = counter++;
    
    var hmac = crypto.createHmac('sha256', macKey);
    hmac.update(c.toString());
    
    data['COUNTER'] = c;
    data['MAC'] = hmac.digest('base64');
    data['MAC_LABEL'] = hmaclabel;
    return data;
}

function functionMessage(func, command, data) {
    var root = xmlbuilder.create('TRANSACTION', {
        headless: true,
        encoding: 'ASCII'
    });
    
    root.ele('FUNCTION_TYPE', func);
    root.ele('COMMAND', command);
    if (data) {
        root.ele(data);
    }

    return root.end({
        pretty: true,
        indent: '  '
    });
}
    
    function getValue(data, el) {
        var els = el.toLowerCase().split('/');
        var d = data;        
        
        for (var i = 0; i < els.length; i++) {
            var cel = els[i];
            var found = false;
            
            for (var j = 0; j < d.children.length; j++) {
                var c = d.children[j];
                if (c.name.toLowerCase() == cel) {
                    d = c;
                    found = true;
                    break;
                }
            }

            if (!found) {
                return null;
            }
        }

        return ((d.children || [])[0] || {}).value;
    };

    function write(msg) {
        log('SENT: \n' + msg);
        client.write(msg);
    }

function log(msg) {
    console.log(new Date().getTime() + ": " + msg);
}
