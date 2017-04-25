var net = require('net');
var xmlbuilder = require('xmlbuilder');
var argv = require('minimist')(process.argv.slice(2));
var NodeRSA = require('node-rsa');
var XmlReader = require('xml-reader');

var ip = argv._[0];
var port = argv.p || 5025;

if (!ip) {
    console.log("Incorrect arguments.");
    console.log("Usage stresspoint [-p <port>] <destination_ip>");
    process.exit(-1);
}

var client = new net.Socket();
var rsaKey = null;
const reader = XmlReader.create({ stream: true });

process.on('exit', function() {
    if (client) {
        client.destroy();
    }
});

reader.on('done', function(data) {
    console.log('XML: ' + data);
});

console.log("Connecting to " + ip);

client.connect(port, ip, function() {
    console.log("Connected to " + ip);
    register();
});

client.on('data', function(data) {
    var dataStr = data.toString();
    console.log('RECEIVED: ' + dataStr);
    reader.parse(dataStr);
});

client.on('close', function() {
	console.log('Connection closed');
});

function register() {
    var code = "1234";

    console.log("Generating RSA pair");
    rsaKey = new NodeRSA();
    rsaKey.generateKeyPair();
    var publicKey = rsaKey.exportKey("pkcs8-public-der");

    console.log("Sending register request");
    var msg = registerMessage(code, publicKey.toString('base64'));
    
    client.write(msg);
    console.log("REGISTER: " + msg);
}

function registerMessage(code, key) {
    return functionMessage("SECURITY", "REGISTER", { ENTRY_CODE: code, KEY: key });
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



















