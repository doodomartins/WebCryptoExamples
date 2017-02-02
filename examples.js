// Examples based on https://github.com/diafygi/webcrypto-examples and 
//http://qnimate.com/asymmetric-encryption-using-web-cryptography-api/
var crypto = window.crypto || window.msCrypto;

//Keys
var public_key_object_s = null;
var private_key_object_s = null;

var public_key_object_c = null;
var private_key_object_c = null;

//For export key
var string_private_key = null;
var json_private_key = null;

var string_signature_key = "";

//Data encrypted/decrypted
var decrypted_data = null;
var encrypted_data = null;

//Hash
var encrypted_hash = null;

//Using in encrypt method
var vector = crypto.getRandomValues(new Uint8Array(16));

//Signature
var signature = null;

var data = "oi";

function readSingleFile(e) {
  var file = e.target.files[0];
  if (!file) {
    return;
  }
  var reader = new FileReader();
  reader.onload = function(e) {
    var contents = e.target.result;
    displayContents(contents);
    data = contents;
  };
  reader.readAsText(file);
}

function displayContents(contents) {
  var element = document.getElementById('file-content');
  element.innerHTML = contents;
}

function displayResult(contents) {
  var element = document.getElementById('results');
  element.innerHTML = contents;
}

function convertStringToArrayBufferView(str) {
    var bytes = new Uint8Array(str.length);
    for (var iii = 0; iii < str.length; iii++) {
        bytes[iii] = str.charCodeAt(iii);
    }

    return bytes;
}

function convertArrayBufferToHexaDecimal(buffer) {
    var data_view = new DataView(buffer);
    var iii, len, hex = '', c;

    for(iii = 0, len = data_view.byteLength; iii < len; iii += 1) {
        c = data_view.getUint8(iii).toString(16);
        if(c.length < 2) {
            c = '0' + c;
        }
        hex += c;
    }
    return hex;
}

function convertArrayBufferViewtoString(buffer) {
    var str = "";
    for (var iii = 0; iii < buffer.byteLength; iii++) {
        str += String.fromCharCode(buffer[iii]);
    }
    return str;
}

function sha256() {
    console.log(data);
	if(crypto.subtle) {
	    var promise = crypto.subtle.digest({name: "SHA-256"}, 
                                           convertStringToArrayBufferView(data));

	    promise.then(function(result) {
	        var hash_value = convertArrayBufferToHexaDecimal(result);
            var encrypted_hash = hash_value;
            displayResult(hash_value)
	        console.log(hash_value);
	    });
	} else {
	    alert("Cryptography API not Supported");
	}
}

function genKey() {
    genKeysig();
    displayResult(string_signature_key);
}

function genKeysig() {
    
    var promise_key = null;

    if(crypto.subtle) {
        promise_key = crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", 
                                                  modulusLength: 2048, 
                                                  publicExponent: new Uint8Array([0x01, 0x00, 0x01]), 
                                                  hash: {name: "SHA-256"}}, 
                                                true, 
                                                ["sign", "verify"]);

        promise_key.then(function(key) {
            private_key_object_s = key.privateKey;
            public_key_object_s = key.publicKey;

            console.log("Sig keys");
            exportKeySig();
        });

        promise_key.catch = function(e) {
            console.log(e.message);
        }
        
    } else {
        alert("Cryptography API not Supported");
    }
}

function exportKeySig() {
    var promise_key = null;
    if(crypto.subtle) {
        promise_key = crypto.subtle.exportKey("jwk", public_key_object_s);
        promise_key.then(function(key){
            string_signature_key = "Public Key\n" + JSON.stringify(key);
        });
        promise_key = crypto.subtle.exportKey("jwk", private_key_object_s);
        promise_key.then(function(key){
            string_signature_key += "</p>Private Key\n" + JSON.stringify(key) + "</p>";
            displayResult(string_signature_key);
            console.log(string_signature_key);
        });
        
    }
}


function genKeyenc() {
    var promise_key_c = null;

    if(crypto.subtle) {
        promise_key_c = crypto.subtle.generateKey({ name: "RSA-OAEP", 
                                                    modulusLength: 2048, 
                                                    publicExponent: new Uint8Array([0x01, 0x00, 0x01]), 
                                                    hash: {name: "SHA-256"}}, 
                                                  false, 
                                                  ["encrypt", "decrypt"]);

        promise_key_c.then(function(key) {
            private_key_object_c = key.privateKey;
            public_key_object_c = key.publicKey;
            console.log("Encrypt and decrypt keys");
            console.log(public_key_object_c);
            console.log(private_key_object_c);
        });

        promise_key_c.catch = function(e) {
            console.log(e.message);
        }
        
    } else {
        alert("Cryptography API not Supported");
    }
}


function encryp() {
    // genKeyenc();
    var encrypt_promise = null;
    console.log(data);
    //iv: Is initialization vector. It must be 16 bytes
    encrypt_promise = crypto.subtle.encrypt({ name: "RSA-OAEP", 
                                              iv: vector}, 
                                            public_key_object_c, 
                                            convertStringToArrayBufferView(data));

    encrypt_promise.then(
        function(result) {
            encrypted_data = new Uint8Array(result);
            console.log(encrypted_data);
        }, 
        function(e) {
            console.log(e.message);
        }
    );
}

function decryp() {
    var decrypt_promise = null;

    decrypt_promise = crypto.subtle.decrypt({ name: "RSA-OAEP", 
                                              iv: vector}, 
                                            private_key_object_c, 
                                            encrypted_data);

    decrypt_promise.then(
        function(result) {
            decrypted_data = new Uint8Array(result);
            console.log(convertArrayBufferViewtoString(decrypted_data));
        },
        function(e) {
            console.log(e.message);
        }
    );
}

function sign() {
    var encrypt_promise = null;
    encrypt_promise = crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5"}, 
                                         private_key_object_s, 
                                         convertStringToArrayBufferView(data));

    encrypt_promise.then(
        function(result_signature) {
            signature = result_signature; //signature generated
            sig_value = new Uint8Array(signature)
            displayResult(sig_value.toString());
            console.log(sig_value);
        }, 
        function(e){
            console.log(e);
        }
    );
}

function verify() {
var decrypt_promise = null;

    decrypt_promise = crypto.subtle.verify({ name: "RSASSA-PKCS1-v1_5"}, 
                                           public_key_object_s, signature, 
                                           convertStringToArrayBufferView(data));

    decrypt_promise.then(
        function(result) {
            displayResult(result);
            console.log(result);//true or false
        },
        function(e) {
            console.log(e.message);
        }
    );
}
