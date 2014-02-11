

function build_json_request(mode, txt) {
    var request = {};

    // generate a random key and IV
    var key = forge.random.getBytesSync(32);
    var iv = forge.random.getBytesSync(16);

    request.b64_key = forge.util.encode64(key);
    request.b64_iv = forge.util.encode64(iv);
    request.mode = mode;

    // encrypt The request using the AES key, 
    var cipher = forge.aes.createEncryptionCipher(key, mode);
    cipher.start(iv);
    cipher.update(forge.util.createBuffer(txt));
    cipher.finish();
   
    request.b64_encval = forge.util.encode64(cipher.output.bytes());

    console.log("Base64 request encryption key: " + request.b64_key);
    $("#b64_key").html(request.b64_key);
    console.log("Base64 request encryption iv: " +  request.b64_iv);
    $("#b64_iv").html(request.b64_iv);
    console.log("Request encryption mode: " +  request.mode);
    $("#req_mode").html(request.mode);
    console.log("Base64 encrypted message: " + request.b64_encval);
    $("#b64_enc_txt").html(request.b64_encval);
    return JSON.stringify(request);
}

function handle_json_response(data, txtStatus, jqXHR) {
    // generate a random key and IV
    var key = forge.util.decode64(data.b64_key);
    var iv = forge.util.decode64(data.b64_iv);
    var ciphertxt = forge.util.decode64(data.b64_encval);

    // decrypt The response using the AES key, 
    var cipher = forge.aes.createDecryptionCipher(key, data.mode);
    cipher.start(iv);
    cipher.update(forge.util.createBuffer(ciphertxt));
    cipher.finish();
   
    var response_txt = cipher.output.bytes();

    console.log("Base64 response encryption key: " + data.b64_key);
    $("#resp_b64_key").html(data.b64_key);
    console.log("Base64 response encryption iv: " +  data.b64_iv);
    $("#resp_b64_iv").html(data.b64_iv);
    console.log("Response encryption mode: " +  data.mode);
    $("#resp_mode").html(data.mode);
    console.log("Base64 encrypted response: " + data.b64_encval);
    $("#resp_b64_enc_txt").html(data.b64_encval);
    console.log("decrypted response: " + response_txt);
    $("#resp_txt").html(response_txt);
}

function do_json_request(url, json_request, done = null, fail = null, always = null) {
    $.post(url, json_request, null, "json")
    .done(function(data, textStatus, jqXHR) {
        if (typeof done == "function") { done(data, textStatus, jqXHR); }
    })
    .fail(function(jqXHR, textStatus, ethrow) {
        if (typeof fail == "function") { fail(jqXHR, textStatus, ethrow); }
    })
    .always(function(a, b, c) {
        /*  
            depending on success or failure, the contents of "a" and "b"    
            change to be the same as the arguments to done or fail, 
        */
        if (typeof always == "function") { always(a, b, c); }
    });
}

$(document).ready(function() {
    $("#testencbutton").click(function() {
        var url = "http://127.0.0.1:8001/testenc.json";
        var message = $("#message").val();
        var mode = $("#enc_mode").val();
        var raw_request = build_json_request(mode, message);
        do_json_request(url, raw_request, handle_json_response);
    });
});


