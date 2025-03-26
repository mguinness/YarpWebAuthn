function atobarray(sBase64) {
    var sBinaryString = atob(sBase64), aBinaryView = new Uint8Array(sBinaryString.length);
    Array.prototype.forEach.call(aBinaryView, function (el, idx, arr) { arr[idx] = sBinaryString.charCodeAt(idx); });
    return aBinaryView;
}

function barraytoa(arrayBuffer) {
    return btoa(String.fromCharCode(...new Uint8Array(arrayBuffer)));
}

async function registerkey() {
    try {
        let data = await fetch('registerkey', { method: 'POST' });
        let json = await data.json()
        json.publicKey.challenge = atobarray(json.publicKey.challenge)
        json.publicKey.user.id = atobarray(json.publicKey.user.id)
        let cred = await navigator.credentials.create(json)
        window.command.innerHTML = 'On your server, save this key in appsettings under hosts section:<br /><pre>"' + window.location.hostname +
            '": {<br />&nbsp;&nbsp;"' + barraytoa(cred.rawId) + '": "' + barraytoa(cred.response.getPublicKey()) + '"<br />}</pre>'
    } catch (e) {
        console.log(e);
    }
}

async function existingKey() {
    try {
        let data = await fetch('existingkey', { method: 'POST' });
        let json = await data.json()
        if (json.publicKey !== undefined) {
            json.publicKey.challenge = atobarray(json.publicKey.challenge)
            json.publicKey.allowCredentials.forEach(x => x.id = atobarray(x.id))
            let result = await navigator.credentials.get(json)
            await fetch('validatekey', { method: 'POST', body: JSON.stringify({
                id: barraytoa(result.rawId),
                authenticatorData: barraytoa(result.response.authenticatorData),
                clientDataJSON: barraytoa(result.response.clientDataJSON),
                signature: barraytoa(result.response.signature)
            }), headers:{ 'Content-Type': 'application/json' }})
            window.location.href = "/"
        }
        if (json.error == 'not_configured') {
            window.command.innerHTML = 'No credentials configured on server for ' + window.location.hostname
        }
    } catch (e) {
        console.log(e);
    }
}