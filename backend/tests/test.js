import { WebSocketServer, WebSocket } from "ws";
import { PayloadCrypto } from "../utils/useCrypto.js";

const ENC_KEY = Buffer.from("47b97958402a27d38960bce4e4aff3da17e077be9bdd200b935c61ec78a06db1", "hex")
const crypto = new PayloadCrypto(ENC_KEY);

const ws = new WebSocket("ws://localhost:3000/ws");

ws.on('open', function open() {
    let response 
    response = {
        type: 'user',
        action: 'cr.Login',
        username: 'selam',
        password: '12345'
    }

    const encryptedResponse = crypto.encrypt(response);
    console.log(JSON.stringify({
        encrypted: encryptedResponse.encrypted,
        iv: encryptedResponse.iv
    }))
  ws.send(JSON.stringify({
        encrypted: encryptedResponse.encrypted,
        iv: encryptedResponse.iv
    }));

})

ws.on('message', (data) => {
    const jsonData = JSON.parse(data.toString())
    if(!jsonData.encrypted || !jsonData.iv) {
        throw new Error("Eksik şifreleme")
    }

    const encryptedBuffer = Buffer.from(jsonData.encrypted, 'base64')
    const ivBuffer = Buffer.from(jsonData.iv, 'base64')

    let decrypted
    try {
        decrypted = crypto.decrypt(encryptedBuffer, ivBuffer)
    } catch(error) {
        console.log(error)
        return
    }

    console.log(decrypted)
})