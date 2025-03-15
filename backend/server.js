import { WebSocket, WebSocketServer } from "ws";
import bodyParser from "body-parser";
import express from 'express'
import http from 'http'
import bcrypt from 'bcrypt'
import { PayloadCrypto } from "./utils/useCrypto.js";
import { handleRegister, handleLogin } from './models/model.user.js' 


const ENC_KEY = Buffer.from("47b97958402a27d38960bce4e4aff3da17e077be9bdd200b935c61ec78a06db1", "hex")
const crypto = new PayloadCrypto(ENC_KEY);

const App = class App {
    constructor() {
        this.app = express()
        this.httpServer = http.createServer(this.app)

        this.wss = new WebSocketServer({
            server: this.httpServer,
            path: "/ws"
        })
        this.app.use(express.static('public'))
        this.app.use(bodyParser.json())

        this.runserver()
    }

    async handleUser(payload) {
        try {
            switch(payload.action) {
                case 'cr.Register':
                    handleRegister(payload.username, payload.password)
                    break;
                case 'cr.Login':
                    return await handleLogin(payload.username, payload.password)
            }
        } catch(error) {
            console.log("error", error)
        }
    }

    runserver() {
        this.app.get('/', (req, res) => {
            res.send("Hi Traveler!")
        })

        this.wss.on("connection", (socket) => {
            console.log("connection made")
            socket.on("message", async (data) => {
                try {
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
                        socket.send(JSON.stringify({
                            type: 'error',
                            message: 'Deşifreeleme hatasıı'
                        }))
                        return
                    }

                    let response
                    switch(decrypted.type) {
                        case 'user':
                            response = await this.handleUser(decrypted)
                            break;
                    }
                    const encryptedResponse = crypto.encrypt(response)
                    socket.send(JSON.stringify({
                        encrypted: encryptedResponse.encrypted,
                        iv: encryptedResponse.iv
                    }))
                } catch(error) {
                    console.log(error)
                }
            })
        })

        this.httpServer.listen('3000', () => {
            console.log("server running")
        })
    }
}

new App()