import { BaseModel, Fields, Serializer } from "better-sequelize";
import bcrypt from 'bcrypt';
import { generateToken } from "../utils/useAuth.js";
import jwt from 'jsonwebtoken';
import db from "./a.database.js";

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret';

class UserModel extends BaseModel {
    static fields = {
        username: Fields.StringField({ allowNull: false, unique: true }),
        password: Fields.StringField({ allowNull: false })
    }
}

class UserSerializer extends Serializer.createFor(UserModel) {
    async findByUsername(username) {
        return this._baseFindBy('username', username)
    }
}

const User = new UserSerializer()

async function handleRegister(username, password) {
    try {
        const hashedPass = await bcrypt.hash(password, 10)
        User.create({
            username: username,
            password: hashedPass
        })
    
    } catch(error) {
        console.log(error)
    }
}

async function handleLogin(username, password) {
    try {
        const user = await User.findByUsername(username)
        if (!user) {
            return { error: 'User not found' }
        }

        const isValid = await bcrypt.compare(password, user.password)
        if (!isValid) {
            return { error: 'Invalid password' }
        }

        const token = generateToken({ userId: user.id }, JWT_SECRET, { expiresIn: '24h' });

        let response = {
            type: "user",
            action: "cr.LoginSuccess",
            token: token
        }
        return response
    } catch(error) {
        console.log(error)
        return { error: 'Login failed' }
    }
}

export { 
    User, 
    handleRegister,
    handleLogin
}