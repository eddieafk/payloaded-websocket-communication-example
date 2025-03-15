import jwt from 'jsonwebtoken'
import { User } from '../models/model.user.js'

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret'

const generateToken = (userId) => {
    return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '24h' })
}

const verifyToken = (token) => {
    try {
        return jwt.verify(token, JWT_SECRET)
    } catch(error) {
        console.log(error)
        return null
    }
}

const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    if (!token) {
        return res.status(401).json({ error: 'Authorization token required' })
    }

    const decoded = verifyToken(token)
    if (!decoded) {
        return res.status(403).json({ error: 'Invalid or expired token' })
    }

    try {
        const user = await User.findById(decoded.userId)
        if (!user) {
            return res.status(404).json({ error: 'User not found' })
        }
        req.user = user
        next()
    } catch (error) {
        console.log(error)
        return res.status(500).json({ error: 'Authentication failed' })
    }
}

export {
    generateToken,
    verifyToken,
    authenticateToken
}