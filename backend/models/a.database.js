import { BaseModel, Serializer, Database } from 'better-sequelize'

const db = Database.initialize({
    dialect: 'sqlite',
    storage: './db.sqlite'
})

export default db;