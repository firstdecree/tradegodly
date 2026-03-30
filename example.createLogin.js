(async()=>{
    "use strict";

    // Dependencies
    const client = await require("./modules/mongodb.js")
    const sAES256 = require("simple-aes-256")
    const { parse } = require("smol-toml")
    const hashJS = require("hash.js")
    const fs = require("fs")
    
    // Variables
    const config = parse(fs.readFileSync("./config.toml", "utf8"))
    const database = client.db(config.database.databaseName)
    const users = database.collection(config.database.usersCollection)

     // Functions
    const SHA512 = (string)=>{return hashJS.sha512().update(string).digest("hex")}
    const sAES256E = (password, string) => {
        return sAES256.encrypt(password, string).toString("hex")
    }

    // Main
    const username = "username"
    const password = "awesomedude"

    await users.insertOne({
        hashedUsername: SHA512(username),
        username: sAES256E(password, username),
        password: SHA512(password),
        plan: "access",
        planExpiration: "n/a",
        rules: [],
        strategies: [],
        accounts: []
    })
    await client.close()
    console.log("Finished!")
    process.exit()
})()