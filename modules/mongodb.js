"use strict";

// Dependencies
const { MongoClient } = require("mongodb")
const { parse } = require("smol-toml")
const path = require("path")
const fs = require("fs")

// Functions
const findConfig = ()=>{
    var currentDir = process.cwd()
  
    while (true) {
        const candidate = path.join(currentDir, "config.toml")
        if (fs.existsSync(candidate)) return candidate
        const parentDir = path.dirname(currentDir)
        if (parentDir === currentDir) return null
        currentDir = parentDir
    }
}

// Variables
const uri = parse(fs.readFileSync(findConfig(), "utf8")).database.clusterURL

let client;
let clientPromise;

// Main
if(!uri) throw new Error("Please set a MongoDB url.")

if(process.env["NODE_ENV"] === "development"){
    if(!global._mongoClientPromise){
        client = new MongoClient(uri)
        global._mongoClientPromise = client.connect()
    }

    clientPromise = global._mongoClientPromise
}else{
    client = new MongoClient(uri)
    clientPromise = client.connect()
}

module.exports = clientPromise