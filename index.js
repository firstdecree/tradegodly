(async () => {
    "use strict";

    // Dependencies
    const client = await require("./modules/mongodb.js")
    const cookieParser = require("cookie-parser")
    const compression = require("compression")
    const sAES256 = require("simple-aes-256")
    const { ObjectId } = require("mongodb")
    const { parse } = require("smol-toml")
    const { filterXSS } = require("xss")
    const express = require("express")
    const hashJS = require("hash.js")
    const helmet = require("helmet")
    const cryptr = require("cryptr")
    const axios = require("axios")
    const path = require("path")
    const fs = require("fs")

    // Variables
    const config = parse(fs.readFileSync("./config.toml", "utf8"))
    const cT = new cryptr(config.security.cookieMasterKey, { encoding: config.security.cookieEncoding, pbkdf2Iterations: config.security.cookiePBKDF2Iterations, saltLength: config.security.cookieSaltLength })
    const web = express()
    const port = config.web.port

    const database = client.db(config.database.databaseName)
    const users = database.collection(config.database.usersCollection)
    const trades = database.collection(config.database.tradesCollection)

    // Functions
    const SHA512 = (string) => { return hashJS.sha512().update(string).digest("hex") }
    const setCookie = (res, data) => {
        res.cookie("d", data, {
            maxAge: 12 * 60 * 60 * 1000, // 12 hours
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict"
        })
    }

    const dS = async (session) => {
        try {
            const sessionData = JSON.parse(cT.decrypt(session.d))
            return sessionData
        } catch { return false }
    }

    const sAES256E = (password, string) => {
        return sAES256.encrypt(password, string).toString("hex")
    }

    const sAES256D = (password, string) => {
        return sAES256.decrypt(password, Buffer.from(string, "hex")).toString("utf8")
    }

    const promptAI = async (type, rules, strategies, data, recentTrades) => {
        // Variables
        var systemPrompt = ""
        
        // IDK lmfao
        if (type === "trade") {
            systemPrompt = "You are an expert Trading Analyst. Provide a summary of this trade from the data given, and offer advice for improvement. Use three headings: Introduction, Mistakes, and Improvements. Address the user as 'you'.";
        } else if (type === "trades") {
            systemPrompt = "You are a Performance Analyst. Summarize the user's trading performance based on the dashboard data provided. Mention specific statistics and progress. Keep it in a single paragraph. Address the user as 'you'.";
        } else if (type === "chat") {
            systemPrompt = "You are the TradeGodly AI Trading Mentor. Guide the user based on their stated rules and strategies. Be concise, professional, and authentic. Address the user as 'you'.";
        } else {
            systemPrompt = type
        }

        // Core
        const rulesText = (rules && rules.length) ? rules.join("\n") : "None provided yet."
        const strategiesText = (strategies && strategies.length) ? strategies.map(s => `${s.name}: ${s.description || "No description"}${s.howItWorks ? `\nHow it works: ${s.howItWorks}` : ""}`).join("\n---\n") : "None provided yet."
        const recentTradesText = (recentTrades && recentTrades.length) ? recentTrades.map(t => `${t.date}: ${t.asset} (${t.type}) -> ${t.status}`).join("\n") : "None provided yet."

        const promptPayload = `System Context: ${systemPrompt}

User Trading Rules:
${rulesText}

User Strategies:
${strategiesText}

Recent Trades (History):
${recentTradesText}

Input Data/Message: ${data}`

        try {
            const response = await axios.post("https://public-api.firstdecree.org/api/v1.0/ai/chatgptlite",
                { data: promptPayload },
                {
                    headers: { "x-key": "All Hail Decree!" },
                    timeout: 25000
                }
            )

            if (response.data) return response.data
            return "I'm sorry, I couldn't generate a response at this time."
        } catch {
            return "I'm sorry, I'm having trouble connecting to my AI core. Please try again in a moment."
        }
    }

    // Configurations
    //* Express
    web.use(compression({ level: 1 }))
    web.use(helmet({ contentSecurityPolicy: false }))
    web.use(cookieParser())
    web.use(express.json({ limit: "50mb" }))
    web.set("views", path.join(__dirname, "views"))
    web.set("view engine", "ejs")

    // Main
    //* API
    web.post("/api/login", async (req, res) => {
        /**
         * ! AUDITED (2026-03-30)
         * ! Username (POST BODY)
         * ! - If empty, invalidated.
         * ! - If contains special character, invalidated.
         * 
         * ! Password (POST BODY)
         * ! - If empty, invalidated.
         * 
         * ! If account does not exist, invalidated.
         */

        // Variables
        const { username, password } = req.body

        // Validations
        if (!username || !password) return res.send("0")
        if(/[^\w\s]/.test(username)) return res.send("0")
        const accountData = await users.findOne({
            hashedUsername: SHA512(username),
            password: SHA512(password)
        })
        if (!accountData) return res.send("0")

        // Core
        setCookie(res, cT.encrypt(JSON.stringify({
            username: sAES256D(password, accountData.username),
            password: password,
            plan: accountData.plan,
            planExpiration: accountData.planExpiration,
            account: "all" // Default is all.
        })))
        res.send("1")
    })

    web.post("/api/new-rule", async (req, res) => {
        /**
         * ! AUDITED (2026-03-30)
         * ! Rule (POST BODY)
         * ! - If empty, invalidated.
         * ! - If more than 125 characters, invalidated.
         * ! - If account has more than 40 rules, reject.
         * ! - If contains special characters except ",", -, _, ' and . then invalidated.
         */

        const userData = await dS(req.cookies)
        if (!userData) return res.send("0")

        var { rule } = req.body
        if (!rule || rule.length > 125) return res.send("0")
        if(/[^\w\s\-,.'"']/.test(rule)) return res.send("0")
        rule = filterXSS(rule)

        const accountData = await users.findOne({ hashedUsername: SHA512(userData.username) })
        if (!accountData) return res.send("0")

        if (accountData.rules && accountData.rules.length >= 40) return res.send("max")

        await users.updateOne({ hashedUsername: SHA512(userData.username) }, {
            $push: { rules: rule }
        })
        res.send("1")
    })

    web.post("/api/remove-rule", async (req, res) => {
         /**
         * ! AUDITED (2026-03-30)
         * ! Rule (POST BODY)
         * ! - If empty, invalidated.
         * ! - If more than 125 characters, invalidated.
         * ! - If contains special characters except ",", -, _, ' and . then invalidated.
         */

        // High Validation
        const userData = await dS(req.cookies)
        if (!userData) return res.send("0")

        // Variables
        const { rule } = req.body

        // Validations
        if (!rule) return res.send("0")
        if (!rule || rule.length > 125) return res.send("0")
        if(/[^\w\s\-,.'"']/.test(rule)) return res.send("0")

        // Core
        await users.updateOne({ hashedUsername: SHA512(userData.username) }, {
            $pull: { rules: rule }
        })
        res.send("1")
    })

    web.post("/api/new-strategy", async (req, res) => {
        /**
         * ! AUDITED (2026-03-30)
         * ! ALL (POST BODY)
         * ! - If empty, invalidated.
         * ! - All are sanitized to avoid XSS exploitation.
         * 
         * ! Name (POST BODY)
         * ! - If more than 25 characters, invalidated.
         * 
         * ! Description (POST BODY)
         * ! - If more than 300 characters, invalidated.
         * 
         * ! howItWorks (POST BODY)
         * ! - If more than 2500 characters, invalidated.
         */

        // High Validation
        const userData = await dS(req.cookies)
        if (!userData) return res.send("0")

        // Variables
        var { name, description, howItWorks } = req.body

        // Validations
        if (!name || name.length > 25) return res.send("0")
        if (!description || description.length > 300) return res.send("0")
        if (!howItWorks || howItWorks.length > 2500) return res.send("0")
        name = filterXSS(name)
        description = filterXSS(description)
        howItWorks = filterXSS(howItWorks)

        // Core
        await users.updateOne({ hashedUsername: SHA512(userData.username) }, {
            $push: {
                strategies: {
                    id: new ObjectId().toString(),
                    name,
                    description,
                    howItWorks,
                    createdAt: new Date().toISOString()
                }
            }
        })
        res.send("1")
    })

    web.post("/api/remove-strategy", async (req, res) => {
        /**
         * ! AUDITED (2026-03-30)
         * ! ID (POST BODY)
         * ! - If empty, invalidated.
         * ! - If more than 100 characters, invalidated.
         */

        // High Validation
        const userData = await dS(req.cookies)
        if (!userData) return res.send("0")

        // Variables
        const { id } = req.body

        // Validations
        if (!id) return res.send("0")
        if(id.length > 100) return res.send("0")

        // Core
        await users.updateOne({ hashedUsername: SHA512(userData.username) }, {
            $pull: {
                strategies: { id: id }
            }
        })
        res.send("1")
    })

    web.post("/api/new-account", async (req, res) => {
        /**
         * ! AUDITED (2026-03-30)
         * ! Name (POST BODY)
         * ! - If empty, invalidated.
         * ! - If more than 30 characters, invalidated.
         */

        // High Validation
        const userData = await dS(req.cookies)
        if (!userData) return res.send("0")

        // Variables
        var { name, deposit } = req.body

        // Validations
        if (!name) return res.send("0")
        if(name.length > 30) return res.send("0")
        name = filterXSS(name)

        // Core
        await users.updateOne({ hashedUsername: SHA512(userData.username) }, {
            $push: {
                accounts: {
                    name: name,
                    deposit: parseFloat(deposit) || 0,
                    createdAt: new Date().toISOString()
                }
            }
        })
        res.send("1")
    })

    web.post("/api/remove-account", async (req, res) => {
        /**
         * ! AUDITED (2026-03-30)
         * ! Name (POST BODY)
         * ! - If empty, invalidated.
         * ! - If more than 30 characters, invalidated.
         */

        // High Validation
        const userData = await dS(req.cookies)
        if (!userData) return res.send("0")

        // Variables
        const { name } = req.body

        // Validations
        if (!name) return res.send("0")
        if(name.length > 30) return res.send("0")

        // Core
        await users.updateOne({ hashedUsername: SHA512(userData.username) }, {
            $pull: {
                accounts: name
            }
        })

        await users.updateOne({ hashedUsername: SHA512(userData.username) }, {
            $pull: {
                accounts: { name: name }
            }
        })

        await trades.deleteMany({
            owner: SHA512(userData.username),
            account: name
        })

        res.send("1")
    })

    web.post("/api/new-trade", async (req, res) => {
        /**
         * ! AUDITED (2026-03-30)
         * ! ALL (POST BODY)
         * ! - If empty, invalidated.
         * ! - All strings are sanitized to avoid XSS exploitation.
         * ! - Numerical values are parsed to ensure validity.
         * 
         * ! Asset (POST BODY)
         * ! - If more than 20 characters, invalidated.
         * ! - Allowed characters: Alphanumeric, spaces, -, /, .
         * 
         * ! Type/Status/Session/Timeframe (POST BODY)
         * ! - Validated against allowed enum values.
         * 
         * ! Limits
         * ! - Maximum 5000 trades per user to prevent database bloat/abuse.
         */

        // High Validation
        const userData = await dS(req.cookies)
        if (!userData) return res.send("0")
        if (userData.account === "all") return res.send("0")

        // Variables
        var { date, type, asset, session, status, qty, entry, exit, tp, sl, hold, ret, entryTime, exitTime, timeframe, timezone } = req.body

        // Validations
        if (!date || !type || !asset || !status || qty === undefined || entry === undefined || exit === undefined) return res.send("0")
        
        if (!["LONG", "SHORT"].includes(type)) return res.send("0")
        if (!["WIN", "LOSE", "BREAKEVEN"].includes(status)) return res.send("0")
        if (!["Sydney", "Tokyo", "London", "New York"].includes(session)) session = "London"
        if (!["1m", "3m", "5m", "15m", "30m", "1h", "4h", "1d"].includes(timeframe)) timeframe = "1h"

        if (asset.length > 20 || /[^\w\s\-\/\.]/.test(asset)) return res.send("0")
        if (hold && hold.length > 50) return res.send("0")
        if (timezone && timezone.length > 30) return res.send("0")
        if (entryTime && entryTime.length > 20) return res.send("0")
        if (exitTime && exitTime.length > 20) return res.send("0")

        // Sanitization
        asset = filterXSS(asset)
        hold = filterXSS(hold || "")
        timezone = filterXSS(timezone || "UTC")
        entryTime = filterXSS(entryTime || "00:00:00")
        exitTime = filterXSS(exitTime || "00:00:00")

        // Numbers
        qty = parseFloat(qty) || 0
        entry = parseFloat(entry) || 0
        exit = parseFloat(exit) || 0
        tp = parseFloat(tp) || 0
        sl = parseFloat(sl) || 0
        ret = parseFloat(ret) || 0

        // Abuse Prevention
        const tradeCount = await trades.countDocuments({ owner: SHA512(userData.username) })
        if (tradeCount >= 5000) return res.send("max")

        // Core
        await trades.insertOne({
            owner: SHA512(userData.username),
            account: userData.account,
            date,
            type,
            asset,
            session,
            status,
            qty,
            entry,
            exit,
            tp,
            sl,
            hold,
            ret,
            entryTime,
            exitTime,
            timeframe,
            timezone,
            note: {
                content: "",
                screenshots: []
            }
        })
        res.send("1")
    })
    web.post("/api/remove-trade", async (req, res) => {
        /**
         * ! AUDITED (2026-03-30)
         * ! ID (POST BODY)
         * ! - If empty, invalidated.
         * ! - If more than 100 characters, invalidated.
         */

        // High Validation
        const userData = await dS(req.cookies)
        if (!userData) return res.send("0")

        // Variables
        const { id } = req.body
        
        // Validations
        if (!id) return res.send("0")
        if(id.length > 100) return res.send("0")

        // Core
        try {
            await trades.deleteOne({
                _id: new ObjectId(id),
                owner: SHA512(userData.username)
            })
            res.send("1")
        } catch{
            res.send("0")
        }
    })

    web.post("/api/set-account", async (req, res) => {
        // High Validation
        const userData = await dS(req.cookies)
        if (!userData) return res.send("0")

        // Variables
        const { account } = req.body

        // VAlidation
        if (!account) return res.send("0")

        // Core
        if (account !== "all") {
            const accountData = await users.findOne({ hashedUsername: SHA512(userData.username) })
            const allAccountNames = (accountData && accountData.accounts) ? accountData.accounts.map(a => typeof a === "object" ? a.name : a) : []
            if (!allAccountNames.includes(account)) return res.send("0")
        }

        setCookie(res, cT.encrypt(JSON.stringify({
            username: userData.username,
            password: userData.password,
            plan: userData.plan,
            planExpiration: userData.planExpiration,
            account: account === "all" ? "all" : account.charAt(0).toUpperCase() + account.slice(1)
        })))

        res.send("1")
    })

    web.post("/api/update-trade", async (req, res) => {
        /**
         * ! AUDITED (2026-03-30)
         * ! ALL (POST BODY)
         * ! - If empty, invalidated.
         * ! - All strings are sanitized to avoid XSS exploitation.
         * ! - Numerical values are parsed to ensure validity.
         * 
         * ! Asset (POST BODY)
         * ! - If more than 20 characters, invalidated.
         * ! - Allowed characters: Alphanumeric, spaces, -, /, .
         * 
         * ! Type/Status/Session/Timeframe (POST BODY)
         * ! - Validated against allowed enum values.
         * 
         * ! Limits
         * ! - Maximum 5000 trades per user to prevent database bloat/abuse.
         */

        // High Validation
        const userData = await dS(req.cookies)
        if (!userData) return res.send("0")

        // Variables
        var { id, date, type, asset, session, status, qty, entry, exit, tp, sl, hold, ret, entryTime, exitTime, timeframe, timezone } = req.body

        // Validations
        if (!id || !date || !type || !asset || !status || qty === undefined || entry === undefined || exit === undefined) return res.send("0")
        
        if (!["LONG", "SHORT"].includes(type)) return res.send("0")
        if (!["WIN", "LOSE", "BREAKEVEN"].includes(status)) return res.send("0")
        if (!["Sydney", "Tokyo", "London", "New York"].includes(session)) session = "London"
        if (!["1m", "3m", "5m", "15m", "30m", "1h", "4h", "1d"].includes(timeframe)) timeframe = "1h"

        if (asset.length > 20 || /[^\w\s\-\/\.]/.test(asset)) return res.send("0")
        if (hold && hold.length > 50) return res.send("0")
        if (timezone && timezone.length > 30) return res.send("0")
        if (entryTime && entryTime.length > 20) return res.send("0")
        if (exitTime && exitTime.length > 20) return res.send("0")

        // Sanitization
        asset = filterXSS(asset)
        hold = filterXSS(hold || "")
        timezone = filterXSS(timezone || "UTC")
        entryTime = filterXSS(entryTime || "00:00:00")
        exitTime = filterXSS(exitTime || "00:00:00")

        // Numbers
        qty = parseFloat(qty) || 0
        entry = parseFloat(entry) || 0
        exit = parseFloat(exit) || 0
        tp = parseFloat(tp) || 0
        sl = parseFloat(sl) || 0
        ret = parseFloat(ret) || 0

        // Core
        try {
            await trades.updateOne(
                { _id: new ObjectId(id), owner: SHA512(userData.username) },
                {
                    $set: {
                        date, type, asset, session, status, qty, entry, exit, tp, sl, hold, ret,
                        entryTime, exitTime, timeframe, timezone
                    }
                }
            )
            res.send("1")
        } catch {
            res.send("0")
        }
    })

    web.post("/api/update-trade-note", async (req, res) => {
        /**
         * ! AUDITED (2026-03-30)
         * ! ID (POST BODY)
         * ! - If empty, invalidated.
         * 
         * ! Content (POST BODY)
         * ! - If empty, invalidated.
         * ! - Sanitized to ensure anti-XSS exploitation.
         */

        const userData = await dS(req.cookies)
        if (!userData) return res.send("0")

        // Variables
        var { id, content } = req.body

        // Validations
        if (!id || !content) return res.send("0")
        content = filterXSS(content)

        // Core
        try {
            await trades.updateOne(
                { _id: new ObjectId(id), owner: SHA512(userData.username) },
                { $set: { "note.content": content } }
            )
            res.send("1")
        } catch{
            res.send("0")
        }
    })

    web.post("/api/add-screenshot", async (req, res) => {
        /**
         * ! AUDITED (2026-03-30)
         * ! ALL (POST BODY)
         * ! - If empty, invalidated.
         */

        // High Validation
        const userData = await dS(req.cookies)
        if (!userData) return res.send("0")

        // Variables
        const { id, img } = req.body

        // Validations
        if (!id || !img) return res.send("0")

        // Core
        try {
            await trades.updateOne(
                { _id: new ObjectId(id), owner: SHA512(userData.username) },
                { $push: { "note.screenshots": img } }
            )
            res.send("1")
        } catch {
            res.send("0")
        }
    })

    web.post("/api/delete-screenshot", async (req, res) => {
        /**
         * ! AUDITED (2026-03-30)
         * ! ALL (POST BODY)
         * ! - If empty, invalidated.
         */

        // High Validation
        const userData = await dS(req.cookies)
        if (!userData) return res.send("0")

        // Variables
        const { id, index } = req.body
        
        // Validations
        if (!id || index === undefined) return res.send("0")

        // Core
        try {
            const tradeData = await trades.findOne({ _id: new ObjectId(id), owner: SHA512(userData.username) })
            if (!tradeData || !tradeData.note || !tradeData.note.screenshots) return res.send("0")

            const screenshots = tradeData.note.screenshots
            screenshots.splice(index, 1)

            await trades.updateOne(
                { _id: new ObjectId(id), owner: SHA512(userData.username) },
                { $set: { "note.screenshots": screenshots } }
            )
            res.send("1")
        } catch {
            res.send("0")
        }
    })

    //* Handler
    web.get("/logout", (req, res) => { res.clearCookie("d").redirect("/login") })
    web.get("/delete-account", async (req, res) => {
        // High Validation
        const userData = await dS(req.cookies)
        if (!userData) return res.redirect("/login")

        // Core
        await trades.deleteMany({ owner: SHA512(userData.username) })
        await users.deleteOne({ hashedUsername: SHA512(userData.username) })
        res.clearCookie("d").redirect("/")
    })
    web.get("/login", async (req, res, next) => {
        const userData = await dS(req.cookies)
        if (userData) return res.redirect("/dashboard")
        next()
    })
    web.use(express.static(path.join(__dirname, "public"), { extensions: ["html"] }))

    //* EJS
    web.get("/dashboard", async (req, res) => {
        // High Validation
        const userData = await dS(req.cookies)
        if (!userData) return res.redirect("/login")

        // Variables
        const accountData = await users.findOne({ hashedUsername: SHA512(userData.username) })
        userData.accountsList = accountData && accountData.accounts ? accountData.accounts.map(a => typeof a === "object" ? a.name : a) : []

        const query = { owner: SHA512(userData.username) }
        userData.account = (userData.account || "all").trim()
        if (userData.account !== "all") query.account = userData.account

        const allTrades = await trades.find(query).toArray()
        allTrades.sort((a, b) => new Date(a.date) - new Date(b.date))

        var totalWins = 0, totalLosses = 0, totalLongs = 0, totalShorts = 0
        var sumWins = 0, sumLosses = 0
        const dailyPnL = {}

        // Core
        allTrades.forEach(trade => {
            var ret = parseFloat(trade.ret) || 0
            if (trade.status === "WIN") { totalWins++; sumWins += Math.abs(ret); ret = Math.abs(ret) }
            if (trade.status === "LOSE") { totalLosses++; sumLosses += Math.abs(ret); ret = -Math.abs(ret) }

            if (trade.type === "LONG") totalLongs++
            if (trade.type === "SHORT") totalShorts++

            const dStr = new Date(trade.date).toLocaleDateString('en-US', { month: 'short', day: 'numeric', timeZone: 'UTC' })
            if (!dailyPnL[dStr]) dailyPnL[dStr] = 0
            dailyPnL[dStr] += ret
        })

        const pnlLabels = []
        const pnlData = []
        var cumulativePnL = 0

        for (const date in dailyPnL) {
            cumulativePnL += dailyPnL[date]
            pnlLabels.push(date)
            pnlData.push(cumulativePnL)
        }

        if (pnlLabels.length === 0) {
            pnlLabels.push(new Date().toLocaleDateString("en-US", { month: "short", day: "numeric", timeZone: "UTC" }))
            pnlData.push(0)
        }

        userData.stats = {
            wins: totalWins,
            losses: totalLosses,
            longs: totalLongs,
            shorts: totalShorts,
            avgWin: totalWins > 0 ? (sumWins / totalWins) : 0,
            avgLoss: totalLosses > 0 ? (sumLosses / totalLosses) : 0,
            pnl: cumulativePnL
        }

        userData.chart = {
            labels: JSON.stringify(pnlLabels),
            data: JSON.stringify(pnlData)
        }

        userData.recentTrades = allTrades.reverse().slice(0, 50)
        const recentTData = userData.recentTrades.map(t => ({
            date: t.date,
            asset: t.asset,
            status: t.status,
            type: t.type,
            ret: t.ret
        }))

        userData.ai = !userData.recentTrades.length ? "No trades data yet to analyze." : await promptAI("trades", accountData.rules || [], accountData.strategies || [], JSON.stringify({
            stats: userData.stats,
            recentTrades: recentTData
        }), recentTData)

        res.render("dashboard", userData)
    })

    web.get("/trades", async (req, res) => {
        // High Validation
        const userData = await dS(req.cookies)
        if (!userData) return res.redirect("/login")

        // Variables
        const accountData = await users.findOne({ hashedUsername: SHA512(userData.username) })
        userData.accountsList = accountData && accountData.accounts ? accountData.accounts.map(a => typeof a === "object" ? a.name : a) : []

        const page = parseInt(req.query.page) || 1
        const limit = 10
        const skip = (page - 1) * limit

        // Core
        const query = { owner: SHA512(userData.username) }
        userData.account = (userData.account || "all").trim()
        if (userData.account !== "all") query.account = userData.account

        userData.tradesList = await trades.find(query).sort({ _id: -1 }).skip(skip).limit(limit).toArray()
        const totalTrades = await trades.countDocuments(query)

        userData.currentPage = page
        userData.totalPages = Math.ceil(totalTrades / limit) || 1
        userData.totalTrades = totalTrades
        res.render("trades", userData)
    })

    web.get("/calendar", async (req, res) => {
        // High Validation
        const userData = await dS(req.cookies)
        if (!userData) return res.redirect("/login")

        // Variables
        const accountData = await users.findOne({ hashedUsername: SHA512(userData.username) })
        userData.accountsList = accountData && accountData.accounts ? accountData.accounts.map(a => typeof a === "object" ? a.name : a) : []

        const query = { owner: SHA512(userData.username) }
        userData.account = (userData.account || "all").trim()
        if (userData.account !== "all") query.account = userData.account

        // Core
        userData.allTrades = await trades.find(query).toArray()
        userData.hideAccountSelect = true
        res.render("calendar", userData)
    })

    web.get("/seasonality-charts", async (req, res) => {
        // Variables
        const userData = await dS(req.cookies)
        if (!userData) return res.redirect("/login")

        // Core
        const accountData = await users.findOne({ hashedUsername: SHA512(userData.username) })
        userData.accountsList = accountData && accountData.accounts ? accountData.accounts.map(a => typeof a === "object" ? a.name : a) : []

        const query = { owner: SHA512(userData.username) }
        userData.account = (userData.account || "all").trim()
        if (userData.account !== "all") query.account = userData.account

        userData.allTrades = await trades.find(query).toArray()
        userData.hideAccountSelect = true
        res.render("seasonality-charts", userData)
    })

    web.get("/api/chart-data/:symbol", async (req, res) => {
        /**
         * ! AUDITED (2026-03-30)
         * ! Symbol (PARAM)
         * ! - If empty, invalidated.
         * ! - If more than 30 characters, invalidated.
         * 
         * ! - Internal (QUERY)
         * ! - If more than 30 characters, invalidated.
         */

        // Variables
        const userData = await dS(req.cookies)
        if (!userData) return res.send("0")
        var { symbol } = req.params
        var { interval } = req.query

        // Validations
        if(!symbol) return res.send("0")
        if (!interval) interval = "1h"
        if(symbol.length > 30) return res.send("0")
        if(interval.length > 30) return res.send("0")

        // Core
        if (symbol === "XAUUSD") symbol = "GC=F"
        else if (symbol.length === 6) symbol = `${symbol}=X`

        try {
            const response = await fetch(`https://query1.finance.yahoo.com/v8/finance/chart/${symbol}?interval=${interval}&range=7d`)
            const data = await response.json()

            if (data && data.chart && data.chart.result) {
                const result = data.chart.result[0]
                const timestamps = result.timestamp
                const quotes = result.indicators.quote[0]

                if (timestamps) {
                    const formatted = timestamps.map((t, i) => ({
                        time: t,
                        open: quotes.open[i],
                        high: quotes.high[i],
                        low: quotes.low[i],
                        close: quotes.close[i]
                    })).filter(p => p.open != null)

                    return res.json(formatted)
                }
            }

            const cryptoSymbol = req.params.symbol.endsWith("USD") ? req.params.symbol + "T" : req.params.symbol
            const binanceInterval = interval === "1d" ? "1d" : (interval.endsWith("h") ? interval : (interval.endsWith("m") ? interval : "1h"))
            const binanceRes = await fetch(`https://api.binance.com/api/v3/klines?symbol=${cryptoSymbol}&interval=${binanceInterval}&limit=500`)
            const bData = await binanceRes.json()

            if (Array.isArray(bData)) {
                const formatted = bData.map(d => ({
                    time: Math.floor(d[0] / 1000),
                    open: parseFloat(d[1]),
                    high: parseFloat(d[2]),
                    low: parseFloat(d[3]),
                    close: parseFloat(d[4])
                }))
                return res.json(formatted)
            }

            res.send("0")
        } catch{
            res.send("0")
        }
    })

    web.get("/settings", async (req, res) => {
        // Variables
        const userData = await dS(req.cookies)
        if (!userData) return res.redirect("/login")

        const accountData = await users.findOne({ hashedUsername: SHA512(userData.username) })
        userData.accountsList = accountData && accountData.accounts ? accountData.accounts.map(a => typeof a === "object" ? a.name : a) : []
        userData.rules = accountData && accountData.rules ? accountData.rules : []

        // Core
        userData.accountsData = []
        if (accountData && accountData.accounts) {
            const allTrades = await trades.find({ owner: SHA512(userData.username) }).toArray()
            userData.accountsData = accountData.accounts.map(acc => {
                // Variables
                const isObj = typeof acc === "object"
                const name = isObj ? acc.name : acc
                const deposit = isObj ? acc.deposit : 0
                var crDate = isObj ? new Date(acc.createdAt) : new Date()
                if (isNaN(crDate)) crDate = new Date()

                const accTrades = allTrades.filter(t => t.account === name)
                var wins = 0, sumWin = 0, losses = 0, sumLoss = 0, pnl = 0

                // Core
                accTrades.forEach((t) => {
                    var ret = parseFloat(t.ret) || 0
                    if (t.status === "WIN") { wins++; sumWin += Math.abs(ret); pnl += Math.abs(ret) }
                    else if (t.status === "LOSE") { losses++; sumLoss += Math.abs(ret); pnl -= Math.abs(ret) }
                })

                const total = wins + losses
                const winrate = total > 0 ? ((wins / total) * 100).toFixed(0) : 0
                const avgWin = wins > 0 ? (sumWin / wins).toFixed(2) : 0
                const avgLoss = losses > 0 ? (sumLoss / losses).toFixed(2) : 0

                const blown = deposit > 0 && (deposit + pnl <= 0)

                return { name, deposit, createdAt: typeof acc === "object" ? crDate.toLocaleDateString() : 'N/A', winrate, avgWin, avgLoss, pnl, blown }
            })
        }

        userData.hideAccountSelect = true
        res.render("settings", userData)
    })

    web.get("/strategies", async (req, res) => {
        // Variables
        const userData = await dS(req.cookies)
        if (!userData) return res.redirect("/login")

        // Core
        const accountData = await users.findOne({ hashedUsername: SHA512(userData.username) })
        userData.accountsList = accountData && accountData.accounts ? accountData.accounts.map(a => typeof a === "object" ? a.name : a) : []
        userData.strategies = accountData && accountData.strategies ? accountData.strategies : []

        userData.hideAccountSelect = true
        res.render("strategies", userData)
    })

    web.get("/strategy-builder", async (req, res) => {
        // Variables
        const userData = await dS(req.cookies)
        if (!userData) return res.redirect("/login")

        // Core
        const accountData = await users.findOne({ hashedUsername: SHA512(userData.username) })
        userData.accountsList = accountData && accountData.accounts ? accountData.accounts.map(a => typeof a === "object" ? a.name : a) : []

        userData.hideAccountSelect = true
        res.render("strategy-builder", userData)
    })

    web.post("/api/ai-strategy-builder", async (req, res) => {
        /**
         * ! AUDITED (2026-03-30)
         * ! Prompt (POST BODY)
         * ! - If prompt is empty, invalidated.
         * ! - If prompt is more than 1500 characters, invalidated.
         */

        // Variables
        const userData = await dS(req.cookies)
        if (!userData) return res.send("0")
        var { prompt } = req.body

        // Variables
        if (!prompt) return res.send("0")
        if(prompt.length > 1500) return res.send("0")
        prompt = filterXSS(prompt)

        // Core
        const accountData = await users.findOne({ hashedUsername: SHA512(userData.username) })
        const systemPrompt = `Prompt rule:
You are an expert quantitative trading strategist. The user will give you a description or an idea for a trading strategy.
You must output a highly detailed, professional strategy broken into EXACTLY three parts, separated by the delimiter "|||".

Part 1: Strategy Name (Max 25 characters, keep it catchy and professional)
Part 2: Short Description (Max 300 characters, summarizing the core concept)
Part 3: Detailed "How It Works" (Max 2500 characters, covering indicators, entry/exit criteria, timeframe, risk management, and market conditions). Format this third part with markdown.

Make sure the total response uses the delimiter "|||" strictly between the three parts. Do not include extra text outside this format.`;

        const recentTrades = (await trades.find({ owner: SHA512(userData.username) }).sort({ _id: -1 }).limit(50).toArray()).map(t => ({
            date: t.date,
            asset: t.asset,
            status: t.status,
            type: t.type
        }))

        const response = await promptAI(systemPrompt, accountData.rules || [], [], prompt, recentTrades)
        res.send(response)
    })

    web.get("/ai", async (req, res) => {
        // Variables
        const userData = await dS(req.cookies)
        if (!userData) return res.redirect("/login")

        // Core
        const accountData = await users.findOne({ hashedUsername: SHA512(userData.username) })
        userData.accountsList = accountData && accountData.accounts ? accountData.accounts.map(a => typeof a === "object" ? a.name : a) : []

        userData.hideAccountSelect = true
        res.render("ai", userData)
    })

    web.post("/api/ai-chat", async (req, res) => {
        /**
         * ! AUDITED (2026-03-30)
         * ! Message (POST BODY)
         * ! - If message is empty, invalidated.
         * ! - If message is more than 1500 characters, invalidated.
         */

        // Variables
        const userData = await dS(req.cookies)
        if (!userData) return res.send("0")
        var { message } = req.body

        // Validations
        if (!message) return res.send("0")
        if(message > 1500) return res.send("0")
        message = filterXSS(message)

        // Core
        const accountData = await users.findOne({ hashedUsername: SHA512(userData.username) })
        const recentTrades = (await trades.find({ owner: SHA512(userData.username) }).sort({ _id: -1 }).limit(50).toArray()).map(t => ({
            date: t.date,
            asset: t.asset,
            status: t.status,
            type: t.type
        }))

        const response = await promptAI("chat", accountData.rules || [], accountData.strategies || [], message, recentTrades)
        res.send(response)
    })

    web.get("/trade/:id", async (req, res) => {
        /**
         * ! AUDITED (2026-03-30)
         * ! ID (POST BODY)
         * ! - If empty, invalidated.
         * ! - If trade data does not exist (we correlate with cookie username to ensure user can't view others trade, only his/her), invalidated.
         */

        // Variables
        const userData = await dS(req.cookies)
        if (!userData) return res.redirect("/login")

        // Validations
        const { id } = req.params

        // Core
        try {
            if(!id) return res.redirect("/dashboard")
            const tradeData = await trades.findOne({
                _id: new ObjectId(id),
                owner: SHA512(userData.username)
            })

            if (!tradeData) return res.redirect("/dashboard")
            const accountData = await users.findOne({ hashedUsername: SHA512(userData.username) })

            const recentTrades = (await trades.find({ owner: SHA512(userData.username) }).sort({ _id: -1 }).limit(50).toArray()).map(t => ({
                date: t.date,
                asset: t.asset,
                status: t.status,
                type: t.type
            }))

            userData.trade = tradeData
            userData.ai = await promptAI("trade", accountData.rules || [], accountData.strategies || [], JSON.stringify(tradeData), recentTrades)
            res.render("trade", userData)
        } catch {
            res.redirect("/dashboard")
        }
    })

    //* Others
    web.use("/{*any}", (req, res) => res.redirect("/"))
    web.listen(port, () => console.log(`TradeTrack is running. Port: ${port}`))
})()