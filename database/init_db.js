const { Client } = require('pg');

const passwordsToTry = ['postgres', 'admin', 'root', 'password', '', 'rog'];
const targetUser = 'nhiadmin';
const targetPass = 'CHANGE_ME_strong_password_here';
const targetDb = 'nhishield';

async function initDb() {
    let client;
    let connected = false;

    // 1. Try connecting with various common passwords
    for (const pass of passwordsToTry) {
        const url = `postgresql://postgres:${pass}@localhost:5432/postgres`;
        client = new Client({ connectionString: url });
        try {
            await client.connect();
            console.log(`Connected successfully with password: '${pass}'`);
            connected = true;
            break;
        } catch (err) {
            // connection failed, try next
        }
    }

    if (!connected) {
        // Try connecting with Windows Username
        try {
            client = new Client({ connectionString: `postgresql://rog@localhost:5432/postgres` });
            await client.connect();
            console.log(`Connected successfully without password using Windows username 'rog'`);
            connected = true;
        } catch (e) { }
    }

    if (!connected) {
        console.error("Failed to connect to local PostgreSQL. Check if it requires a specific password.");
        process.exit(1);
    }

    // 2. Create the user if it doesn't exist
    try {
        await client.query(`CREATE USER ${targetUser} WITH PASSWORD '${targetPass}';`);
        console.log(`User ${targetUser} created.`);
    } catch (err) {
        if (err.code === '42710') {
            console.log(`User ${targetUser} already exists.`);
        } else {
            console.error("Error creating user:", err.message);
        }
    }

    // 3. Create the database if it doesn't exist
    try {
        await client.query(`CREATE DATABASE ${targetDb} OWNER ${targetUser};`);
        console.log(`Database ${targetDb} created.`);
    } catch (err) {
        if (err.code === '42P04') {
            console.log(`Database ${targetDb} already exists.`);
        } else {
            console.error("Error creating database:", err.message);
        }
    }

    // 4. Grant privileges
    try {
        await client.query(`GRANT ALL PRIVILEGES ON DATABASE ${targetDb} TO ${targetUser};`);
        console.log(`Granted privileges on ${targetDb} to ${targetUser}.`);
    } catch (err) {
        console.error("Error granting privileges:", err.message);
    }

    await client.end();
    console.log("Database Initialization Complete.");
}

initDb();
