const { MongoClient } = require('mongodb');

// MongoDB Connection URI and Database Name
const uri = "mongodb://localhost:27017"; 
const dbName = "chandraTravelDB"; 

// Helper function to generate a 7-character alphanumeric request ID
function generateAlphanumericId(length) {
    let result = '';
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

async function migrateTo7CharIds() {
    let client;
    try {
        client = new MongoClient(uri, { useNewUrlParser: true, useUnifiedTopology: true });
        await client.connect();
        const db = client.db(dbName);
        const requestsCollection = db.collection('requests');

        console.log(`Connected to MongoDB database: ${dbName}`);

        // Find requests that currently have a 6-character requestId
        const requestsToUpdate = await requestsCollection.find({
            requestId: { $exists: true, $regex: /^[a-zA-Z0-9]{6}$/ }
        }).toArray();

        if (requestsToUpdate.length === 0) {
            console.log('No 6-character requestIds found needing an update to 7 characters. All good!');
            return;
        }

        console.log(`Found ${requestsToUpdate.length} requests with 6-character IDs to update to 7 characters...`);

        for (const request of requestsToUpdate) {
            let newRequestId;
            let isUnique = false;
            while(!isUnique) {
                newRequestId = generateAlphanumericId(7);
                const existingRequest = await requestsCollection.findOne({ requestId: newRequestId });
                if (!existingRequest) {
                    isUnique = true;
                }
            }

            await requestsCollection.updateOne(
                { _id: request._id },
                { $set: { requestId: newRequestId } }
            );
            console.log(`Updated request ${request._id} (old: ${request.requestId}) with new 7-char requestId: ${newRequestId}`);
        }

        console.log('Migration to 7-character alphanumeric requestIds complete.');

    } catch (error) {
        console.error('Error during migration to 7-char IDs:', error);
    } finally {
        if (client) {
            await client.close();
            console.log('MongoDB connection closed.');
        }
    }
}

migrateTo7CharIds(); 