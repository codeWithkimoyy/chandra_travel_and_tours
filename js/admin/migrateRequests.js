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

async function migrateRequests() {
    let client;
    try {
        client = new MongoClient(uri, { useNewUrlParser: true, useUnifiedTopology: true });
        await client.connect();
        const db = client.db(dbName);
        const requestsCollection = db.collection('requests');

        console.log(`Connected to MongoDB database: ${dbName}`);

        // Find requests that do not have a requestId field or have an empty string
        const requestsToUpdate = await requestsCollection.find({
            $or: [
                { requestId: { $exists: false } },
                { requestId: "" }
            ]
        }).toArray();

        if (requestsToUpdate.length === 0) {
            console.log('No requests found needing a new requestId. All good!');
            return;
        }

        console.log(`Found ${requestsToUpdate.length} requests to update...`);

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
            console.log(`Updated request ${request._id} with new requestId: ${newRequestId}`);
        }

        console.log('Migration complete. All requests now have a 7-character alphanumeric requestId.');

    } catch (error) {
        console.error('Error during migration:', error);
    } finally {
        if (client) {
            await client.close();
            console.log('MongoDB connection closed.');
        }
    }
}

migrateRequests(); 