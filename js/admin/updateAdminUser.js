const { MongoClient, ObjectId } = require('mongodb');

const uri = "mongodb://localhost:27017";
const dbName = "chandraTravelDB";
const adminEmailToUpdate = 'janely193.jc@gmail.com'; // ** IMPORTANT: Replace with your actual admin email **

async function updateAdminUser() {
    const client = new MongoClient(uri, { useNewUrlParser: true, useUnifiedTopology: true });

    try {
        await client.connect();
        const db = client.db(dbName);
        const usersCollection = db.collection('users');

        console.log(`Attempting to update user: ${adminEmailToUpdate} to admin.`);

        const result = await usersCollection.updateOne(
            { email: adminEmailToUpdate },
            { $set: { userType: 'admin' } }
        );

        if (result.matchedCount === 0) {
            console.warn(`User with email ${adminEmailToUpdate} not found.`);
        } else if (result.modifiedCount === 0) {
            console.log(`User ${adminEmailToUpdate} is already an admin or no change was needed.`);
        } else {
            console.log(`SUCCESS: User ${adminEmailToUpdate} successfully updated to admin!`);
        }
    } catch (error) {
        console.error('Error updating admin user:', error);
    } finally {
        await client.close();
        console.log('MongoDB client closed.');
    }
}

updateAdminUser(); 