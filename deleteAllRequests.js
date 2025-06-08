const { MongoClient } = require('mongodb');

// Update these with your actual MongoDB connection details
const uri = 'mongodb://localhost:27017';
const dbName = 'chandraTravelDB'; // Change if your DB name is different

async function deleteAllRequests() {
  const client = new MongoClient(uri, { useUnifiedTopology: true });
  try {
    await client.connect();
    const db = client.db(dbName);
    const requestsCollection = db.collection('requests');
    const result = await requestsCollection.deleteMany({});
    console.log(`Deleted ${result.deletedCount} requests from the database.`);
  } catch (error) {
    console.error('Error deleting requests:', error);
  } finally {
    await client.close();
  }
}

deleteAllRequests(); 