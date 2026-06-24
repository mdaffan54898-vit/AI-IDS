from pymongo import MongoClient

client = MongoClient("mongodb://localhost:27017")
db = client["ids_db"]
collection = db["alerts"]

print("Logged Alerts:")
for doc in collection.find():
    print(doc)
    print("---")