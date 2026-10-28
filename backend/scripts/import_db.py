import asyncio
import json
from motor.motor_asyncio import AsyncIOMotorClient
import os
from bson import json_util

async def import_db():
    uri = "mongodb://localhost:27017"
    db_name = "forensiq"
    in_dir = "mongo_dump_json"
    
    if not os.path.exists(in_dir):
        print(f"Directory {in_dir} not found. Nothing to import.")
        return
        
    client = AsyncIOMotorClient(uri)
    db = client[db_name]
    
    for filename in os.listdir(in_dir):
        if filename.endswith(".json"):
            coll_name = filename[:-5]
            print(f"Importing collection: {coll_name}")
            
            in_file = os.path.join(in_dir, filename)
            with open(in_file, "r", encoding="utf-8") as f:
                docs = json_util.loads(f.read())
            
            if docs:
                coll = db[coll_name]
                # Drop existing data if you want a clean import
                await coll.drop()
                await coll.insert_many(docs)
                print(f"Imported {len(docs)} documents to {coll_name}")
            else:
                print(f"No documents found in {filename}")

if __name__ == "__main__":
    asyncio.run(import_db())
