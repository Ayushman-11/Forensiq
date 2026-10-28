import asyncio
import json
from motor.motor_asyncio import AsyncIOMotorClient
import os
from bson import json_util

async def export_db():
    uri = "mongodb://localhost:27017"
    db_name = "forensiq"
    out_dir = "mongo_dump_json"
    
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)
        
    client = AsyncIOMotorClient(uri)
    db = client[db_name]
    
    collections = await db.list_collection_names()
    print(f"Found collections: {collections}")
    
    for coll_name in collections:
        print(f"Exporting collection: {coll_name}")
        coll = db[coll_name]
        cursor = coll.find({})
        docs = await cursor.to_list(length=None)
        
        out_file = os.path.join(out_dir, f"{coll_name}.json")
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(json_util.dumps(docs, indent=2))
        print(f"Exported {len(docs)} documents to {out_file}")

if __name__ == "__main__":
    asyncio.run(export_db())
