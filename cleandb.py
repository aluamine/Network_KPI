from tools.mongo_con import myDB
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-c", "--col", help = "type collection to drop or keep empty to drop all collections", type=str, required=False)
args = parser.parse_args()
collection = args.col
myDB.initialize()

if collection==None:
    #cols = myDB.DATABASE.name.list_collection_names()
    collections = myDB.DATABASE.list_collection_names()
    for collection_name in collections:
        myDB.dropCollection(collection_name)
else: myDB.dropCollection(collection)