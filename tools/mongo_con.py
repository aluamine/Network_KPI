import pymongo
from pymongo import monitoring
import tools.constants as CONSTANTS

class myDB(object):
    URI = CONSTANTS.URI
    DATABASE = None
    CLIENT = None

    @staticmethod
    def initialize():
        try:
            myDB.CLIENT = pymongo.MongoClient(myDB.URI)
            myDB.DATABASE = myDB.CLIENT[CONSTANTS.DB_NAME]
            print("connected to ",myDB.DATABASE.name, "database")
        except:
            myDB.CLIENT = None
            print ("Unable to connect to mongodb")

    @staticmethod
    def list_databases():
        print(myDB.CLIENT.list_database_names())

    @staticmethod
    def insert(collection,data):
        myDB.DATABASE[collection].insert_one(data)

    @staticmethod
    def findOne(collection,query, field_to_retreive):
        return myDB.DATABASE[collection].find_one(query, field_to_retreive)

    @staticmethod
    def updateOne(collection,query, update):
        return myDB.DATABASE[collection].update_one(query,update)

    @staticmethod
    def dropCollection(collection):
        myDB.DATABASE[collection].drop()
        print(collection," dropped")
