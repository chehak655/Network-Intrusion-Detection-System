from database.db import Database

db = Database()

rows = db.fetch_all()

print()

print("TOTAL RECORDS :", len(rows))

print()

for row in rows:

    print(row)