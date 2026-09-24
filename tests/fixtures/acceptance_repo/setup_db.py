import sqlite3
import os

# Use relative path so it works both in Docker (/repo) and local runner
conn = sqlite3.connect('app.db')
conn.execute('CREATE TABLE IF NOT EXISTS items (name TEXT, description TEXT)')
conn.execute("INSERT INTO items VALUES ('test', 'test item')")
conn.commit()
conn.close()
