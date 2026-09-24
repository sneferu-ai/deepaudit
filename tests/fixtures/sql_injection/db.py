import sqlite3


def search_raw(query):
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS items (name TEXT)")
    cursor.execute("INSERT INTO items VALUES ('alice'), ('bob')")
    cursor.execute(f"SELECT name FROM items WHERE name = '{query}'")
    return cursor.fetchall()
