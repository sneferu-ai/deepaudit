import sqlite3


def search_raw(query: str):
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM items WHERE name = '{query}'")
    return cursor.fetchall()


def search_safe(query: str):
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM items WHERE name = ?", (query,))
    return cursor.fetchall()
