import mysql.connector

from config import (
    DB_HOST,
    DB_PORT,
    DB_USER,
    DB_PASSWORD,
    DB_NAME
)


def get_connection():
    return mysql.connector.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME
    )


if __name__ == "__main__":

    try:
        connection = get_connection()

        print("[+] MySQL connection successful")

        cursor = connection.cursor()

        cursor.execute("SELECT DATABASE()")

        database = cursor.fetchone()[0]

        print(f"[+] Database: {database}")

        cursor.close()
        connection.close()

    except mysql.connector.Error as error:

        print("[!] MySQL connection failed")
        print(error)