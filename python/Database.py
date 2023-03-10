import configparser

import mysql.connector

config = configparser.ConfigParser()
config.read('config.ini')

class Database:

    def get_user_data(self, username):

        con = mysql.connector.connect(
            host=config['database']['host'],
            user=config['database']['user'],
            password=config['database']['password'],
            database=config['database']['database']
        )

        cursor = con.cursor()
        cursor.execute("SELECT salt, password, role from users where username = %s", (username,))

        return cursor.fetchone()
