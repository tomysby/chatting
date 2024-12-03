"""
This module contains a Caribou migration.

Migration Name: chat_migration
Migration Version: 20241202132947
"""


def upgrade(connection):
    # add your upgrade step here
    sql = """
            create table chats
            ( id INTEGER PRIMARY KEY AUTOINCREMENT
            , "from" INTEGER REFERENCES users(id)
            , "to" INTEGER REFERENCES users(id)
            , message TEXT
            , created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            ) """
    connection.execute(sql)
    connection.commit()
    pass


def downgrade(connection):
    # add your downgrade step here
    connection.execute('drop table chats')
    pass
