import config
import pymysql.cursors
class mysql:
    def local_sql_conn():
        connection = pymysql.connect(host=config.local_mysqlhost,
            user=config.local_mysqluser,
            password=config.local_mysqlpass,
            db=config.local_mysqldb,
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor)
        return(connection)
        
    # это соединение будет возвращать списки
    def local_sql_conn_l():
        connection = pymysql.connect(host=config.local_mysqlhost,
            user=config.local_mysqluser,
            password=config.local_mysqlpass,
            db=config.local_mysqldb,
            charset='utf8mb4')
        return(connection)