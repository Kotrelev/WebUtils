import config
import pymysql.cursors
class mysql:
    def local_sql_conn():
        try:
            connection = pymysql.connect(host=config.local_mysqlhost,
                user=config.local_mysqluser,
                password=config.local_mysqlpass,
                db=config.local_mysqldb,
                charset='utf8mb4',
                cursorclass=pymysql.cursors.DictCursor)
            return(connection)
        except Exception as err_message:
            logger.error('Ошибка в функции mysql.local_sql_conn {}'.format(str(err_message)))
        
    # это соединение будет возвращать списки
    def local_sql_conn_l():
        try:
            connection = pymysql.connect(host=config.local_mysqlhost,
                user=config.local_mysqluser,
                password=config.local_mysqlpass,
                db=config.local_mysqldb,
                charset='utf8mb4')
            return(connection)
        except Exception as err_message:
            logger.error('Ошибка в функции mysql.local_sql_conn_l {}'.format(str(err_message)))
            
class ipv4_table:
    def get_ipv4(logger):
        try:
            response = requests.get(config.get_ipv4_api)
            if response.ok and response.content != b'[]':
                return response.json()
            return None
        except Exception as err_message:
            logger.error('Ошибка в функции get_ipv4 {}'.format(str(err_message)))
            return None