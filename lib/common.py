import config, requests, ipaddress, string, secrets
import pymysql.cursors
from datetime import datetime

class common:
    def id_generator(size, logger):
        try:
            alphabet = string.ascii_letters + string.digits
            sid = ''.join(secrets.choice(alphabet) for i in range(int(size)))
            return sid
        except Exception as err_message:
            logger.error('Ошибка в функции common.id_generator {}'.format(str(err_message)))

class common_mysql:
    def local_sql_conn(logger):
        # это соединение будет возвращать словари
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
    
    def local_sql_conn_l(logger):
        # это соединение будет возвращать списки
        try:
            connection = pymysql.connect(host=config.local_mysqlhost,
                user=config.local_mysqluser,
                password=config.local_mysqlpass,
                db=config.local_mysqldb,
                charset='utf8mb4')
            return(connection)
        except Exception as err_message:
            logger.error('Ошибка в функции mysql.local_sql_conn_l {}'.format(str(err_message)))
            
    def sql_set_session(sid, storage, date, logger):
        try:
            logger.warning('TEMP STORAGE {}'.format(storage))
            connection = common_mysql.local_sql_conn(logger)
            req = ("insert into web_utils_session(sid, storage, date)" 
                   "values ('{}', '{}', '{}')".format(sid, storage, date))
            with connection.cursor() as cursor:
                cursor.execute(req)
            connection.commit()
            connection.close()
        except Exception as err_message:
            logger.error('Ошибка в функции sql_set_session {}'.format(str(err_message)))
        
    def sql_upd_session(sid, storage, logger):
        try:
            connection = common_mysql.local_sql_conn(logger)
            req = ("update web_utils_session set storage = '{}' where sid = '{}';".format(storage.replace("'", '***'), sid))
            logger.info('UPD REQ: {}'.format(req))
            with connection.cursor() as cursor:
                cursor.execute(req)
            connection.commit()
            connection.close()
        except Exception as err_message:
            logger.error('Ошибка в функции sql_upd_session {}'.format(str(err_message)))
        
    def sql_get_session(sid, logger):
        try:
            connection = common_mysql.local_sql_conn(logger)
            req = ('SELECT * from web_utils_session where sid = "{}"'.format(sid))
            with connection.cursor() as cursor:
                cursor.execute(req)
                session_vars = cursor.fetchall()
            connection.close()
            return session_vars
        except Exception as err_message:
            logger.error('Ошибка в функции sql_get_session {}'.format(str(err_message)))
        
    def sql_del_session(sid, logger):
        try:
            connection = common_mysql.local_sql_conn(logger)
            req = ('DELETE from web_utils_session where sid = "{}"'.format(sid))
            with connection.cursor() as cursor:
                cursor.execute(req)
            connection.commit()
            connection.close()
        except Exception as err_message:
            logger.error('Ошибка в функции sql_get_session {}'.format(str(err_message)))
            
    def sql_clean_sessions(logger):
        try:
            connection = common_mysql.local_sql_conn(logger)
            req = ('SELECT * from web_utils_session;')
            with connection.cursor() as cursor:
                cursor.execute(req)
                session_vars = cursor.fetchall()
            if session_vars:
                for session in session_vars:
                    if session['date'] != datetime.now().date():
                        req = ('DELETE from web_utils_session where sid = "{}"'.format(session['sid']))
                        with connection.cursor() as cursor:
                            cursor.execute(req)
                        connection.commit()
            connection.close()
        except Exception as err_message:
            logger.error('Ошибка в функции sql_clean_sessions {}'.format(str(err_message)))
            
            
            
class ipv4_table:
    def get_ipv4(logger):
        try:
            response = requests.get(config.get_ipv4_api)
            if response.ok and response.content != b'[]':
                return response.json()
            return None
        except Exception as err_message:
            logger.error('Ошибка в функции ipv4_table.get_ipv4 {}'.format(str(err_message)))
        
    def get_free_ip(ipv4, node, amount, logger):
        try:
            # Получаем из ipv4 список доступных сетей вида {'91.197.194.1/24': 'lo0.11'}
            unnums = {r['ip']+'/'+str(r['net']): r['address'].split('- ')[2]
                      for r in ipv4 
                      if r['name'] == node 
                      and r['contract'] == 'GW' 
                      and 'auto - unnumbered - ' in r['address']}
            if not unnums:
                msg = 'Не нашел сетей для узла {} в ipv4'.format(node)
                return msg, None
            
            # Ищем свободный IP
            ipv4_d = {r['ip']: r for r in ipv4}
            for gw in unnums:
                gw_iface = ipaddress.ip_interface(gw)
                gateway = str(gw_iface.ip)
                ipaddresses = {'ip': [], 
                               'mask': str(gw_iface.netmask),
                               'mask_bits': str(gw_iface.netmask.max_prefixlen),
                               'gateway': gateway,
                               'loopback': unnums[gw]}
                for host in gw_iface.network:
                    shost = str(host)
                    if (not ipv4_d[shost]['contract'] 
                        and not ipv4_d[shost]['name']
                        and not ipv4_d[shost]['address']):
                        ipaddresses['ip'].append(shost)
                        
                    if len(ipaddresses['ip']) == amount:
                        return 'OK', ipaddresses

            msg = 'Нет свободных/недостаточно IP для узла {} в ipv4 ({})'.format(node, unnums)
            return msg, None
            
        except Exception as err_message:
            logger.error('Ошибка в функции ipv4_table.get_free_ip {}'.format(str(err_message)))