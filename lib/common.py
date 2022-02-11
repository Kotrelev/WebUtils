import config, requests, ipaddress
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
                               'gateway': gateway,
                               'loopback': unnums[gw]}
                for host in gw_iface.network:
                    shost = str(host)
                    if (not ipv4_d[shost]['contract'] 
                        and not ipv4_d[shost]['name']
                        and not ipv4_d[shost]['address']):
                        ipaddresses[gateway]['ip'].append(shost)
                        
                    if len(ipaddresses[gateway]['ip']) == amount:
                        return 'OK', ipaddresses

            msg = 'Нет свободных/недостаточно IP для узла {} в ipv4 ({})'.format(node, unnums)
            return msg, None
            
        except Exception as err_message:
            logger.error('Ошибка в функции ipv4_table.get_free_ip {}'.format(str(err_message)))