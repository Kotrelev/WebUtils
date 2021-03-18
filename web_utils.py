# -*- coding: utf-8 -*-
#!/usr/bin/python3
#Python 3.7.3

import config, ipaddress, logging, webbrowser, re, json
import urllib, subprocess, requests, secrets, string, smtplib
import pymysql.cursors

from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler
from pyzabbix import ZabbixAPI
from flask import Flask
from flask import request
from flask import redirect
from flask import render_template
from flask import flash
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate

web_utils_app = Flask(__name__)

logger = logging.getLogger('my_logger')
handler = RotatingFileHandler(config.log_file, maxBytes=100000, backupCount=5)
formatter = logging.Formatter(
        "[%(asctime)s] {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s")
handler.setLevel(logging.INFO)
handler.setFormatter(formatter)
logger.setLevel(logging.INFO)
logger.addHandler(handler)

states = {0: '<font color="#ff0000">Suspended</font>', 1: '<font color="#009900">Active</font>'}

# это соединение будет возвращать словари
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

def hostid_by_ip(zabbix_conn, ip):
    try:
        host_iface = zabbix_conn.hostinterface.get(output=['hostid', 'ip'], filter={'ip': ip})
        if not host_iface:
            return None
        return host_iface[0]['hostid']
    except Exception as err_message:
        logger.error('Ошибка в функции hostid_by_ip {}'.format(str(err_message)))
        return None
        
# achtung! эта функция может вернуть больше одного id
def hostid_by_name(zabbix_conn, name, logger):
    try:
        dev_arr = zabbix_conn.host.get(search={'name': name}, output=['hostid','host','name'])
        if not dev_arr:
            dev_arr = zabbix_conn.host.get(search={'host': name}, output=['hostid','host','name'])
            if not dev_arr:
                return None
        return dev_arr # [{'hostid': '10934', 'host': 'BMor18-cs2', 'name': 'BMor18-cs2'}]
    except Exception as err_message:
        logger.error('Ошибка в функции hostid_by_name {}'.format(str(err_message)))
        return None
        
def hostname_by_id(zabbix_conn, hostid):
    try:
        dev_arr = zabbix_conn.host.get(filter={'hostid': hostid}, output=['hostid','host','name'])
        if not dev_arr:
            return None
        return dev_arr
    except Exception as err_message:
        logger.error('Ошибка в функции hostname_by_id {}'.format(str(err_message)))
        return None
        
def ip_by_hostname(hostname, logger):
    try:
        zabbix_conn = ZabbixAPI(config.zabbix_link, user=config.zabbix_user, password=config.zabbix_pass)
        interfaces = zabbix_conn.hostinterface.get()
        hid = hostid_by_name(zabbix_conn, hostname, logger)
        zabbix_conn.user.logout()
        if not hid: return None
        for hostid in hid:
            # filter incomlite names such as 'Pirog17' instead of 'Pirog17-cr1'
            if (hostid['host'].lower() == hostname.lower() or 
                hostid['name'].lower() == hostname.lower()):
                for interface in interfaces:
                    if interface['hostid'] == hostid['hostid']:
                        return interface['ip']
        return None
    except Exception as err_message:
        logger.error('Ошибка в функции ip_by_hostname {}'.format(str(err_message)))
        return None
        
def mapid_by_hostid(zabbix_conn, hostid):
    try:
        all_elements_on_maps = zabbix_conn.map.get(selectSelements="extend", output='selements')
        map_arr = []
        for map in all_elements_on_maps:
            for selement in map['selements']:
                try: 
                    selement['elements'][0]['hostid']
                except: 
                    continue
                else:
                    if selement['elements'][0]['hostid'] == hostid:
                        map_arr.append(selement['sysmapid'])
        return map_arr  # list of map ids example: [1,2,3]
    except Exception as err_message:
        logger.error('Ошибка в функции mapid_by_hostid {}'.format(str(err_message)))
        
def mapname_by_mapid(zabbix_conn, mapid):
    try:
        map_params = zabbix_conn.map.get(sysmapids=mapid)
    except:
        return 'Unknown'
    return map_params[0]['name']    # example: 'Kantemir4'
        
def get_email_by_contract(contract, logger):
    try:
        response = requests.get(config.get_contract_api+contract)
        if response.ok and response.content != b'[]':
            return list({row['email'] for row in response.json()})
        return None
    except Exception as err_message:
        logger.error('Ошибка в функции get_email_by_contract {}'.format(str(err_message)))
        return None
        
### INVENTORY FUNCTIONS
# уникальная модель с макс датой за последний год
def sql_dynamic_month(connection, model):
    try:
        req = ('SELECT DISTINCT '
        ' FIRST_VALUE(date) OVER (PARTITION BY model, MONTH(date), YEAR(date) ORDER BY date desc ) as date,'
        ' FIRST_VALUE(quantity) OVER (PARTITION BY model, MONTH(date), YEAR(date) ORDER BY date desc ) as quantity'
        ' FROM InventoryDynamic WHERE model = \"{}\" and date > DATE_SUB(NOW(),INTERVAL 1 YEAR);'.format(model))
        with connection.cursor() as cursor:
            cursor.execute(req)
            dynamic = cursor.fetchall()
        return dynamic
    except Exception as err_message:
        logger.error('Ошибка в функции sql_dynamic_month {}'.format(str(err_message)))
        
# уникальные модели
def sql_dynamic_models(connection):
    try:
        req = ('select type, vendor, model from InventoryDynamic GROUP BY model;')
        with connection.cursor() as cursor:
            cursor.execute(req)
            dynamic = cursor.fetchall()
        return dynamic
    except Exception as err_message:
        logger.error('Ошибка в функции sql_dynamic_models {}'.format(str(err_message)))

# берем серийник, возвращаем запись из Inventory, последнюю запись из Vars и все записи из Inventory+Vars
def sql_inventory_serial(connection, serial):
    try:
        req_inv = ('select * from Inventory where serial = \'{}\';'.format(serial))
        req_vars = ('select * from InventoryVars where date=(select MAX(date) from InventoryVars where serial = \'{}\') and serial = \'{}\';'.format(serial, serial))
        # Есть идея выдавать инвентарные данные и последние переменные одной строкой.
        #req = ('SELECT * FROM Inventory, InventoryVars'
        #       ' WHERE Inventory.serial = InventoryVars.serial'
        #       ' and date=(select MAX(date) from InventoryVars where InventoryVars.serial = \'{}\')'
        #       ' and Inventory.serial = \'{}\';'.format(serial, serial))
        
        #req3 = ('select * from InventoryVars where serial = \'{}\';'.format(serial))
        req_history = ('SELECT * FROM Inventory, InventoryVars'
               ' WHERE Inventory.serial = InventoryVars.serial'
               ' and Inventory.serial = \'{}\';'.format(serial))
        cursor = connection.cursor()
        cursor.execute(req_inv)
        inventory = cursor.fetchall()
        if not inventory:
            cursor.close()
            return None, None, None
        # tuple to list и заодно уберем лишний индекс
        inventory = list(inventory[0])
        # подменяем код состояния текстом.
        inventory[6] = states[inventory[6]]
        cursor.execute(req_vars)
        inventory_vars = cursor.fetchall()
        cursor.execute(req_history)
        inventory_vars_history = cursor.fetchall()
        # tuple >> list
        inventory_vars_history = [list(line) for line in inventory_vars_history]
        # подменяем коды состояний текстом
        for x in range(len(inventory_vars_history)):
            inventory_vars_history[x][6] = states[inventory_vars_history[x][6]]
        cursor.close()
        return inventory, inventory_vars[0], inventory_vars_history
    except Exception as err_message:
        logger.error('Ошибка в функции sql_inventory_serial: {}'.format(str(err_message)))
        

# берем имя/IP, возвращаем запись из Inventory, последнюю запись из Vars и все записи из Inventory+Vars
def sql_inventory_ipname(connection, ipname):
    try:
        ipaddress.ip_address(ipname)
    # не нашли ип, видимо это имя. Имя ищем через "like" чтобы можно было искать по части имени
    except:
        vars_req = ('select * from InventoryVars '
                    ' where date=(select MAX(date) from InventoryVars where name like "%{}%")'
                    ' and name like "%{}%";'.format(ipname, ipname))
        # тут берем самые новые записи для уникальных серийных по указанному имени
        hist_req = ('SELECT * FROM Inventory, InventoryVars'
                    ' WHERE Inventory.serial = InventoryVars.serial'
                    ' and date=(select MAX(date) from InventoryVars where InventoryVars.serial = Inventory.serial)'
                    ' and InventoryVars.name like "%{}%";'.format(ipname))
    # нашли ип
    else:
        vars_req = ('select * from InventoryVars '
                    ' where date=(select MAX(date) from InventoryVars where ip = "{}")'
                    ' and ip = "{}";'.format(ipname, ipname))
        # тут берем самые новые записи для уникальных серийных по указанному ip
        hist_req = ('SELECT * FROM Inventory, InventoryVars'
                    ' WHERE Inventory.serial = InventoryVars.serial'
                    ' and date=(select MAX(date) from InventoryVars where InventoryVars.serial = Inventory.serial)'
                    ' and InventoryVars.ip = "{}";'.format(ipname))
    try:
        cursor = connection.cursor()
        cursor.execute(vars_req)
        last_vars = cursor.fetchall()
        if not last_vars:
            cursor.close()
            return None, None, None
        # для самого нового девайса в vars запросим инфу из Inventory
        inv_req = ('select * from Inventory where serial = "{}";'.format(last_vars[0][0]))
        cursor.execute(inv_req)
        inventory = cursor.fetchall()
        inventory = list(inventory[0])
        inventory[6] = states[inventory[6]]
        cursor.execute(hist_req)
        inventory_vars_history = cursor.fetchall()
        inventory_vars_history = [list(line) for line in inventory_vars_history]
        for x in range(len(inventory_vars_history)):
            url = 'https://devnet.spb.avantel.ru/inventory_serial_{}'.format(
                                urllib.parse.quote(inventory_vars_history[x][0].replace('/','slash'), safe=''))
            model_url = '<a href={}>{}</a>'.format(url, inventory_vars_history[x][0])
            inventory_vars_history[x][0] = model_url
            inventory_vars_history[x][6] = states[inventory_vars_history[x][6]]
        cursor.close()
        return inventory, last_vars[0], inventory_vars_history
    except Exception as err_message:
        logger.error('Ошибка в функции sql_inventory_ipname: {}'.format(str(err_message)))
        
# берет дату и кол-во месяцев (m), возвращает имя месяца.год для даты минус m
def month_back(date, m):
    for month in range(0, m):
        date = date - timedelta(days = date.day)
    return(date.strftime('%b.%y'))
        
    
# уникальные серийники с макс. датой по ip
def sql_many_ip(connection, ip):
    try:
        many_ip_arr = []
        # уникальные серийники с макс. датой по ip
        req = ('SELECT DISTINCT'
               ' serial,'
               ' FIRST_VALUE(date) OVER (PARTITION BY ip, MONTH(date), YEAR(date) ORDER BY date desc ) as date'
               ' FROM InventoryVars where ip = \'{}\';'.format(ip))
        with connection.cursor() as cursor:
            cursor.execute(req)
            serials = cursor.fetchall()
            for serial in serials:
                # собираем в одну строку данные из инвентори и варс
                req2 = ('SELECT * FROM Inventory, InventoryVars '
                        ' WHERE Inventory.serial = InventoryVars.serial'
                        ' and date=(select MAX(date) from InventoryVars where InventoryVars.serial = \"{}\")'
                        ' and Inventory.serial = \"{}\";'.format(serial[0], serial[0])
                        )
                cursor.execute(req2)
                data = cursor.fetchall()
                many_ip_arr.append(data[0])
        return many_ip_arr
    except Exception as err_message:
        logger.error('Ошибка в функции sql_dynamic_models {}'.format(str(err_message)))
    
# inventory + vars по типу/вендору/модели
def sql_inventory_vmt(connection, req, vmt):
    try:
        dev_req = ('SELECT * FROM Inventory, InventoryVars'
            ' WHERE Inventory.serial = InventoryVars.serial'
            ' and date=(select MAX(date) from InventoryVars where InventoryVars.serial = Inventory.serial)'
            ' and Inventory.{} = "{}";'.format(vmt, req))
        cursor = connection.cursor()
        cursor.execute(dev_req)
        dev_arr = cursor.fetchall()
        if not dev_arr:
            cursor.close()
            return None
        dev_arr = [list(line) for line in dev_arr]
        for x in range(len(dev_arr)):
            url = 'https://devnet.spb.avantel.ru/inventory_serial_{}'.format(
                                        urllib.parse.quote(dev_arr[x][0].replace('/','slash'), safe=''))
            model_url = '<a href={}>{}</a>'.format(url, dev_arr[x][0])
            
            dev_arr[x][0] = model_url
            dev_arr[x][6] = states[dev_arr[x][6]]
        cursor.close()
        return dev_arr
    except Exception as err_message:
        logger.error('Ошибка в функции sql_inventory_vmt: {}'.format(str(err_message)))
        
# inventory suspended
def sql_inventory_suspended(connection):
    try:
        dev_req = ('SELECT * FROM Inventory WHERE monitored = "0";')
        cursor = connection.cursor()
        cursor.execute(dev_req)
        dev_arr = cursor.fetchall()
        if not dev_arr:
            cursor.close()
            return None
        dev_arr = [list(line) for line in dev_arr]
        for x in range(len(dev_arr)):
            url = 'https://devnet.spb.avantel.ru/inventory_serial_{}'.format(
                                        urllib.parse.quote(dev_arr[x][0].replace('/','slash'), safe=''))
            model_url = '<a href={}>{}</a>'.format(url, dev_arr[x][0])
            
            dev_arr[x][0] = model_url
            dev_arr[x][6] = states[dev_arr[x][6]]
        cursor.close()
        return dev_arr
    except Exception as err_message:
        logger.error('Ошибка в функции sql_inventory_suspended: {}'.format(str(err_message)))
        
        
### INVENTORY FUNCTIONS END
     
def getSysObjectID(ip, community, logger):
    try:
        proc = subprocess.Popen("/bin/snmpwalk -Ov -t 2 -v1 -c {} {} 1.3.6.1.2.1.1.2".format(community, ip),
                                stdout=subprocess.PIPE,shell=True)
        (out,err) = proc.communicate()
        if out:
            return out.decode('utf-8').strip('OID: ').strip('\n')
        return None
    except Exception as err_message:
        logger.error('{}: Ошибка в функции getSysObjectID {}'.format(ip, str(err_message)))
        
def getSNMPstuff(ip, community, oid, logger):
    try:
        proc = subprocess.Popen(
            "/bin/snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
            stdout=subprocess.PIPE,shell=True)
        (out,err) = proc.communicate()
        if out:
            return out.decode('utf-8')
        return None
    except Exception as err_message:
        logger.error('{}: Ошибка в функции getSNMPstuff {}'.format(ip, str(err_message)))
    
def sql_set_session(sid, storage, date):
    try:
        connection = local_sql_conn()
        req = ("insert into web_utils_session(sid, storage, date)" 
               "values ('{}', '{}', '{}')".format(sid, storage, date))
        with connection.cursor() as cursor:
            cursor.execute(req)
        connection.commit()
        connection.close()
    except Exception as err_message:
        logger.error('Ошибка в функции sql_set_session {}'.format(str(err_message)))
    
def sql_upd_session(sid, storage):
    try:
        connection = local_sql_conn()
        req = ("update web_utils_session set storage = '{}' where sid = '{}';".format(storage.replace("'", '***'), sid))
        logger.info('UPD REQ: {}'.format(req))
        with connection.cursor() as cursor:
            cursor.execute(req)
        connection.commit()
        connection.close()
    except Exception as err_message:
        logger.error('Ошибка в функции sql_upd_session {}'.format(str(err_message)))
    
def sql_get_session(sid):
    try:
        connection = local_sql_conn()
        req = ('SELECT * from web_utils_session where sid = "{}"'.format(sid))
        with connection.cursor() as cursor:
            cursor.execute(req)
            session_vars = cursor.fetchall()
        connection.close()
        return session_vars
    except Exception as err_message:
        logger.error('Ошибка в функции sql_get_session {}'.format(str(err_message)))
    
def sql_del_session(sid):
    try:
        connection = local_sql_conn()
        req = ('DELETE from web_utils_session where sid = "{}"'.format(sid))
        with connection.cursor() as cursor:
            cursor.execute(req)
        connection.commit()
        connection.close()
    except Exception as err_message:
        logger.error('Ошибка в функции sql_get_session {}'.format(str(err_message)))
        
def sql_clean_sessions():
    try:
        connection = local_sql_conn()
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
    
def sql_add_notification_history(nid, ndate, wdate, subject, 
                                 addr, devs, emails, body, logger):
    try:
        connection = local_sql_conn()
        req = ("INSERT into webutils_notif_history"
               "(id, notif_date, works_date, subject, address, devices, emails, body) values "
               "('{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}')".format(nid, ndate, wdate, 
                                                                   subject, addr, devs, 
                                                                   emails, body))
        with connection.cursor() as cursor:
            cursor.execute(req)
        connection.commit()
        connection.close()
    except Exception as err_message:
        logger.error('Ошибка в функции sql_add_notification_history {}'.format(str(err_message)))
        
def sql_get_notification_history():
    try:
        table = {}
        connection = local_sql_conn()
        req = ("select id, notif_date, works_date from webutils_notif_history group by id limit 25")
        with connection.cursor() as cursor:
            cursor.execute(req)
            nfs = cursor.fetchall()
            for x in range(len(nfs)):
                nid = nfs[x]['id']
                table[nid] = {}
                table[nid]['notif_date'] = nfs[x]['notif_date']
                table[nid]['works_date'] = nfs[x]['works_date']
                req = ("select * from webutils_notif_history where id = '{}'".format(nid))
                cursor.execute(req)
                notification = cursor.fetchall()
                table[nid]['devices'] = ', '.join(set(n['devices'] for n in notification))
                table[nid]['address'] = ', '.join(set(n['address'] for n in notification))
        connection.close()
        return table
    except Exception as err_message:
        logger.error('Ошибка в функции sql_get_notification_history {}'.format(str(err_message)))
    
def sql_get_notification_history_msg(msgid):
    try:
        connection = local_sql_conn()
        req = ("select * from webutils_notif_history where id = '{}'".format(msgid))
        with connection.cursor() as cursor:
            cursor.execute(req)
            notification_history_msg = cursor.fetchall()
        connection.close()
        return notification_history_msg
    except Exception as err_message:
        logger.error('Ошибка в функции sql_get_notification_history_msg {}'.format(str(err_message)))
    
def client_notification_get_emails(devices_arr, contract_dict, logger):
    
    devices_arr = list(set(devices_arr))
    all_devices_arr = []
    #contract_dict = {ip: {'name': hostname, 
    #                      'ip': ip,
    #                      'address': '',
    #                      'uplink': '',
    #                      'cont_num': '', 
    #                      'unrecognized': [], 
    #                      'alive': 0, 
    #                      'contracts': {}}
    #                }
    
    # в devices_arr будем записывать все девайсы в цепочке 
    while devices_arr != []:
        try:
            # берем первый ip из списка на обработку
            ip = devices_arr[0]
            if ip in all_devices_arr:
                # Уже видели девайс, пропускаем
                devices_arr.remove(ip)
                continue
            # в all_devices_arr записываем тоже что и в devices_arr но отсюда девайсы не будем удалять после обработки
            all_devices_arr.append(ip)
            
            # собираем getSysObjectID из за mikrotik RB260 у которых дискрипшны прям в названиях интерфейсов. 
            # Заодно проверяем доступность железки.
            sysobjectid = getSysObjectID(ip, config.community, logger)
            if not sysobjectid:
                devices_arr.remove(ip)
                contract_dict[ip]['alive'] = 0
                continue
            else:
                contract_dict[ip]['alive'] = 1
                if sysobjectid == 'iso.3.6.1.4.1.14988.2':
                    descoid = '1.3.6.1.2.1.31.1.1.1.1'
                else: descoid = '1.3.6.1.2.1.31.1.1.1.18'
            
            # собираем дескрипшны
            descs = getSNMPstuff(ip, config.community, descoid, logger)
            if not descs: 
                logger.error('{}: Не нашел подписей на портах'.format(ip))
                continue
            descs_arr = [x.strip('STRING: ').strip('"') for x in descs.split('\n')]
            for desc in descs_arr:
                if desc == "": continue
                # тут мачим договор. 888 это тестовый договор.
                contract = re.search('(\d{4}-\d{2})|(\d{5})|888', desc)
                # мачим даунлинк
                downlink = re.search('([a-zA-Z0-9\-]+-(as|ds|cs|dr)\d+)', desc)
                # если договор уже видели, игнорим его
                if contract and contract.group() in contract_dict[ip]['contracts']:
                    continue
                elif contract and 'OFF' not in desc:
                    emails = get_email_by_contract(contract.group(), logger)
                    if emails:
                        contract_dict[ip]['contracts'][contract.group()] = ', '.join(emails)
                    else:
                        contract_dict[ip]['unrecognized'].append(desc)
                elif downlink:
                    if 'UP' in desc or 'U_' in desc:
                        continue
                    else:
                        ipx = ip_by_hostname(downlink.group(1), logger)
                        # loop detection
                        if ipx and ipx in all_devices_arr:
                            continue
                        elif ipx and ipx not in all_devices_arr:
                            logger.info('DEV_ARRR {} {}'.format(ipx, devices_arr))
                            devices_arr.append(ipx)
                            contract_dict[ipx] = {'name': downlink.group(1),
                                                  'ip': ipx,
                                                  'address': '',
                                                  'uplink': contract_dict[ip]['name'],
                                                  'cont_num': '',
                                                  'unrecognized': [],
                                                  'alive': 0,
                                                  'contracts': {}}
                        else:
                            contract_dict[ip]['unrecognized'].append(desc)
                else:
                    contract_dict[ip]['unrecognized'].append(desc)
            contract_dict[ip]['unrecognized'] = ', '.join(ds for ds in contract_dict[ip]['unrecognized'])
            # если договоров нет, то ставим "заглушку" чтобы в таблице дырок небыло
            if len(contract_dict[ip]['contracts']) == 0:
                contract_dict[ip]['contracts'][''] = ''
            contract_dict[ip]['cont_num'] = str(len(contract_dict[ip]['contracts']))
                
            devices_arr.remove(ip)
        except Exception as err_message:
            logger.error('Ошибка в функции client_notification_get_emails {}: {}'.format(ip,str(err_message)))
            return str(err_message)
    
    logger.info(str(contract_dict))
    return contract_dict
    
def get_address_zabbix_host(contract_dict, logger):
    try:
        zabbix_conn = ZabbixAPI(config.zabbix_link, 
                                user=config.zabbix_user, 
                                password=config.zabbix_pass)
        for dev in contract_dict:
            dev_arr = zabbix_conn.host.get(filter={'host': contract_dict[dev]['name']}, 
                                           output=['host', 'name', 'inventory'], 
                                           selectInventory=['inventory_mode', 'site_address_a'])
            if not dev_arr: continue
            contract_dict[dev]['hostid'] = dev_arr[0]['hostid']
            contract_dict[dev]['inventory'] = dev_arr[0]['inventory']['inventory_mode']
            # проверим не выключена ли инвентаризация у девайса:
            if dev_arr[0]['inventory']['inventory_mode'] == '-1':
                # включаем
                inv_on = zabbix_conn.host.update(hostid=dev_arr[0]['hostid'], 
                                                 inventory_mode = 0)
                if inv_on: 
                    logger.info('Turned on inventory for {}'.format(dev_arr[0]['host']))
                    contract_dict[dev]['inventory'] == '0'
                else:
                    logger.warning('{}: failed zabbix inventory activation'.format(dev))
                continue
            if 'site_address_a' in dev_arr[0]['inventory']:
                contract_dict[dev]['address'] = dev_arr[0]['inventory']['site_address_a']
        zabbix_conn.user.logout()
        return contract_dict
    except Exception as err_message:
        logger.error('Ошибка в функции get_address_zabbix_host {}'.format(str(err_message)))
    
def set_address_zabbix_host(device_dict, address, logger):
    try:
        zabbix_conn = ZabbixAPI(config.zabbix_link, 
                                user=config.zabbix_user, 
                                password=config.zabbix_pass)
        if device_dict['inventory'] == '-1':
            inv_on = zabbix_conn.host.update(hostid=device_dict['hostid'], 
                                             inventory_mode = 0)
            if not inv_on: 
                zabbix_conn.user.logout()
                logger.warning('{}: failed zabbix inventory activation'.format(device_dict['name']))
                return None
            logger.info('{}: zabbix inventory turned on: {}'.format(device_dict['name'], address))
        addr_upd = zabbix_conn.host.update(hostid=device_dict['hostid'], 
                                           inventory={'site_address_a': address})
        zabbix_conn.user.logout()
        if not addr_upd:
            logger.warning('{}: failed zabbix address update'.format(device_dict['name']))
        logger.info('{}: zabbix address updated: {}'.format(device_dict['name'], address))
    except Exception as err_message:
        logger.error('Ошибка в функции set_address_zabbix_host {}'.format(str(err_message)))
    
def send_email(subject, body_text, to_email, nf_logger):
    try:
        from_addr = config.from_addr
        msg = MIMEMultipart()
        msg["From"] = from_addr
        msg["Subject"] = subject
        msg["Date"] = formatdate(localtime=True)
        msg.attach( MIMEText(body_text, 'html', _charset='utf-8') )
        msg["To"] = to_email
        
        server = smtplib.SMTP(config.smtp_server)
        server.sendmail(from_addr, to_email, msg.as_string())
        nf_logger.info('email sent to {}'.format(str(to_email)))
        server.quit()
    except Exception as err_message:
        nf_logger.error('Ошибка в функции send_email {}'.format(str(err_message)))

def sql_add_notification_tg(now, wdate_dt, edate_dt, time_span, addr_list, device_list, logger):
    try:
        w_start = format(wdate_dt, '%d.%m.%y %H:%M')
        w_end = format(edate_dt, '%d.%m.%y %H:%M')
        msg = config.notifier_tg_msg.format(w_start, w_end, time_span, addr_list, device_list)
        msg_date = format(wdate_dt - timedelta(minutes = 30), '%Y-%m-%d %H:%M:%S')
        connection = local_sql_conn()
        req = ("INSERT into NotifierTG(message, telegram_id, msg_date, cur_date)"
               "values ('{}', '{}', '{}', '{}')".format(msg, 
                                                        config.notifier_tg_id,
                                                        msg_date, 
                                                        now))
        with connection.cursor() as cursor:
            cursor.execute(req)
        connection.commit()
        connection.close()
    except Exception as err_message:
        logger.error('Ошибка в функции sql_add_notification_tg {}'.format(str(err_message)))
        
###
###
### 
###
###
   
###
### MAPS
###
    
@web_utils_app.route("/")
def main():
    return render_template("maps.html")
    
@web_utils_app.route('/maps_out', methods=['POST'])
def maps_out():
    try:
        dev = request.form['text']
        dev = dev.strip(' \t')
        if dev == 'obiwan': return render_template("obi-wan.html")
        zabbix_conn = ZabbixAPI(config.zabbix_link, 
                                user=config.zabbix_user, 
                                password=config.zabbix_pass)
    
        try:
            ipaddress.ip_address(dev)
        # user sent hostname
        except:

            maps_arr = []
            dev = dev.lower()
            if re.search('[а-я]', dev):
                dev = dev.translate(str.maketrans("йцукенгшщзфывапролдячсмить","qwertyuiopasdfghjklzxcvbnm"))
            hosts = hostid_by_name(zabbix_conn, dev, logger)
            if not hosts:
                msg = 'Девайс {} не найден в базе'.format(dev)
                return render_template("maps.html", msg=msg)
            # if hostname returns only one id
            if len(hosts) == 1:
                map_ids = mapid_by_hostid(zabbix_conn, hosts[0]['hostid'])
                if not map_ids:
                    msg = 'Девайс {} не нарисован на картах'.format(hosts[0]['name'])
                    return render_template("maps.html", msg=msg)
                # if host id found on a single map
                if len(map_ids) == 1:
                    return render_template("map_redirect.html", map_id=map_ids[0])
                # if host id found on many maps
                else:
                    for map in map_ids:
                        mname = mapname_by_mapid(zabbix_conn, map)
                        maps_arr.append([mname, config.zabbix_map_link+map])
                return render_template("maps_out.html", maps_arr=maps_arr)
                
            # if hostname returns many ids
            devices_arr = []
            for devid in hosts:
                devices_arr.append([devid['hostid'],devid['name']])
                
            return render_template("devices_out.html", devices_arr=devices_arr)
                    
        
        # user sent ip address
        else:
            maps_arr = []
            host = hostid_by_ip(zabbix_conn, dev)
            if not host:
                msg = 'Девайс {} не найден в базе'.format(dev)
                return render_template("maps.html", msg=msg)
            map_ids = mapid_by_hostid(zabbix_conn, host)
            if not map_ids:
                msg = 'Девайс {} не нарисован на картах'.format(dev)
                return render_template("maps.html", msg=msg)
            # Тут я воюю с редиректом. return redirect, webbrowser.open, render html с редиректом...
            if len(map_ids) == 1:
                return render_template("map_redirect.html", map_id=map_ids[0])
            else:
                for map in map_ids:
                    mname = mapname_by_mapid(zabbix_conn, map)
                    map_link = config.zabbix_map_link+map
                    maps_arr.append([mname, map_link])
                
        zabbix_conn.user.logout()
        if maps_arr:
            return render_template("maps_out.html", maps_arr=maps_arr)
        else:
            msg = 'Девайс {} не найден в базе'.format(dev)
            return render_template("maps.html", msg=msg)

    except Exception as err_message:
        logger.error('Ошибка в функции maps_out {}'.format(str(err_message)))
        return str(err_message)

# Принимаем id девайса в заббиксе, возвращаем карты на которых он есть
@web_utils_app.route("/devid_<devid>")
def mapfordevice(devid):
    zabbix_conn = ZabbixAPI(config.zabbix_link, user=config.zabbix_user, password=config.zabbix_pass)
    maps_arr = []
    map_ids = mapid_by_hostid(zabbix_conn, devid)
    if not map_ids:
        msg = 'Девайс {} не нарисован на картах'.format(hostname_by_id(zabbix_conn, devid)[0]['host'])
        return render_template("maps.html", msg=msg)
    if len(map_ids) == 1:
        return render_template("map_redirect.html", map_id=map_ids[0])
    for mapid in map_ids:
        map_name = mapname_by_mapid(zabbix_conn, mapid)
        maps_arr.append([map_name, config.zabbix_map_link+mapid])
    maps_arr = sorted(maps_arr, key=lambda a: a[1])
    zabbix_conn.user.logout()
    return render_template('maps_out.html', maps_arr=maps_arr)
      
###
### /MAPS
###
    
###
### ARP
###
    
def get_arp(connection, search_obj, dev, logger):
    try:
        req = ('SELECT * from arp where {} = "{}"'.format(search_obj, dev))
        with connection.cursor() as cursor:
            cursor.execute(req)
            arp_arr = cursor.fetchall()
        return arp_arr
    except Exception as err_message:
        logger.error('Ошибка в функции get_arp {}'.format(str(err_message)))
    
@web_utils_app.route("/arp")
def arp():
    return render_template("arp.html")
   
@web_utils_app.route('/arp_out', methods=['POST'])
def arp_out():
    try:
        dev = request.form['text']
        dev = dev.strip(' \t')
        search_obj = ''
        # checking if we got an IP
        try:
            ipaddress.ip_address(dev)
        # not ip address
        except:
            # MAC addr detected!
            if re.match(b'^(\w{4}\.){2}\w{4}$|^(\w{2}[:-]){5}\w{2}$|^\w{12}$', dev.encode('utf-8')):
                search_obj = 'mac'
                dev = dev.upper().replace('.', '').replace(':', '')
            else:
                return render_template("arp.html", msg='IP или MAC!')
        # ip address
        else:
            search_obj = 'ip'
        connection = local_sql_conn()
        arp_arr = get_arp(connection, search_obj, dev, logger)
        connection.close()
        if not arp_arr:
            msg = '{} в базе арпов не найден'.format(dev)
            return render_template("arp.html", msg=msg)
        return render_template('arp_out.html', dev=dev, arp_arr=arp_arr)
    except Exception as err_message:
        logger.error('Ошибка в функции arp_out {}'.format(str(err_message)))
        return str(err_message)
    
###
### /ARP
###
    
###
### INVENTORY
###
    
@web_utils_app.route("/inventory")
def inventory():
    connection = local_sql_conn()
    now = datetime.now()
    headers = ['Type','Vendor','Model']
    #сделаем массив с названиями последних 12 месяцев
    headers += (month_back(now, x) for x in reversed(range(0, 12)))
    models = []
    # получим массив диктов вида {'type': 'switch', 'vendor': 'Cisco', 'model': 'SF352-08'}
    db = sql_dynamic_models(connection)
    for model in db:
        # из inventoryDynamic выгружаем данные по кол-ву по конкретной модели за последний год
        data = sql_dynamic_month(connection, model['model'])
        # преобразуем в словарь вида {месяц.год: количество}
        ndata = {format(x['date'], '%b.%y'):x['quantity'] for x in data}
        for x in range(3,15):
            ndata.setdefault(headers[x], 0)
        url = 'https://devnet.spb.avantel.ru/inventory_model_{}'.format(
                                        urllib.parse.quote(model['model'].replace('/','slash'), safe=''))
        model_url = '<a href={}>{}</a>'.format(url, model['model'])
        models += [[model['type'], model['vendor'], model_url,*[ndata[x] for x in headers[3:15]]]]
    connection.close()
    
    # А тут мы вместо того чтобы просто дать другой запрос в базу, будем переделывать уже имеющуюся таблицу
    headers_t = [headers[0]]+headers[3:]
    headers_v = [headers[1]]+headers[3:]
    # делаем дикт с ключами = типы устройств, а значения = списки с кол-вом девайсов за каждый из последних 12 мес.
    typed = {x[0]:[0 for x in headers_t[1:]] for x in models}
    for model in models:
        for i in range(len(model)-3):
            typed[model[0]][i] += model[i+3]
    url = '<a href=https://devnet.spb.avantel.ru/inventory_type_{}>{}</a>'
    types = [[url.format(urllib.parse.quote(x, safe=''), x)] + typed[x] for x in typed]
    # И еще разок, чего уж там
    vendord = {x[1]:[0 for x in headers_v] for x in models}
    for model in models:
        for i in range(3,len(model)-3):
            vendord[model[1]][i] += model[i+3]
    url = '<a href=https://devnet.spb.avantel.ru/inventory_vendor_{}>{}</a>'
    vendors = [[url.format(urllib.parse.quote(x, safe=''), x)] + vendord[x] for x in vendord]
    
    # list(zip(*types[::-1])) эта хрень поворачивает массив по часовой стрелке, 
    # таким образом получаем туплы с кол-вом девайсов за месяц и суммируем их
    total = ['<b>'+str(sum(x))+'</b>' for x in list(zip(*types[::-1]))[1:]]
    total.insert(0, '<b>Total:</b>')
    
    return render_template("inventory.html", headers=headers, headers_t=headers_t, 
                            headers_v=headers_v, models=models, types=types, vendors=vendors, total=total)

@web_utils_app.route("/inventory_out", methods=['POST'])
def inventory_out():
    dev = request.form['text']
    dev = dev.strip(' \t')
    if not dev: return inventory()#render_template("maps.html")
    # MAC addr detected!
    if re.match(b'^(\w{4}\.){2}\w{4}$|^(\w{2}[:-]){5}\w{2}$', dev.encode('utf-8')):
        return inventory()
        
    connection = local_sql_conn_l()
    # пробуем найти по имени сначала
    inv_data, vars_last, vars_all = sql_inventory_ipname(connection, dev)
    # если нашли больше одного девайса
    if inv_data:
        return render_template('inventory_many2.html', vars_all=vars_all, req=dev)
    # если не нашли ничего, пробуем по серийнику
    if not inv_data:
        inv_data, vars_last, vars_all = sql_inventory_serial(connection, dev)
    connection.close()
    # снова ничего не нашли, сдаемся
    if not inv_data:
        return inventory()
    # по дефолту возвращаем шаблон под один девайс
    return render_template("inventory_one.html", inv_data=inv_data, vars_last=vars_last, vars_all=vars_all)

@web_utils_app.route("/inventory_model_<model>")
def inventory_model(model):
    connection = local_sql_conn_l()
    model = urllib.parse.unquote(model).replace('slash','/')
    vars_all = sql_inventory_vmt(connection, model, 'model')
    #if len(vars) == 1:
    #    return inventory_serial(vars[0][0])
    connection.close()
    return render_template('inventory_many.html', vars_all=vars_all)

@web_utils_app.route("/inventory_vendor_<vendor>")
def inventory_vendor(vendor):
    connection = local_sql_conn_l()
    vendor = urllib.parse.unquote(vendor).replace('slash','/')
    vars_all = sql_inventory_vmt(connection, vendor, 'vendor')
    connection.close()
    return render_template('inventory_many2.html', vars_all=vars_all, req=vendor)

@web_utils_app.route("/inventory_type_<dtype>")
def inventory_dtype(dtype):
    connection = local_sql_conn_l()
    dtype = urllib.parse.unquote(dtype).replace('slash','/')
    vars_all = sql_inventory_vmt(connection, dtype, 'type')
    connection.close()
    return render_template('inventory_many2.html', vars_all=vars_all, req=dtype)
    
@web_utils_app.route("/inventory_serial_<serial>")
def inventory_serial(serial):
    connection = local_sql_conn_l()
    serial = urllib.parse.unquote(serial).replace('slash','/')
    inv_data, vars_last, vars_all = sql_inventory_serial(connection, serial)
    connection.close()
    return render_template("inventory_one.html", inv_data=inv_data, vars_last=vars_last, vars_all=vars_all)

@web_utils_app.route("/inventory_suspended")
def inventory_suspended():
    connection = local_sql_conn_l()
    suspended_arr = sql_inventory_suspended(connection)
    connection.close()
    return render_template("inventory_suspended.html", suspended_arr=suspended_arr)

###
### /INVENTORY
###

###
### NOTIFICATION
###

@web_utils_app.route("/client_notification")
def client_notification(msg=''):
    # чистим старые сессии если есть
    sql_clean_sessions()
    notification_history = sql_get_notification_history()
    if not notification_history:
        msg = 'Беда! Не смог считать историю оповещений из базы.'
        logger.error('Could not read notification history from SQL')
        notification_history = {}
    return render_template("client_notification.html", 
                           msg=msg, 
                           notification_history=notification_history)
        
@web_utils_app.route("/client_notification_out", methods=['POST'])
def client_notification_out():
    hostname = request.form['text']
    if not hostname: return client_notification(msg='Хостнейм введи')
    hostname = hostname.strip(' \t')
    
    # дадим возможность юзеру вводить хостнеймы через пробел и/или запятую
    if ',' in hostname:
        hostnames = hostname.replace(' ', '').split(',')
    else:
        hostnames = hostname.split(' ')
    devices_arr = []
    contract_dict = {}
    for hn in hostnames:
        ip = ip_by_hostname(hn, logger)
        if not ip: 
            return client_notification(msg='Не смог определить IP для {}'.format(hn))
        devices_arr.append(ip)
        contract_dict[ip] = {'name': hn, 
                             'ip': ip,
                             'address': '',
                             'uplink': '',
                             'cont_num': '', 
                             'unrecognized': [], 
                             'alive': 0, 
                             'contracts': {}
                             }
        
    #ip = ip_by_hostname(hostname, logger)
    #if not ip: return client_notification(msg='Не смог определить IP')
    # {ip: {name: '', ip: '', address: '', uplink: '', cont_num: '', unrecognized: '', alive: '', contracts: {contract: emails}}}
    contract_dict = client_notification_get_emails(devices_arr, contract_dict, logger)
    contract_dict = get_address_zabbix_host(contract_dict, logger)
    contract_dict_json = json.dumps(contract_dict, ensure_ascii=False)

    # генерячим session id и записываем его вместе с имейлами в mysql
    alphabet = string.ascii_letters + string.digits
    sid = ''.join(secrets.choice(alphabet) for i in range(8))
    today_date = format(datetime.now(), '%Y-%m-%d')
    sql_set_session(sid, contract_dict_json, today_date)
    
    return render_template("client_notification_out.html", 
                           contract_dict=contract_dict,
                           sid=sid,
                           today_date=today_date)
                           
@web_utils_app.route("/client_notification_confirm_<sid>", methods=['POST'])
def client_notification_confirm_(sid):
    logger.info('GOT FORM {}'.format(str(request.form.to_dict())))
    msg = ''
    text_vars = {}
    text_vars['subject'] = request.form['subject']
    text_vars['time_date'] = format(
                                datetime.strptime(request.form['time_date'], 
                                '%Y-%m-%d'), '%d.%m.%Y')
    text_vars['time_start'] = ('{:02d}:{:02d}'.format(
                                    int(request.form['time_start_hr']),
                                    int(request.form['time_start_min'])))
    text_vars['time_end'] = ('{:02d}:{:02d}'.format(
                                    int(request.form['time_end_hr']),
                                    int(request.form['time_end_min'])))
    text_vars['time_span'] = request.form['time_span']
    
    # валидация времени работ
    time_start = datetime.strptime(text_vars['time_start'], '%H:%M')
    time_end = datetime.strptime(text_vars['time_end'], '%H:%M')
    time_span = timedelta(minutes=int(text_vars['time_span']))
    if time_end <= time_start:
        msg = ('Проверь время работ. Начало в {}, '
               'конец в {}, что-то не сходится<br>'.format(text_vars['time_start'], 
                                                       text_vars['time_end']))
    elif (time_end - time_start) < time_span:
        msg = ('Продолжительность перерыва ({} мин) '
               'не может быть больше чем длительность работ в целом<br>'.format(text_vars['time_span']))
    
    checked = request.form.getlist('mail_send')
    logger.info('CHECKED: {}'.format(str(checked)))
    addresses = {key.replace("_address_fld", ''):str(request.form.get(key)) 
                 for key in request.form.keys() if "_address_fld" in key}
    
    sid_storage = sql_get_session(sid)
    if not sid_storage: return client_notification(msg='Проблема с SQL')
    contract_dict = json.loads(sid_storage[0]['storage'])
    # убираем не отмеченные девайсы из списка на рассылку
    excluded = [contract_dict.pop(dev) for dev in list(contract_dict) if dev not in checked]
    # синхронизируем адреса (домов, не мейлы) с полученными из формы
    for d in contract_dict:
        if contract_dict[d]['address'] != addresses[d]:
            logger.info('{} will be changed to {}'.format(contract_dict[d]['address'], addresses[d]))
            contract_dict[d]['address'] = addresses[d]
            set_address_zabbix_host(contract_dict[d], addresses[d], logger)
        # пользуясь случаем агрегируем все email в рамках одного девайса
        contract_dict[d]['all_emails'] = ', '.join(
            [contract_dict[d]['contracts'][e] for e in contract_dict[d]['contracts']])
    
    # переделываем в дикт с ключами - адресами. Нужно чтобы агрегировать по адресу письма клиентам с разных девайсов.
    addr_d = {}
    text_d = {}
    addr_id = 0
    for dev in contract_dict:
        addr = contract_dict[dev]['address']
        if not addr in addr_d:
            addr_d[addr] = {}
            addr_d[addr]['id'] = str(addr_id)
            addr_id =+ 1
            addr_d[addr]['name'] = contract_dict[dev]['name']
            addr_d[addr]['all_emails'] = contract_dict[dev]['all_emails']
            text_d[addr] = config.notification_msg.format(
                                                    text_vars['time_date'],
                                                    text_vars['time_start'],
                                                    text_vars['time_end'],
                                                    text_vars['time_span'],
                                                    addr)
        else:
            addr_d[contract_dict[dev]['address']]['name'] += ', {}'.format(
                                                contract_dict[dev]['name'])
            addr_d[contract_dict[dev]['address']]['all_emails'] += ', {}'.format(
                                                contract_dict[dev]['all_emails'])
    # прогоним группы email по каждому адресу через set чтобы убить дубликаты
    for adr in addr_d:
        addr_d[adr]['all_emails'] = ', '.join(set(addr_d[adr]['all_emails'].split(', ')))
            
    if len(addr_d) == 0: 
        # юзер снял все галочки
        msg = 'Выйди и зайди нормально<br>'
    elif all(not addr_d[adr]['all_emails'] for adr in addr_d):
        # мейлов нет, но вы держитесь
        msg = 'Мейлов нет, слать некуда<br>'
    else:
        storage = {'addr_d': addr_d, 'text_vars': text_vars}
        storage_json = json.dumps(storage, ensure_ascii=False)
        sql_upd_session(sid, storage_json)
    logger.info('ADDR DICT {}'.format(str(addr_d)))
    return render_template("client_notification_confirm.html",
                           addr_d = addr_d, 
                           subject = text_vars['subject'],
                           text_d = text_d,
                           msg = msg,
                           sid = sid)
        
        
@web_utils_app.route("/client_notification_sent_<sid>", methods=['POST'])
def client_notification_sent_(sid):
    now = datetime.now()
    nid = int(now.timestamp())
    
    # Отдельный логгер запишет файл под конкретную рассылку
    nf_logger = logging.getLogger('my_logger')
    nf_handler = logging.FileHandler(config.notification_log_folder+str(nid)+'.log', 'w+')
    nf_formatter = logging.Formatter("[%(asctime)s] %(levelname)s - %(message)s")
    nf_handler.setLevel(logging.INFO)
    nf_handler.setFormatter(nf_formatter)
    nf_logger.setLevel(logging.INFO)
    nf_logger.addHandler(nf_handler)

    sid_storage = sql_get_session(sid)
    if not sid_storage: 
        nf_logger.error('Проблема с SQL (Не считал данные)')
        return client_notification(msg='Проблема с SQL (Не считал данные)')
    #logger.info('SID STORE: {}'.format(sid_storage[0]['storage']))
    data_dict = json.loads(sid_storage[0]['storage'])
    if not data_dict['addr_d']:
        nf_logger.error('Проблема с SQL (Не смог распаковать данные)')
        return client_notification(msg='Проблема с SQL (Не смог распаковать данные)')
    sql_del_session(sid)
    nf_logger.info('Data to work with: {}'.format(str(data_dict)))
    
    subject = data_dict['text_vars']['subject'].replace('***', "'")
    nf_logger.info('Corrected subject: {}'.format(str(subject)))
    text_d = {}
    ndate = format(now, '%Y-%m-%d %H:%M:%S')
    # wdate = works date (время начала работ)
    wdate = '{} {}'.format(data_dict['text_vars']['time_date'], 
                           data_dict['text_vars']['time_start'])
    wdate_dt = datetime.strptime(wdate, '%d.%m.%Y %H:%M')
    wdate = format(wdate_dt, '%Y-%m-%d %H:%M:%S')
    # edate = end date (время окончания работ)
    edate = '{} {}'.format(data_dict['text_vars']['time_date'], 
                           data_dict['text_vars']['time_end'])
    edate_dt = datetime.strptime(edate, '%d.%m.%Y %H:%M')
    edate = format(edate_dt, '%Y-%m-%d %H:%M:%S')
    
    # SENDING MSGS HERE
    for addr in data_dict['addr_d']:
        msg_text = config.notification_msg.format(data_dict['text_vars']['time_date'],
                                                  data_dict['text_vars']['time_start'],
                                                  data_dict['text_vars']['time_end'],
                                                  data_dict['text_vars']['time_span'],
                                                  addr)
        text_d[addr] = msg_text
        nf_logger.info('Message compiled: \n{}'.format(str(msg_text)))
        #В список рассылки добавляем from_addr, чтобы на саппорт упало сообщение тоже.
        for email_addr in data_dict['addr_d'][addr]['all_emails'].split(', ')+[config.from_addr]:
            send_email(subject, msg_text, email_addr, nf_logger)
        
        sql_add_notification_history(nid,
                                     ndate, 
                                     wdate, 
                                     subject,
                                     addr,
                                     data_dict['addr_d'][addr]['name'],
                                     data_dict['addr_d'][addr]['all_emails'],
                                     msg_text,
                                     logger)
                                     
    # делаем запись в MySQL, таблицу NotifierTG для скрипта Notifier. 
    # Он кинет в телегу сообщение о предстоящих работах
    addr_list = '\n'.join([addr for addr in data_dict['addr_d']])
    device_list = ', '.join([data_dict['addr_d'][addr]['name'] for addr in data_dict['addr_d']])
    sql_add_notification_tg(ndate,
                            wdate_dt, 
                            edate_dt, 
                            data_dict['text_vars']['time_span'],
                            addr_list,
                            device_list,
                            logger)
        
    msg = "Сообщения отправлены"
    return render_template("client_notification_confirm.html",
                           addr_d = data_dict['addr_d'], 
                           subject = subject,
                           text_d = text_d,
                           msg = msg,
                           sid = sid)

@web_utils_app.route("/client_notification_history_<sid>")
def client_notification_history(sid):
    notification_history_msg = sql_get_notification_history_msg(sid)
    addr_d = {x['address']: {'name': x['devices'],'all_emails': x['emails']} for x in notification_history_msg}
    text_d = {x['address']: x['body'] for x in notification_history_msg}
    subject = notification_history_msg[0]['subject']
    date = format(notification_history_msg[0]['notif_date'], '%d.%m.%Y %H:%M')
    msg = "Сообщение из архива ({})".format(date)
    return render_template("client_notification_confirm.html",
                           msg = msg,
                           addr_d=addr_d, 
                           subject=subject, 
                           text_d=text_d)
###
### /NOTIFICATION
###

    # Hello, there!
@web_utils_app.route("/obi-wan")
def obi():
    return render_template("obi-wan.html")
    
@web_utils_app.route("/obi-wan-out", methods=['POST'])
def obi_out():
    varrrs = {}
    varrrs['ar'] = request.form['text']
    varrrs['ax'] = request.form['xext']
    varrrs['as'] = request.form['sext']
    varrrs['bs'] = request.form['browser']
    #varrrs['v1'] = ''
    #varrrs['v1'] = request.form['vehicle1']
    #varrrs['v2'] = ''
    #varrrs['v2'] = request.form['vehicle2']
    varrrs['vv'] = request.form.getlist('vehicle')
    varrrs['dt'] = request.form['birthday']
    varrrs['th'] = request.form['timeh']
    varrrs['tm'] = request.form['timem']
    varrrs['dd'] = request.form['appt']
    logger.info(varrrs)
    f = request.form
    varrrs['shit'] = ', '.join([key+':'+str(f.get(key)) for key in f.keys()])
    
    if not varrrs['ar']: return obi()
    alphabet = string.ascii_letters + string.digits
    sid = ''.join(secrets.choice(alphabet) for i in range(8))
    date = format(datetime.now(), '%Y-%m-%d')
    #sql_set_session(sid, varrrs['ar'], date)
    
    return render_template("obi-wan-out.html", sid=sid, varrrs=varrrs)
    
@web_utils_app.route("/obi-wan-out_<sid>", methods=['POST'])
def obi_out2(sid):
    avar2 = request.form['text']
    sid_storage = sql_get_session(sid)
    sql_del_session(sid)
    if not sid_storage: return obi()
    return render_template("obi-wan-out2.html", avar=sid_storage[0]['storage'], avar2=avar2)

if __name__ == "__main__":
    web_utils_app.run(debug=True, host='0.0.0.0', port=4000)