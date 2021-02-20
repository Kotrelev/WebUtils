# -*- coding: utf-8 -*-
#!/usr/local/bin/Python37/WebUtils/Inventory/env/bin/
#Python 3.7.3

import config
import subprocess, os, re, logging, argparse, telebot
import pymysql.cursors
from pyzabbix import ZabbixAPI
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter
from datetime import datetime, timedelta
from time import gmtime, strftime

from Vendors.cisco import cisco
from Vendors.cisco_smb import cisco_smb
from Vendors.cisco_spa import cisco_spa
from Vendors.snr import snr
from Vendors.dlink import dlink
from Vendors.mikrotik import mikrotik
from Vendors.mikrotik_swos import mikrotik_swos
from Vendors.apc import apc
from Vendors.ats import ats
from Vendors.eltex import eltex, eltex2
from Vendors.eaton import eaton
from Vendors.juniper import juniper
from Vendors.extreme import extreme

#no_serial_arr = []
#no_model_arr = []
#no_access_arr = []
#unknown_arr = []            # SysObjectID not in sysobjectid_dict
#ignored_arr = []            # It answers, but script does not know what to do
#no_communication_arr = []   # No snmp/web connection
#no_ping_arr = []
            
def local_sql_conn():
    connection = pymysql.connect(host=config.local_mysqlhost,
        user=config.local_mysqluser,
        password=config.local_mysqlpass,
        db=config.local_mysqldb,
        charset='utf8mb4',
        cursorclass=pymysql.cursors.DictCursor)
    return(connection)
      
def getSysObjectID(ip, logger):
    try:
        for community in config.snmp_comm_ro:
            proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} 1.3.6.1.2.1.1.2".format(community, ip),
                                    stdout=subprocess.PIPE,shell=True)
            (out,err) = proc.communicate()
            if out:
                return out.decode('utf-8').strip('OID: ').strip('\n'), community
        return None, None
    except Exception as err_message:
        logger.error('{}: Ошибка в функции getSysObjectID {}'.format(ip, str(err_message)))
        
def getSysDescr(ip, community, logger):
    try:
        proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c "+community+" "+ip+" iso.3.6.1.2.1.1.1.0",
                                stdout=subprocess.PIPE,shell=True)
        (out,err) = proc.communicate()
        if out:
            return out.decode('utf-8').strip('STRING: ').strip('\n')
        else: return None
    except Exception as err_message:
        logger.error('{}: Ошибка в функции getSysDescr {}'.format(ip, str(err_message)))
        
def getModel(ip, devname, models_dict, inventory_dict, inventory_vars_dict, date, logger):
    try:
        # это те значение которые мы уже умеем собирать с железа.
        sync_list = ['serial', 'name', 'firmware', 'mac', 'hostname', 'location'] 
        stuff = {}
        sysobjectid, community = getSysObjectID(ip, logger)
        if sysobjectid and sysobjectid in config.sysobjectid_dict:
            vendor_cls = config.sysobjectid_dict[sysobjectid]['vendor']
            if type(vendor_cls) == str: 
                #ignored_arr.append(ip)
                failed_dict['ignored'].append(ip)
                # Если игнорим, но девайс есть в базе значит девайс сменили на неведому зверушку
                if (ip in inventory_vars_dict and inventory_dict[inventory_vars_dict[ip]['serial']]['monitored'] == 1):
                    sql_state.setdefault(inventory_vars_dict[ip]['serial'], []).append('dead')
                    if not inventory_dict[inventory_vars_dict[ip]['serial']]['downdate']:
                        sql_state.setdefault(inventory_vars_dict[ip]['serial'], []).append('down')
                    logger.info('{}:{} announced suspended (sysobjectid not supported)'.format(ip, 
                                                    inventory_vars_dict[ip]['serial']))
                return None
            devtype = config.sysobjectid_dict[sysobjectid]['type']
            vendor = vendor_cls.vendor()
            model = config.sysobjectid_dict[sysobjectid]['model']
            # models_dict это просто локальный словарик в котором мы собираем ипы и серийники все подряд
            if vendor not in models_dict:
                models_dict[vendor] = {}
            # модель не понять по SysObjectID
            if model == 'ambiguous':
                # попробуем вытащить модель из вендор-специфик оидов
                model = vendor_cls.get_model(ip, community, logger)

                if not model or model == 'ambiguous':
                    #no_model_arr.append(ip)
                    failed_dict['no model'].append(ip)
                    logger.warning(ip+' has known SysObjectID('+vendor+'), but model identification failed')
                    # Если модель не поняли, но девайс есть в базе значит девайс сменили на неведому зверушку или он просто тупит
                    if (ip in inventory_vars_dict and inventory_dict[inventory_vars_dict[ip]['serial']]['monitored'] == 1):
                        if not inventory_dict[inventory_vars_dict[ip]['serial']]['downdate']:
                            sql_state.setdefault(inventory_vars_dict[ip]['serial'], []).append('down')
                        logger.info('{}:{} down (failed to identify)'.format(ip, inventory_vars_dict[ip]['serial']))
                    return None

            if model:
                stuff = vendor_cls.get_stuff(ip, community, logger)
                      
        # Unknown sysobjectid!
        elif sysobjectid and sysobjectid not in config.sysobjectid_dict:
            #unknown_arr.append(ip)
            failed_dict['unknown'].append(ip)
            logger.warning(ip+' has unknown SysObjectID: '+sysobjectid)
            # Если sysobjectid левый, но девайс есть в базе значит девайс сменили на неведому зверушку
            if (ip in inventory_vars_dict and inventory_dict[inventory_vars_dict[ip]['serial']]['monitored'] == 1):
                if not inventory_dict[inventory_vars_dict[ip]['serial']]['downdate']:
                    sql_state.setdefault(inventory_vars_dict[ip]['serial'], []).append('down')
                sql_state.setdefault(inventory_vars_dict[ip]['serial'], []).append('dead')
                logger.info('{}:{} announced suspended (unknown sysobjectid)'.format(ip, inventory_vars_dict[ip]['serial']))
            return None
        
        # на снмп не ответил, может это СПА8000?
        elif not sysobjectid:
            stuff = cisco_spa.get_stuff8000(ip, logger)
            if stuff:
                if stuff == 'AuthFailed':
                    #no_access_arr.append(ip)
                    failed_dict['no access'].append(ip)
                    logger.warning(ip+' login failed')
                    return None
                elif 'SPA' in stuff['model']:
                    devtype = 'voip'
                    vendor = cisco_spa.vendor()
                    model = stuff['model']
                    if vendor not in models_dict:
                        models_dict[vendor] = {}

    except Exception as err_message:
        failed_dict['error'].append(ip)
        logger.error(ip+' Ошибка в функции getModel (get stuff): '+str(err_message))
        logger.error(ip+' {}: '.format(str(sysobjectid)))
        logger.error(ip+' {}: '.format(str(model)))
        logger.error(ip+' {}: '.format(str(stuff)))
        return None
        
    try:
        # если данных от девайса нет
        if not stuff or not stuff['serial']:
            # если не ответил на снмп
            if not sysobjectid:
                p = ping(ip)
                # если есть пинг
                if p == 0:
                    #no_communication_arr.append(ip)
                    failed_dict['no communication'].append(ip)
                    #logger.warning(ip+' no snmp or web reply')
                # если нет пинга
                else:
                    #no_ping_arr.append(ip)
                    failed_dict['no ping'].append(ip)
            else:
                #no_serial_arr.append(ip)
                failed_dict['no serial'].append(ip)
                logger.warning(ip+' serial is not identified')
            
            if ip in inventory_vars_dict:
                # Игнорим если снят с мониторинга
                if inventory_dict[inventory_vars_dict[ip]['serial']]['monitored'] == 0:
                    return None
                logger.info('{}:{} is down'.format(ip, inventory_vars_dict[ip]['serial']))
                # если недавно упал
                if not inventory_dict[inventory_vars_dict[ip]['serial']]['downdate']:
                    sql_state.setdefault(inventory_vars_dict[ip]['serial'], []).append('down')
                else:
                    # если downtime больше N дней, считаем девайс снятым
                    ddate = inventory_dict[inventory_vars_dict[ip]['serial']]['downdate']
                    downtime = datetime.strptime(date, '%Y-%m-%d').date() - ddate
                    logger.info('{}: down for {} days'.format(ip, str(downtime.days)))
                    if downtime.days > config.downtime_limit:
                        sql_state.setdefault(inventory_vars_dict[ip]['serial'], []).append('dead')
                        logger.info('{}:{} announced suspended (downtime limit)'.format(ip, inventory_vars_dict[ip]['serial']))
            return None
        
    except Exception as err_message:
        failed_dict['error'].append(ip)
        logger.error(ip+' Ошибка в функции getModel (unreachable): '+str(err_message))
        return None
        
    try:
        
        stuff['name'] = devname
        #print(stuff)
        
        if not model in models_dict[vendor]:
            models_dict[vendor][model] = [ip+'|'+stuff['serial']]
        else:
            models_dict[vendor][model].append(ip+'|'+stuff['serial'])
        
        # серийника нет в базе
        if not stuff['serial'] in inventory_dict:
            # добавляем серийник в базу
            sql_add.setdefault(stuff['serial'], {}).update({'dev':[stuff['serial'], devtype, vendor, model, stuff['hardware']]})
            logger.info('{}:{} device added'.format(ip, stuff['serial']))
            # Если ип уже есть в базе с другим серийным, снимаем галочку "мониторинг" у бывшего.
            if ip in inventory_vars_dict and inventory_vars_dict[ip]['serial'] != stuff['serial']:
                logger.info('{}:{} announced suspended (new serial {})'.format(ip, 
                                                inventory_vars_dict[ip]['serial'], stuff['serial']))
                if not inventory_dict[inventory_vars_dict[ip]['serial']]['downdate']:
                    # запишем когда девайс пропал, если такой записи еще нет
                    sql_state.setdefault(inventory_vars_dict[ip]['serial'], []).append('down')
                sql_state.setdefault(inventory_vars_dict[ip]['serial'], []).append('dead')
                logger.info('{}:{} vars added: {}'.format(ip, stuff['serial'], str(stuff)))
                sql_add.setdefault(stuff['serial'], {}).update({'var':[stuff['serial'], 
                                                                   stuff['firmware'],
                                                                   stuff['mac'],
                                                                   ip, 
                                                                   devname, 
                                                                   stuff['hostname'],
                                                                   stuff['location'],
                                                                   date]})
                return None
        # ip нет в базе
        if not ip in inventory_vars_dict:
            if stuff['serial'] in sql_add and 'var' in sql_add[stuff['serial']]:
                logger.warning('{}:{} has a duplicate in zabbix'.format(ip, stuff['serial']))
            # добавляем ип в базу
            sql_add.setdefault(stuff['serial'], {}).update({'var':[stuff['serial'], 
                                                                   stuff['firmware'],
                                                                   stuff['mac'],
                                                                   ip, 
                                                                   devname, 
                                                                   stuff['hostname'],
                                                                   stuff['location'],
                                                                   date]})
            logger.info('{}:{} vars added: {}'.format(ip, stuff['serial'], str(stuff)))
        # обновляем vars если есть изменения
        elif any(inventory_vars_dict[ip][x] != stuff[x] for x in sync_list):
            if stuff['serial'] in sql_add and 'var' in sql_add[stuff['serial']]:
                logger.warning('{}:{} has a duplicate in zabbix'.format(ip, stuff['serial']))
            sql_add.setdefault(stuff['serial'], {}).update({'var':[stuff['serial'], 
                                                                   stuff['firmware'],
                                                                   stuff['mac'],
                                                                   ip, 
                                                                   devname, 
                                                                   stuff['hostname'],
                                                                   stuff['location'],
                                                                   date]})
            logger.info('{}:{} vars updated: {} to {}'.format(ip, stuff['serial'], 
                                            str(inventory_vars_dict[ip]), str(stuff)))
        # если мониторинг выключен, включаем
        if stuff['serial'] in inventory_dict and inventory_dict[stuff['serial']]['monitored'] == 0:
            sql_state.setdefault(stuff['serial'], []).append('alive')
            logger.info('{}:{} resuscitated'.format(ip, stuff['serial']))
        # обнуляем downtime
        if stuff['serial'] in inventory_dict and inventory_dict[stuff['serial']]['downdate']:
            sql_state.setdefault(stuff['serial'], []).append('up')
            logger.info('{}:{} is back online'.format(ip, stuff['serial']))
            
    except Exception as err_message:
        failed_dict['error'].append(ip)
        logger.error(ip+' Ошибка в функции getModel: '+str(err_message))
        return None

def sql_get_inventory(connection, logger):
    try:
        with connection.cursor() as cursor: 
            cursor.execute("select * from Inventory") 
            inventory = cursor.fetchall()
            return inventory

    except Exception as err_message:
        logger.error('Ошибка в функции sql_get_inventory {}'.format(str(err_message)))
        
def sql_get_inventory_vars(connection, logger):
    try:
        with connection.cursor() as cursor: 
            cursor.execute("SELECT tt.* FROM InventoryVars tt NATURAL JOIN "
                           "( SELECT serial, MAX(date) AS date FROM InventoryVars GROUP BY serial ) mostrecent;") 
            inventory_vars = cursor.fetchall()
            return inventory_vars

    except Exception as err_message:
        logger.error('Ошибка в функции sql_get_inventory_vars {}'.format(str(err_message)))
        
def sql_get_vars_by_serial(connection, serial, logger):
    try:
        with connection.cursor() as cursor: 
            cursor.execute("select * from InventoryVars "
                           "where date=(select MAX(date) from InventoryVars where serial = '{}')"
                           " and serial = '{}';".format(serial, serial))
            inventory_vars = cursor.fetchall()
            return inventory_vars

    except Exception as err_message:
        logger.error('Ошибка в функции sql_get_vars_by_serial {}'.format(str(err_message)))

        
def sql_upd_dynamic(connection, date, logger):
    try:
        with connection.cursor() as cursor:
            cursor.execute("select max(date) from InventoryDynamic;")
            max_date = cursor.fetchall()
            # проверяем что за этот день данных в базе еще нет. Если уже есть, то выходим.
            if date == format(max_date[0]['max(date)'], '%Y-%m-%d'):
                return None
            cursor.execute("INSERT INTO InventoryDynamic (type, vendor, model, quantity, date)"
                           " SELECT type, vendor, model, COUNT(model) AS `quantity`, \"{}\""
                           " FROM Inventory WHERE monitored = 1 GROUP BY model;".format(date))
            connection.commit()
    except Exception as err_message:
        logger.error('Ошибка в функции sql_upd_dynamic {}'.format(str(err_message)))
        
def sql_action(connection, sql_add, sql_state, date):
    try:
        for serial in sql_add:
            req_arr = []
            if serial in sql_state:
                sql_state.pop(serial, None)
            if 'dev' in sql_add[serial]:
                req = ("insert into Inventory(serial, type, vendor, model, hardware, monitored)" 
                    "values ('{}', '{}', '{}', '{}', '{}', '{}')".format(*sql_add[serial]['dev'],1))
                req_arr.append(req)
            if 'var' in sql_add[serial]:
                req = ("insert into InventoryVars(serial, firmware, mac, ip, name, hostname, location, date)" 
                    "values ('{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}')".format(*sql_add[serial]['var']))
                req_arr.append(req)
            with connection.cursor() as cursor:
                for req in req_arr:
                    cursor.execute(req)
                connection.commit()
        for serial in sql_state:
            req_arr = []
            if 'down' in sql_state[serial]:
                req = ("UPDATE Inventory SET downdate = \"{}\" WHERE serial = \"{}\"".format(date, serial))
                #print(req)
                req_arr.append(req)
            elif 'up' in sql_state[serial]:
                req = ("UPDATE Inventory SET downdate = NULL WHERE serial = \"{}\"".format(serial))
                req_arr.append(req)
            if 'dead' in sql_state[serial]:
                req = ("UPDATE Inventory SET monitored = 0 WHERE serial = \"{}\"".format(serial))
                req_arr.append(req)
            elif 'alive' in sql_state[serial]:
                req = ("UPDATE Inventory SET monitored = 1 WHERE serial = \"{}\"".format(serial))
                req_arr.append(req)
            with connection.cursor() as cursor:
                for req in req_arr:
                    cursor.execute(req)
                connection.commit()
    except Exception as err_message:
        logger.error('{}: Ошибка в функции sql_action {}'.format(serial, str(err_message)))
        return None
            
def hostid_by_ip(zabbix_conn, ip):
    try:
        host_iface = zabbix_conn.hostinterface.get(output=['hostid', 'ip'], filter={'ip': ip})
        if not host_iface:
            return None
        return host_iface[0]['hostid']
    except Exception as err_message:
        logger.error('Ошибка в функции hostid_by_ip {}'.format(str(err_message)))
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
        
def get_interface(hostid, interfaces):
    for interface in interfaces:
        if interface['hostid'] == hostid:
            return interface['ip']
    
def ping(ip):
    result = os.system('ping -c 2 '+ip+' > /dev/null 2>&1')
    return result
    
def telegram_report(connection, sql_state, sql_add, models_dict, ip_dict, failed_dict):
    try:
        html_report = ('<!DOCTYPE html><html><head>'
                       '<meta charset="utf-8"></head><body>')
        if failed_dict['no serial']:
            html_report += '<h2>Серийник не удалось определить:</h2> {}'.format(
                '<br>'.join('| '+ip+' | '+ip_dict[ip] for ip in failed_dict['no serial']))
        if failed_dict['no model']:
            html_report += '<br><h2>Модель невозможно определить:</h2> {}'.format(
                '<br>'.join('| '+ip+' | '+ip_dict[ip] for ip in failed_dict['no model']))
        if failed_dict['no access']:
            html_report += '<br><h2>Нет доступа на устройство:</h2> {}'.format(
                '<br>'.join('| '+ip+' | '+ip_dict[ip] for ip in failed_dict['no access']))
        if failed_dict['unknown']:
            html_report += '<br><h2>Неизвестный SysObjectID:</h2> {}'.format(
                '<br>'.join('| '+ip+' | '+ip_dict[ip] for ip in failed_dict['unknown']))
        if failed_dict['ignored']:
            html_report += '<br><h2>Игнорируем:</h2> {}'.format(
                '<br>'.join('| '+ip+' | '+ip_dict[ip] for ip in failed_dict['ignored']))
        if failed_dict['no communication']:
            html_report += '<br><h2>Нет связи по SNMP/Web:</h2> {}'.format(
                '<br>'.join('| '+ip+' | '+ip_dict[ip] for ip in failed_dict['no communication']))
        if failed_dict['no ping']:
            html_report += '<br><h2>No Ping:</h2> {}'.format(
                '<br>'.join('| '+ip+' | '+ip_dict[ip] for ip in failed_dict['no ping']))
        if failed_dict['error']:
            html_report += '<br><h2>Ошибка при выполнении скрипта (см. лог):</h2> {}'.format(
                '<br>'.join('| '+ip+' | '+ip_dict[ip] for ip in failed_dict['error']))
        with open('/var/log/Inventory/'+strftime("%A", gmtime())+'.log', 'r') as log_file:
            html_report += '<br><h2>Log:</h2>'
            for line in log_file:
                html_report += line+'<br>'
        html_report += '</body></html>'
        
        filename = 'Inventory_'+strftime("%A", gmtime())+'.html'
        with open('/usr/local/bin/Python37/WebUtils/static/html/'+filename, 'w') as report:
            report.write(html_report)
        html_link = 'https://devnet.spb.avantel.ru/html/'+filename
        link_msg = "\n<a href=\""+html_link+"\">Тут подробный отчет</a>"
        
        bot = telebot.TeleBot(config.TOKEN)
        
        dead_arr = [ser for ser in sql_state if 'dead' in sql_state[ser]]
        alive_arr = [ser for ser in sql_state if 'alive' in sql_state[ser]]
        add_arr = [ser for ser in sql_add if 'dev' in sql_add[ser]]
        
        dead_vars = [sql_get_vars_by_serial(connection, serial, logger)[0] for serial in dead_arr]
        alive_vars = [sql_get_vars_by_serial(connection, serial, logger)[0] for serial in alive_arr]
        add_vars = alive_vars + [sql_get_vars_by_serial(connection, serial, logger)[0] for serial in add_arr]
        
        succeeded = len([ip for v in models_dict for m in models_dict[v] for ip in models_dict[v][m]])
        
        report = ('📓 <b>Инвентаризация</b>\n'
                  'Из заббикса взял {} устройств, {} из них успешно опрошены.'.format(len(ip_dict), succeeded))
        if dead_vars:
            report = report+'\n<b>Устройства исключены:</b>\n'
            report = report+'<code>'+'\n'.join(d['ip']+' '+d['name'] for d in dead_vars)+'</code>'
        
        if add_vars:
            report = report+'\n<b>Устройства добавлены:</b>\n'
            report = report+'<code>'+'\n'.join(d['ip']+' '+d['name'] for d in add_vars)+'</code>'
            
        error_count = (len(failed_dict['no serial'])+
                       len(failed_dict['no model'])+
                       len(failed_dict['no access'])+
                       len(failed_dict['unknown'])+
                       len(failed_dict['error']))
        ignore_count = len(failed_dict['ignored'])
        silent_count = (len(failed_dict['no communication'])+
                       len(failed_dict['no ping']))
        
        
        report = report+'\nОшибок при опросе: {}'.format(error_count)
        report = report+'\nНе ответили на запросы: {}'.format(silent_count)
        report = report+'\nПроигнорированы: {}'.format(ignore_count)
            
        report = report+link_msg
            
        bot.send_message('-1001299276887', report, parse_mode='html')
                  
    except Exception as err_message:
        logger.error('Ошибка в функции telegram_report {}'.format(str(err_message)))    
    
if __name__ == '__main__':
    try:
        parser = argparse.ArgumentParser(description='ip')
        parser.add_argument('str', nargs='?', type=str, help='ip')
        args = parser.parse_args()
        if args.str: print('got arg: '+args.str)
        
        logger = logging.getLogger('my_logger')
        if args.str: handler = logging.StreamHandler()
        else: 
            handler = logging.FileHandler(config.logs_folder+strftime("%A", gmtime())+'.log', 'w+')
        formatter = logging.Formatter("[%(asctime)s] %(levelname)s - %(message)s")
        handler.setLevel(logging.INFO)
        handler.setFormatter(formatter)
        logger.setLevel(logging.INFO)
        logger.addHandler(handler)
        
        z = ZabbixAPI(config.zabbix_addr, 
                    user=config.zabbix_username, 
                    password=config.zabbix_password)
        
        hosts = z.host.get(monitored_hosts=1, output='extend')
        interfaces = z.hostinterface.get()
        
        failed_dict = {'no serial': [],
                       'no model': [],
                       'no access': [],
                       'unknown': [],
                       'ignored': [],
                       'no communication': [],
                       'no ping': [],
                       'error': []}
        
        models_dict = {}
        sql_add = {}
        sql_state = {}
        
        connection = local_sql_conn()
        #заберем таблички, переделаем их в словари
        inventory_dict = {x['serial']:x for x in sql_get_inventory(connection, logger)}
        inventory_vars_dict = {x['ip']:x for x in sql_get_inventory_vars(connection, logger)}
        
        date = format(datetime.now(), '%Y-%m-%d')
        
        ip_dict = {}

        for host in hosts:
            ip = get_interface(host['hostid'], interfaces)
            if '10.60.' in ip or '188.68.187.' in ip or '10.61.' in ip:
                ip_dict[ip] = host['name']
        

        # ip есть в базе, но не в заббиксе
        for ip in inventory_vars_dict:
            if ip not in ip_dict and inventory_dict[inventory_vars_dict[ip]['serial']]['monitored'] == 1:
                #sql_off_device(connection, inventory_vars_dict[ip]['serial'], logger)
                sql_state.setdefault(inventory_vars_dict[ip]['serial'], []).append('down')
                sql_state.setdefault(inventory_vars_dict[ip]['serial'], []).append('dead')
                logger.info('{}:{} announced suspended (not in zabbix anymore)'.format(ip, 
                                            inventory_vars_dict[ip]['serial']))
                
        # Если указали ип (аргументом) то выкидываем в помойку ip_dict приготовленный из заббикса, и юзаем свой ип
        if args.str and re.match('\d+\.\d+\.\d+\.\d+',args.str):
            hname = hostname_by_id(z, hostid_by_ip(z, args.str))[0]['name']
            print(hname)
            #getModel(args.str, hname, models_dict, inventory_dict, inventory_vars_dict, date, logger)
            ip_dict = {args.str:hname}
            print(ip_dict)
            logger.info('models_dict: \n'+str(models_dict))
            
        z.user.logout()  
                
        with ThreadPoolExecutor(max_workers=100) as executor:
            results = [executor.submit(getModel, ip, ip_dict[ip], models_dict, 
                                       inventory_dict, inventory_vars_dict, date, logger) for ip in ip_dict]
        
        for v in models_dict:
            print(v+'\n')
            for m in models_dict[v]:
                print('  '+m+'\n'+str(models_dict[v][m]))
        print('-----')
        print('No serial number: {}'.format(str(failed_dict['no serial'])))
        print('No model: {}'.format(str(failed_dict['no model'])))
        print('No access: {}'.format(str(failed_dict['no access'])))
        print('Unknown SysObjectID: {}'.format(str(failed_dict['unknown'])))
        print('Ignored: \n')
        for ip in failed_dict['ignored']:
            print(' {}: {}'.format(ip, ip_dict[ip]))
        print('No communication:\n')
        for ip in failed_dict['no communication']:
            print(' {}: {}'.format(ip, ip_dict[ip]))
        print('No Ping:\n')
        for ip in failed_dict['no ping']:
            print(' {}: {}'.format(ip, ip_dict[ip]))
        
        # Тут пишем в базу все накопленные знания
        sql_action(connection, sql_add, sql_state, date)
        print(sql_state)
        print(sql_add)
        if len(ip_dict) > 1:
            # Если не один только ип рассматривали, записываем статистику девайсов в таблицу InventoryDynamic
            sql_upd_dynamic(connection, date, logger)
            # И засылаем отчет в телеграм
            telegram_report(connection, sql_state, sql_add, models_dict, ip_dict, failed_dict)
        connection.close()
    except Exception as err_message:
        logger.error(str(err_message))