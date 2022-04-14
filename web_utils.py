# -*- coding: utf-8 -*-
#!/usr/bin/python3
#Python 3.7.3

import config, ipaddress, logging, webbrowser, re, json, time
import urllib, subprocess, requests, secrets, string, smtplib
import pymysql.cursors

from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler
from pyzabbix import ZabbixAPI
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask
from flask import request
from flask import redirect, url_for
from flask import render_template
from flask import flash
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate
from lib.zabbix_common import zabbix_common
from lib.snmp_common import snmp_common
from lib.configurator.configurator import configurator
from lib.configurator.sql import nodes_sql_tables
from lib.erth_inventory import erth_inventory
from lib.ddm import ddm
from lib.zabbix95 import zabbix95
from lib.ipv4_table import ipv4_table
from lib.common import common_mysql
from lib.inventory.mysql import inventory_mysql
from lib.network_avalibility.avalibility_report import avalibility

#from lib.snmp_common import snmp_common
web_utils_app = Flask(__name__)

logger = logging.getLogger('my_logger')
handler = RotatingFileHandler(config.log_file, maxBytes=100000, backupCount=5)
formatter = logging.Formatter(
        "[%(asctime)s] {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s")
handler.setLevel(logging.INFO)
handler.setFormatter(formatter)
logger.setLevel(logging.INFO)
logger.addHandler(handler)

def hostid_by_ip(zabbix_conn, ip):
    try:
        host_iface = zabbix_conn.hostinterface.get(output=['hostid', 'ip'], filter={'ip': ip})
        if not host_iface:
            return None
        return host_iface[0]['hostid']
    except Exception as err_message:
        logger.error('Ошибка в функции hostid_by_ip {}'.format(str(err_message)))
        
# achtung! эта функция может вернуть больше одного id
def hostid_by_name(zabbix_conn, name, logger):
    try:
        dev_arr = zabbix_conn.host.get(search={'name': name}, 
                                       output=['hostid','host','name'])
        if not dev_arr:
            dev_arr = zabbix_conn.host.get(search={'host': name}, 
                                           output=['hostid','host','name'])
            if not dev_arr:
                return None
        return dev_arr # [{'hostid': '10934', 'host': 'BMor18-cs2', 'name': 'BMor18-cs2'}]
    except Exception as err_message:
        logger.error('Ошибка в функции hostid_by_name {}'.format(str(err_message)))
        
def hostname_by_id(zabbix_conn, hostid):
    try:
        dev_arr = zabbix_conn.host.get(filter={'hostid': hostid}, 
                                       output=['hostid','host','name'])
        if not dev_arr:
            return None
        return dev_arr
    except Exception as err_message:
        logger.error('Ошибка в функции hostname_by_id {}'.format(str(err_message)))
        
def ip_by_hostname(hostname, logger):
    try:
        zabbix_conn = ZabbixAPI(config.zabbix_link, 
                                user=config.zabbix_user, 
                                password=config.zabbix_pass)
        interfaces = zabbix_conn.hostinterface.get()
        hid = hostid_by_name(zabbix_conn, hostname, logger)
        zabbix_conn.user.logout()
        if not hid: return None, None
        for hostid in hid:
            # filter incomlite names such as 'Pirog17' instead of 'Pirog17-cr1'
            if (hostid['host'].lower() == hostname.lower() or 
                hostid['name'].lower() == hostname.lower()):
                for interface in interfaces:
                    if interface['hostid'] == hostid['hostid']:
                        return interface['ip'], hostid['hostid']
        return None, None
    except Exception as err_message:
        logger.error('Ошибка в функции ip_by_hostname {}'.format(str(err_message)))
        return None, None
        
def mapid_by_hostid(zabbix_conn, hostid):
    try:
        all_elements_on_maps = zabbix_conn.map.get(selectSelements="extend", 
                                                   output='selements')
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


def month_back(date, m):
    # берет дату и кол-во месяцев (m), возвращает имя месяца.год для даты минус m
    for month in range(0, m):
        date = date - timedelta(days = date.day)
    return(date)

    
def make_session_id():
    alphabet = string.ascii_letters + string.digits
    sid = ''.join(secrets.choice(alphabet) for i in range(8))
    return sid
    
    
def sql_add_notification_history(nid, ndate, wdate, subject, 
                                 addr, devs, emails, body, logger):
    try:
        connection = common_mysql.local_sql_conn(logger)
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
        connection = common_mysql.local_sql_conn(logger)
        req = ("select id, notif_date, works_date from webutils_notif_history group by id ORDER BY notif_date DESC")
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
        connection = common_mysql.local_sql_conn(logger)
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
            
            # собираем SysObjectID из за mikrotik RB260 у которых дискрипшны прям в названиях интерфейсов. 
            # Заодно проверяем доступность железки.
            sysobjectid, community = snmp_common.get_sysobjectid(ip, logger)
            if not sysobjectid:
                devices_arr.remove(ip)
                contract_dict[ip]['alive'] = 0
                # если девайс недоступен, то ставим "заглушку" чтобы в таблице дырок небыло
                contract_dict[ip]['contracts'][''] = ''
                # cont_num используется в темплейте client_notification_out для правильной генерации таблицы
                contract_dict[ip]['cont_num'] = len(contract_dict[ip]['contracts'])
                continue
            else:
                contract_dict[ip]['alive'] = 1
                if sysobjectid == 'iso.3.6.1.4.1.14988.2':
                    descoid = '1.3.6.1.2.1.31.1.1.1.1'
                else: descoid = '1.3.6.1.2.1.31.1.1.1.18'
            
            # собираем дескрипшны
            descs, community = snmp_common.generic_request(ip, descoid, logger, omit_oid=True)
            if not descs: 
                logger.error('{}: Не нашел подписей на портах'.format(ip))
                continue
            descs_arr = [x.strip('STRING: ').strip('"') for x in descs.split('\n')]
            for desc in descs_arr:
                if not desc: continue
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
                    if any(x in desc for x in ['UP', 'U_', 'PP_']):
                        continue
                    else:
                        ipx, host_id = ip_by_hostname(downlink.group(1), logger)
                        # loop detection
                        if ipx and ipx in all_devices_arr:
                            continue
                        elif ipx and ipx not in all_devices_arr:
                            logger.info('DEV_ARRR {} {}'.format(ipx, devices_arr))
                            devices_arr.append(ipx)
                            contract_dict[ipx] = {'name': downlink.group(1),
                                                  'ip': ipx,
                                                  'host_id': host_id,
                                                  'address': '',
                                                  'uplink': contract_dict[ip]['name'],
                                                  'cont_num': '1',
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
            # cont_num используется в темплейте client_notification_out для правильной генерации таблицы
            contract_dict[ip]['cont_num'] = len(contract_dict[ip]['contracts'])
            devices_arr.remove(ip)
        except Exception as err_message:
            logger.error('Ошибка в функции client_notification_get_emails {}: {}'.format(ip,str(err_message)))
            return str(err_message)
    
    logger.info(str(contract_dict))
    return contract_dict

def zabbix_add_maintenance(tcode_start, tcode_end, hostids_arr, devices, config, logger):
    try:
        timeperiod = {'timeperiod_type': 0,
                      'every': 1,
                      'dayofweek': 0,
                      'day': 1,
                      'period': int(tcode_end-tcode_start),
                      'start_date': int(tcode_start)
                      }
        name = 'Плановые работы {}'.format(format(datetime.fromtimestamp(tcode_start), '%d.%m.%Y %H:%M'))
        descr = '{}'.format(devices)
        zabbix_conn = ZabbixAPI(config.zabbix_link, 
                                user=config.zabbix_user, 
                                password=config.zabbix_pass)
        # return: {'jsonrpc': '2.0', 'result': {'maintenanceids': ['17']}, 'id': '1'}
        zabbix_conn.do_request('maintenance.create', params={'name': name,
                                                     'maintenance_type': '0',
                                                     'description': descr,
                                                     'active_since': int(tcode_start),
                                                     'active_till': int(tcode_end),
                                                     'hostids': hostids_arr,
                                                     'timeperiods': [timeperiod]
                                                    }
                      )
        zabbix_conn.user.logout()
        
    except Exception as err_message:
        logger.error('Ошибка в функции zabbix_add_maintenance {}'.format(str(err_message)))
    
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
            if dev_arr[0]['inventory']['inventory_mode'] != '1':
                # включаем
                inv_on = zabbix_conn.host.update(hostid=dev_arr[0]['hostid'], 
                                                 inventory_mode = 1)
                if inv_on: 
                    logger.info('Turned on inventory for {}'.format(dev_arr[0]['host']))
                    contract_dict[dev]['inventory'] == '1'
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
        if device_dict['inventory'] != '1':
            inv_on = zabbix_conn.host.update(hostid=device_dict['hostid'], 
                                             inventory_mode = 1)
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

#def create_msg_notification_tg(wdate_dt, edate_dt, time_span, addr_list, device_list, logger):
#    try:
#        w_start = format(wdate_dt, '%d.%m.%y %H:%M')
#        w_end = format(edate_dt, '%d.%m.%y %H:%M')
#        message_text = config.notifier_tg_msg.format(w_start, w_end, time_span, addr_list, device_list)
#        return message_text
#    except Exception as err_message:
#        logger.error('Ошибка в функции create_msg_notification_tg {}'.format(str(err_message)))
        
def sql_add_notification_tg(str_now, message_text, msg_date, telegram_id, logger):
    try:
        connection = common_mysql.local_sql_conn(logger)
        req = ("INSERT into NotifierTG(message, telegram_id, msg_date, cur_date)"
               "values ('{}', '{}', '{}', '{}')".format(message_text, 
                                                        telegram_id,
                                                        msg_date, 
                                                        str_now))
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
                    for mapid in map_ids:
                        mname = mapname_by_mapid(zabbix_conn, mapid)
                        maps_arr.append([mname, config.zabbix_link+'/zabbix.php?action=map.view&sysmapid='+mapid])
                return render_template("maps_out.html", maps_arr=maps_arr)
                
            # if hostname returns many ids
            devices_dict = {}
            for devid in hosts:
                devices_dict[devid['name']] = devid['hostid']
                
            return render_template("devices_out.html", 
                                   devices_arr=sorted(devices_dict),
                                   devices_dict=devices_dict)
                    
        
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
                for mapid in map_ids:
                    mname = mapname_by_mapid(zabbix_conn, mapid)
                    map_link = config.zabbix_link+'/zabbix.php?action=map.view&sysmapid='+mapid
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
        maps_arr.append([map_name, config.zabbix_link+'/zabbix.php?action=map.view&sysmapid='+mapid])
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
        connection = common_mysql.local_sql_conn(logger)
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
    connection = common_mysql.local_sql_conn(logger)
    now = datetime.now()
    headers = ['Type','Vendor','Model']
    #сделаем массив с названиями последних 12 месяцев
    headers += (month_back(now, x).strftime('%b.%y') for x in reversed(range(0, 12)))
    models = []
    # получим массив диктов вида {'type': 'switch', 'vendor': 'Cisco', 'model': 'SF352-08'}
    db = inventory_mysql.get_dynamic_models(connection, logger)
    for model in db:
        # из inventoryDynamic выгружаем данные по кол-ву по конкретной модели за последний год
        data = inventory_mysql.get_dynamic_month(connection, model['model'], logger)
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
        for i in range(len(model)-3):
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
        
    connection = common_mysql.local_sql_conn_l(logger)
    # пробуем найти по имени сначала
    inv_data, vars_last, vars_all = inventory_mysql.get_ipname(connection, dev, logger)
    # если нашли больше одного девайса
    if inv_data:
        return render_template('inventory_many2.html', vars_all=vars_all, req=dev)
    # если не нашли ничего, пробуем по серийнику
    if not inv_data:
        inv_data, vars_last, vars_all = inventory_mysql.get_serial(connection, dev, logger)
    connection.close()
    # снова ничего не нашли, сдаемся
    if not inv_data:
        return inventory()
    # по дефолту возвращаем шаблон под один девайс
    return render_template("inventory_one.html", inv_data=inv_data, vars_last=vars_last, vars_all=vars_all)

@web_utils_app.route("/inventory_model_<model>")
def inventory_model(model):
    connection = common_mysql.local_sql_conn_l(logger)
    model = urllib.parse.unquote(model).replace('slash','/')
    vars_all = inventory_mysql.get_vmt(connection, model, 'model', logger)
    #if len(vars) == 1:
    #    return inventory_serial(vars[0][0])
    connection.close()
    return render_template('inventory_many.html', vars_all=vars_all)

@web_utils_app.route("/inventory_vendor_<vendor>")
def inventory_vendor(vendor):
    connection = common_mysql.local_sql_conn_l(logger)
    vendor = urllib.parse.unquote(vendor).replace('slash','/')
    vars_all = inventory_mysql.get_vmt(connection, vendor, 'vendor', logger)
    connection.close()
    return render_template('inventory_many2.html', vars_all=vars_all, req=vendor)

@web_utils_app.route("/inventory_type_<dtype>")
def inventory_dtype(dtype):
    connection = common_mysql.local_sql_conn_l(logger)
    dtype = urllib.parse.unquote(dtype).replace('slash','/')
    vars_all = inventory_mysql.get_vmt(connection, dtype, 'type', logger)
    connection.close()
    return render_template('inventory_many2.html', vars_all=vars_all, req=dtype)
    
@web_utils_app.route("/inventory_serial_<serial>")
def inventory_serial(serial):
    connection = common_mysql.local_sql_conn_l(logger)
    serial = urllib.parse.unquote(serial).replace('slash','/')
    inv_data, vars_last, vars_all = inventory_mysql.get_serial(connection, serial, logger)
    connection.close()
    return render_template("inventory_one.html", inv_data=inv_data, vars_last=vars_last, vars_all=vars_all)

@web_utils_app.route("/inventory_suspended")
def inventory_suspended():
    connection = common_mysql.local_sql_conn_l(logger)
    suspended_arr = inventory_mysql.get_suspended(connection, logger)
    connection.close()
    return render_template("inventory_suspended.html", suspended_arr=suspended_arr)

###
### /INVENTORY
###

###
### NOTIFICATION (Email)
###

@web_utils_app.route("/client_notification")
def client_notification(msg=''):
    # чистим старые сессии если есть
    common_mysql.sql_clean_sessions(logger)
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
        ip, host_id = ip_by_hostname(hn, logger)
        if not ip: 
            return client_notification(msg='Не смог определить IP для {}'.format(hn))
        devices_arr.append(ip)
        contract_dict[ip] = {'name': hn, 
                             'ip': ip,
                             'host_id': host_id,
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
    logger.info('contract_dict: {}'.format(str(contract_dict)))
    contract_dict_json = json.dumps(contract_dict, ensure_ascii=False)

    # генерячим session id и записываем его вместе с имейлами в mysql
    sid = make_session_id()
    today_date = format(datetime.now(), '%Y-%m-%d')
    common_mysql.sql_set_session(sid, contract_dict_json, today_date, logger)
    
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
    date_start = datetime.strptime(request.form['time_date'], '%Y-%m-%d')
    text_vars['time_date'] = format(date_start, '%d.%m.%Y')
    text_vars['time_date_end'] = text_vars['time_date']
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
    #ТУт проблема если мы начинаем в один день и заканчиваем в другой.
    if time_end == time_start:
        msg = ('Проверь время работ. Начало в {} и '
               'конец в {}, что-то не сходится'.format(text_vars['time_start'], 
                                                       text_vars['time_end']))
    elif time_end < time_start:
        day = timedelta(minutes=1440)
        text_vars['time_date_end'] = format(date_start + day, '%d.%m.%Y')
        time_end = time_end + day
    
    max_span = time_end - time_start
    if max_span < time_span:
        msg = ('Продолжительность перерыва ({} мин) '
               'не может быть больше чем длительность '
               'работ в целом.<br>C {} до {} это {} минут максимум<br>'.format(
                   text_vars['time_span'],
                   text_vars['time_start'],
                   text_vars['time_end'],
                   str(int(max_span.seconds/60)),
               )
              )
    
    checked = request.form.getlist('mail_send')
    logger.info('CHECKED: {}'.format(str(checked)))
    addresses = {key.replace("_address_fld", ''):str(request.form.get(key)) 
                 for key in request.form.keys() if "_address_fld" in key}
    logger.info('addresses: {}'.format(str(addresses)))
    sid_storage = common_mysql.sql_get_session(sid, logger)
    logger.info('sid_storage: {}'.format(str(sid_storage)))
    if not sid_storage: 
        return client_notification(msg='Проблема с SQL')
    contract_dict = json.loads(sid_storage[0]['storage'].replace('\t', '').replace('\\"', '').replace('\\', ''))
    
    # для создания обслуживания в заббиксе сделаем лист с host_id (в заббиксе) всех устройств в цепочке
    host_id_arr = [contract_dict[dev]['host_id'] for dev in contract_dict]
    
    # убираем не отмеченные девайсы из списка на рассылку
    excluded = [contract_dict.pop(dev) for dev in list(contract_dict) 
                if dev not in checked]
    # убираем девайсы без договоров из списка на рассылку
    no_contracts_found = [contract_dict.pop(dev) for dev in list(contract_dict) 
                          if '' in contract_dict[dev]['contracts']]
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
        storage = {'addr_d': addr_d, 'text_vars': text_vars, 'hostids': host_id_arr}
        storage_json = json.dumps(storage, ensure_ascii=False)
        common_mysql.sql_upd_session(sid, storage_json, logger)
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

    sid_storage = common_mysql.sql_get_session(sid, logger)
    if not sid_storage: 
        nf_logger.error('Проблема с SQL (Не считал данные)')
        return client_notification(msg='Проблема с SQL (Не считал данные)')
    #logger.info('SID STORE: {}'.format(sid_storage[0]['storage']))
    data_dict = json.loads(sid_storage[0]['storage'])
    if not data_dict['addr_d']:
        nf_logger.error('Проблема с SQL (Не смог распаковать данные)')
        return client_notification(msg='Проблема с SQL (Не смог распаковать данные)')
    common_mysql.sql_del_session(sid, logger)
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
    edate = '{} {}'.format(data_dict['text_vars']['time_date_end'], 
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
    msg_date = format(wdate_dt - timedelta(minutes = 30), '%Y-%m-%d %H:%M:%S')
    w_start = format(wdate_dt, '%d.%m.%y %H:%M')
    w_end = format(edate_dt, '%d.%m.%y %H:%M')
    message_text = config.notifier_tg_msg.format(w_start, w_end, data_dict['text_vars']['time_span'], addr_list, device_list)

    # Создаем уведомление с телегу.
    # You should make an API for this one.
    sql_add_notification_tg(ndate, 
                            message_text, 
                            msg_date, 
                            config.notifier_tg_id, 
                            logger)
    
    # создаем обслуживание девайсов в заббиксе
    # эту функцию решили пока что не включать.
    #zabbix_add_maintenance(wdate_dt.timestamp(), 
    #                       edate_dt.timestamp(), 
    #                       data_dict['hostids'], 
    #                       device_list,
    #                       config, 
    #                       logger)
        
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
### /NOTIFICATION (Email)
###


###
### NOTIFIER (Telegram)
###

def sql_get_notifications(logger):
    try:
        connection = common_mysql.local_sql_conn(logger)
        req_active = ("select * from NotifierTG")
        req_history = ("select * from NotifierTG_history")
        with connection.cursor() as cursor:
            cursor.execute(req_active)
            active = cursor.fetchall()
            cursor.execute(req_history)
            history = cursor.fetchall()
        connection.close()
        return active, history
    except Exception as err_message:
        logger.error('Ошибка в функции sql_get_notifications {}'.format(str(err_message)))
        
def sql_del_notification(nid):
    try:
        connection = common_mysql.local_sql_conn(logger)
        req = ("delete from NotifierTG where id = '{}'".format(nid))
        with connection.cursor() as cursor:
            cursor.execute(req)
        connection.commit()
        connection.close()
    except Exception as err_message:
        logger.error('Ошибка в функции sql_del_notification {}'.format(str(err_message)))
    
        
@web_utils_app.route("/notifier")
def notifier(msg=''):
    notifications, history = sql_get_notifications(logger)
    # подменяем id каналов в телеге на имена. Хардкод, словарь в конфиге лежит.
    for x in range(len(notifications)):
        if notifications[x]['telegram_id'] in config.tg_id_name_dict:
            notifications[x]['telegram_id'] = config.tg_id_name_dict[notifications[x]['telegram_id']]
    for x in range(len(history)):
        if history[x]['telegram_id'] in config.tg_id_name_dict:
            history[x]['telegram_id'] = config.tg_id_name_dict[history[x]['telegram_id']]
    today_date = format(datetime.now(), '%Y-%m-%d')
    return render_template("notifier.html",
                           msg = msg,
                           today_date = today_date,
                           active_notifications = notifications,
                           history = history)
    
@web_utils_app.route("/notifier_create", methods=['POST', 'GET'])
def notifier_create():
    if request.method == 'GET':
        return redirect(url_for('notifier'))
    now = datetime.now()
    logger.error('NOW')
    ndate = format(now, '%Y-%m-%d %H:%M:%S')
    logger.error('NOW STRING')
    telegram_chat = request.form['telegram_chat_fld']
    logger.error('CHAT ID {}'.format(telegram_chat))
    time_date = request.form['time_date']
    logger.error('DATE {}'.format(time_date))
    time_start = ('{:02d}:{:02d}:00'.format(
                                    int(request.form['time_start_hr']),
                                    int(request.form['time_start_min'])))
    logger.error('TIME {}'.format(time_start))
    msg_date = '{} {}'.format(time_date, time_start)
    message_text = request.form['msg_textarea']
    sql_add_notification_tg(ndate, message_text, msg_date, telegram_chat, logger)

    msg = "Уведомление создано"
    return notifier(msg)
    
@web_utils_app.route("/notifier_delete_<nid>", methods=['POST', 'GET'])
def notifier_delete(nid):
    if request.method == 'GET':
        return redirect(url_for('notifier'))
    sql_del_notification(nid)
    msg = "Уведомление удалено"
    return notifier(msg)


###
### /NOTIFIER (Telegram)
###

###
### Avalibility_report
###
        
@web_utils_app.route("/avalibility_report", methods=['POST', 'GET'])
def avalibility_report(msg=''):

    #
    #min_date = format(datetime.now() - timedelta(days = 290), '%Y-%m-%d')

    if request.method == 'GET':
        now = datetime.now()
        fromd = int(datetime.strptime('01.'+month_back(now, 1).strftime("%m.%Y"),'%d.%m.%Y').timestamp())
        tilld = int(datetime.strptime('01.'+now.strftime("%m.%Y"),'%d.%m.%Y').timestamp())
    if request.method == 'POST':
        date_from = datetime.strptime(request.form['avalibility_report_date_from'], '%Y-%m-%d')
        date_to = datetime.strptime(request.form['avalibility_report_date_to'], '%Y-%m-%d')
        if (date_to - date_from).days > 290:
            msg = 'Заббикс не хавает больше 290 дней за раз. Я потом починю =)'
            date_from = date_to - timedelta(days = 1)
        fromd = date_from.timestamp()
        tilld = date_to.timestamp()
    fromd_human_str = format(datetime.fromtimestamp(fromd), '%d.%m.%Y')
    tilld_human_str = format(datetime.fromtimestamp(tilld), '%d.%m.%Y')
    fromd_str = format(datetime.fromtimestamp(fromd), '%Y-%m-%d')
    tilld_str = format(datetime.fromtimestamp(tilld), '%Y-%m-%d')
    
    (report, 
     report_grouped, 
    ) = avalibility.get_report(fromd, tilld, logger)
    (buttons_script, 
     buttons,
     table_sorter_script,
    ) = avalibility.js_generator(report_grouped, logger)
        
    return render_template("avalibility_report.html",
                           msg = msg,
                           fromd_str = fromd_str,
                           tilld_str = tilld_str,
                           fromd_human_str = fromd_human_str,
                           tilld_human_str = tilld_human_str,
                           report = report,
                           report_grouped = report_grouped,
                           buttons_script = buttons_script,
                           buttons = buttons,
                           table_sorter_script = table_sorter_script)

###
### /Avalibility_report
###

###
### Zabbix95
###
@web_utils_app.route("/zabbix95", methods=['POST', 'GET'])
def zabbix95_init(msg=''):

    zabbix95_ifaces = zabbix95.get_ifaces(logger)
    zabbix95_ifaces_sorted = sorted(zabbix95_ifaces.keys())
    span_dict = {neigh: sum(len(zabbix95_ifaces[neigh][node]) 
                 for node in zabbix95_ifaces[neigh]) 
                 for neigh in zabbix95_ifaces}
    validation_msg = zabbix95.validate_base(zabbix95_ifaces, logger)
    
    return render_template("zabbix95.html",
                           msg = msg,
                           validation_msg = validation_msg,
                           zabbix95_ifaces = zabbix95_ifaces,
                           zabbix95_ifaces_sorted = zabbix95_ifaces_sorted,
                           span_dict = span_dict,)

@web_utils_app.route("/zabbix95_add", methods=['POST', 'GET'])
def zabbix95_add():
    if request.method == 'GET':
        return redirect(url_for('zabbix95'))
       
    neighbour = request.form['zabbix95_add_name']
    node = request.form['zabbix95_add_node']
    iface = request.form['zabbix95_add_iface']
    
    interface, msg = zabbix95.validate_iface(neighbour, node, iface, logger)
    
    if interface:
        zabbix95.sql_add_iface(neighbour, node, interface, logger)
    
    return zabbix95_init(msg)

@web_utils_app.route("/zabbix95_delete_<iface_id>", methods=['POST', 'GET'])
def zabbix95_delete(iface_id):
    if request.method == 'GET':
        return redirect(url_for('zabbix95'))
    zabbix95.sql_del_iface(iface_id, logger)
    msg = "Интерфейс удален"
    return zabbix95_init(msg)
    
@web_utils_app.route("/zabbix95_report", methods=['POST', 'GET'])
def zabbix95_report():
    if request.method == 'GET':
        return redirect(url_for('zabbix95'))
       
    date_from = datetime.strptime(request.form['zabbix95_report_date_from'], '%Y-%m-%d')
    date_to = datetime.strptime(request.form['zabbix95_report_date_to'], '%Y-%m-%d')
    fromd = int(date_from.timestamp())
    tilld = int(date_to.timestamp())
    fromd_str = format(date_from, '%d.%m.%Y')
    tilld_str = format(date_to, '%d.%m.%Y')
    checked = request.form.getlist('zabbix95_report_check')
    if not checked:
        msg = 'Галочку поставь кого опрашивать'
        return zabbix95_init(msg)
    
    ifaces_data = zabbix95.get_ifaces(logger)
    
    report, ifaces_data, aggr_data = zabbix95.create_report(ifaces_data, 
                                                            fromd, 
                                                            tilld, 
                                                            checked, 
                                                            logger)
    if type(report) == str:
        return zabbix95_init(report)

    report = '\n'.join(report)
    
    links = zabbix95.create_csv(ifaces_data, 
                                aggr_data, 
                                date_from, 
                                date_to, 
                                checked, 
                                logger)

    return render_template("zabbix95_report.html", 
                           report=report, 
                           fromd_str=fromd_str, 
                           tilld_str=tilld_str,
                           links = links)
    
###
### /Zabbix95
###

###
### DDM
###
    
        
@web_utils_app.route("/ddm_report", methods=['POST', 'GET'])
def ddm_report():
    if request.method == 'GET':
        return render_template("ddm_report.html")
    else:
        alarm_dict = ddm.get_alarms(logger)
        return render_template("ddm_report.html",
                               alarm_dict = alarm_dict)

###
### /DDM
###


###
### Configurator
###
        
@web_utils_app.route("/configurator", methods=['GET'])
def configurator_init(msg=''):
    hostname_list = zabbix_common.get_hostname_list(logger)
    
    #conf_nodes = nodes_sql_tables.get_nodes(logger)
    #vlan_ranges = nodes_sql_tables.get_vlan_ranges(logger)
    #ip_ranges = nodes_sql_tables.get_ip_ranges(logger)
    
    # агрегируем данные для вывода в таблице. 
    #nodes_dict = {}
    #for n in conf_nodes:
    #    #nodes_dict[n['node']] = n.copy()
    #    n['vlan_ranges'] = ', '.join([f'{x["range_start"]}-{x["range_end"]}' 
    #                                 for x in vlan_ranges 
    #                                 if x['node'] == n['node']])
    #    n['ip_ranges'] = ', '.join([f'{x["range_start"]}-{x["range_end"]}' 
    #                               for x in ip_ranges 
    #                               if x['node'] == n['node']])

    
    return render_template("configurator.html",
                           msg = msg,
                           hostname_list = hostname_list,
                           policer_dict = config.policer_dict,
                           )

@web_utils_app.route("/configurator_edit_node_<node_id>", methods=['POST', 'GET'])
def configurator_edit_node(node_id):
    if request.method == 'GET':
        return configurator_init()
    #conf_nodes = nodes_sql_tables.get_nodes(logger)
    #vlan_ranges = nodes_sql_tables.get_vlan_ranges(logger)
    #ip_ranges = nodes_sql_tables.get_ip_ranges(logger)
    #
    #nodes_list = [h['node'] for h in conf_nodes]
    #hostname_list = zabbix_common.get_hostname_list(logger)
    #hostname_list = [h for h in hostname_list 
    #                 if ('-cr' in h or '-ds' in h) and h not in nodes_list]
    #
    #nodes_sql_tables.edit_node(node_id, logger)
    #return render_template("configurator_edit_node.html",
    #                       node_id = node_id,
    #                       conf_nodes = conf_nodes,
    #                       vlan_ranges = vlan_ranges,
    #                       ip_ranges = ip_ranges,
    #                       hostname_list = hostname_list,)
    return configurator_init(msg="Сорямба, пока что не умею")

@web_utils_app.route("/configurator_add_node", methods=['GET'])
def configurator_add_node():
    #if request.method == 'GET':
    #    return configurator_init()
    
    conf_nodes = nodes_sql_tables.get_nodes(logger)
    nodes_list = [h['node'] for h in conf_nodes]
    hostname_list = zabbix_common.get_hostname_list(logger)
    hostname_list = [h for h in hostname_list 
                     if ('-cr' in h or '-ds' in h) and h not in nodes_list]
    
    return render_template("configurator_add_node.html",
                           hostname_list = hostname_list,)

@web_utils_app.route("/configurator_commit_node", methods=['POST', 'GET'])
def configurator_commit_node():
    if request.method == 'GET':
        return configurator_init()
    hostname = request.form['hostname_fld']
    mpls = 'mpls_fld' in request.form
    vpls = 'vpls_fld' in request.form
    ip_unnum = 'ip_unnum_fld' in request.form
    ip_common = 'ip_common_fld' in request.form
    loopback = request.form['loopback_fld']
    vlan_ranges = request.form.getlist('vlan_ranges_fld[]')
    ip_ranges = request.form.getlist('ip_ranges_fld[]')
    ip_gws = request.form.getlist('ip_gw_fld[]')
    
    for vrange in vlan_ranges:
        vr = vrange.split('-')
        nodes_sql_tables.set_vlan_range(hostname, vr[0], vr[1], logger)
        
    for i, iprange in enumerate(ip_ranges):
        nodes_sql_tables.set_ip_range(node, range_start, range_end, subnet, gateway, logger)
    
    nodes_sql_tables.set_node(hostname, '', mpls, vpls, ip_unnum, ip_common, loopback, logger)
    
    
    msg = f'Узел {hostname} добавлен'
    #msg = 'Узел обновлен'
    msg = [hostname, mpls, vpls, ip_unnum, ip_common, loopback, vlan_ranges, ip_ranges, ip_gws]
    return configurator_init(msg = msg,)

@web_utils_app.route("/configurator_delete_node_<node_id>", methods=['POST', 'GET'])
def configurator_delete_node(node_id):
    if request.method == 'GET':
        return configurator_init()
    nodes_sql_tables.del_node(node_id, logger)
    return configurator_init(msg="Узел удален")


#@web_utils_app.route("/configurator_config", methods=['GET'])
#def configurator_config(msg=''):
#    hostname_list = zabbix_common.get_hostname_list(logger)
#    
#    return render_template("configurator.html",
#                           msg = msg,
#                           hostname_list = hostname_list,
#                           policer_dict = config.policer_dict)
                           
@web_utils_app.route("/configurator_inet_create", methods=['POST'])
def configurator_inet_create(msg=''):
    inet_form = {}
    inet_form['hostname'] = request.form['hostname_fld']
    inet_form['contract'] = request.form['contract_fld'].replace("\\", "&&&")
    inet_form['rate'] = request.form['rate_fld']
    inet_form['name'] = request.form['name_fld'].replace("'", "***").replace('"', "***")
    # replace is needed to put the value into mysql without errors
    inet_form['latin_name'] = request.form['latname_fld']
    inet_form['tasknum'] = request.form['inet_tasknum_fld']
    inet_form['address'] = request.form['addr_fld']
    inet_form['amount_ip'] = request.form['amountip_fld']

    
    host_dict = {}
    # Берем оконечнй хостнейм, собираем с него всю инфу.
    configurator.get_host(inet_form['hostname'], 
                          host_dict, 
                          logger)

    # Проверяем что данные собрались
    if any([x not in host_dict[inet_form['hostname']] for x in ['model', 'ifaces', 'vlans']]): 
        return configurator_init('Не смог опросить {}'.format(inet_form['hostname']))
    if host_dict[inet_form['hostname']]['mpls']: 
        return configurator_init('Девайс {} не может быть конечным'.format(inet_form['hostname']))
    
    # Собираем все не занятые интерфейсы (без дескрипшна или с OFF в дескрипшне)
    ifaces_dict = configurator.get_free_ifaces(host_dict, 
                                               [inet_form['hostname']], 
                                               logger)
    
    # генерим id сессии и складываем host_dict в базу
    storage = {'host_dict': host_dict, 
               'inet_form': inet_form}
    sid = make_session_id()
    date = format(datetime.now(), '%Y-%m-%d')
    storage_json = json.dumps(storage, ensure_ascii=False)
    common_mysql.sql_set_session(sid, storage_json, date, logger)
    
    # Экономим на темплейтах
    next_action = 'configurator_inet_confirm'
    
    #return configurator_init('no can do: {}'.format(host_dict))
    return render_template("configurator_ifcs.html", 
                           ifaces_dict = ifaces_dict, 
                           next_action = next_action,
                           sid = sid,
                           rawdata = [inet_form, host_dict])        
    
@web_utils_app.route("/configurator_inet_confirm_<sid>", methods=['POST'])
def configurator_inet_confirm(sid):
    
    # Забираем из SQL уже собранные данные по конечному девайсу
    sid_storage = common_mysql.sql_get_session(sid, logger)
    if not sid_storage: 
        msg = 'Проблема с SQL (Не считал данные)'
        logger.error(msg)
        return configurator_init(msg)
    data_dict = json.loads(sid_storage[0]['storage'])
    if not 'host_dict' in data_dict:
        msg = 'Проблема с SQL (Не смог распаковать данные)'
        logger.error(msg)
        return configurator_init(msg)
    host_dict = data_dict['host_dict']
    inet_form = data_dict['inet_form']
    # Убиваем сессию. ЭТО НАДО БУДЕТ УБРАТЬ КОГДА НАПИШЕШЬ ПРОДОЛЖЕНИЕ
    #common_mysql.sql_del_session(sid, logger)
    
    # Формируем словарь конечных интерфейсов
    # пример end_iface_dict = {'Avtov17-as0': {'gigabitethernet8': 'access'}}
    end_iface_dict = {inet_form['hostname']: {}}
    if_arr = request.form.getlist('configurator_iface_{}[]'.format(inet_form['hostname']))
    mode_arr = request.form.getlist('configurator_iftype_{}[]'.format(inet_form['hostname']))
    for i, ifc in enumerate(if_arr):
        if ifc == 'None' or mode_arr[i] == 'None': continue
        end_iface_dict[inet_form['hostname']].update({ifc: mode_arr[i]})
    
    # all_links это словарь {host: {iface_id: iface_name}} для всех 
    # линков всех девайсов в цепочке hostname >> MPLS device
    # been_there это список всех девайсов в цепочке hostname >> MPLS device
    # зачем он мне если есть all_links? Отличный вопрос. Отличный. Вопрос. Да.
    logging.error('TEMP inet_form {}'.format(inet_form))
    logging.error('TEMP host_dict {}'.format(host_dict))
    all_links, been_there = configurator.get_hosts(inet_form['hostname'], 
                                                   host_dict, 
                                                   logger,
                                                   to_mpls = False)
    #logger.warning(all_links)
    # Тут убираем лишние интерфейсы, добавляем инфу по типу Trunk/Access
    chain = configurator.get_chain(all_links, 
                                         been_there, 
                                         host_dict, 
                                         logger)

    # Из всех цепочек крафтим путь между всеми конечными узлами
    #vpath = configurator.path_maker(chains, 
    #                                host_dict, 
    #                                endpoints, 
    #                                logger)
    
    #Получаем таблицу ipv4 и формируем список L3 узлов
    ipv4 = ipv4_table.get_ipv4(logger)
    all_nodes = set([r['name'] for r in ipv4 
                     if r['contract'] == 'GW'
                     and 'auto' in r['address']])
    
    # Определяем L3 девайс
    node = [h for h in chain if h in all_nodes]
    if not node:
        msg = 'Не нашел L3 для {}: chain = {}, all nodes = {}'.format(inet_form['hostname'], 
                                                                      [h for h in chain], 
                                                                      all_nodes)
        logger.error(msg)
        return configurator_init(msg)
    elif len(node) > 1:
        msg = 'Слишком много узлов для {} ({})'.format(inet_form['hostname'], node)
        logger.error(msg)
        return configurator_init(msg)
    node = node[0]
        
    # Ищем свободные IP
    for n in range(0, int(inet_form['amount_ip'])):
        msg, ip_addresses = ipv4_table.get_free_ip(ipv4, node, int(inet_form['amount_ip']), logger)
        if msg != 'OK': 
            return configurator_init(msg)
                    
    # Находим свободный влан
    vlan_id = configurator.vlan_finder(chain, host_dict, logger)
    if not vlan_id:
        return configurator_init(msg='Нет свободных вланов для {}'.format(inet_form['hostname']))
    
    # Тут надо подумать. Имя влана по номеру заявки не прокатит.
    vlan_name = 'inet_{}_{}'.format(inet_form['tasknum'], inet_form['latin_name'])
    
    # Рисуем картинку и получаем ссылку на нее
    diagram_link = configurator.diagram_maker(vlan_name,
                                              chain, 
                                              host_dict, 
                                              end_iface_dict, 
                                              [inet_form['hostname']],
                                              node,
                                              logger)
    
    inet_form['tag'] = vlan_id
    inet_form['vlan_name'] = vlan_name
    inet_form['node'] = node
    
    #Отдаем все полученные данные в генератор конфигов. 
    config_dict = configurator.inet_config_maker(inet_form, 
                                                 chain, 
                                                 host_dict, 
                                                 end_iface_dict, 
                                                 ip_addresses, 
                                                 logger)
    
    #Генерим конфиг роутера клиента
    #inet_router_config(inet_form, ip_addresses, logger)
    
    
    storage = {'inet_form': inet_form,
               'config_dict': config_dict, 
               'ip_addresses': ip_addresses}
    storage_json = json.dumps(storage, ensure_ascii=False)
    common_mysql.sql_upd_session(sid, storage, logger)
    
    rawdata = [inet_form, ip_addresses, config_dict, chain, end_iface_dict, host_dict]
    
    return render_template("configurator_confirm.html",
                           diagram_link = diagram_link,
                           config_dict = config_dict,
                           rawdata = rawdata,)

@web_utils_app.route("/configurator_inet_execute_<sid>", methods=['POST'])
def configurator_inet_execute(sid):
    
    # Забираем из SQL анкету, конфиги, ипы
    sid_storage = common_mysql.sql_get_session(sid, logger)
    # Убиваем сессию.
    common_mysql.sql_del_session(sid, logger)
    if not sid_storage: 
        msg = 'Проблема с SQL (Не считал данные сессии {})'.format(sid)
        logger.error(msg)
        return configurator_init(msg)
    data_dict = json.loads(sid_storage[0]['storage'])
    if not 'host_dict' in data_dict:
        msg = 'Проблема с SQL (Не смог распаковать данные)'
        logger.error(msg)
        return configurator_init(msg)
    inet_form = data_dict['inet_form']
    config_dict = data_dict['config_dict']
    ip_addresses = data_dict['ip_addresses']
        
    for ip in ip_addresses['ip']:
        setip = ipv4_table.set_ipv4_address(
                ip, 
                ip_addresses['mask_bits'], 
                inet_form['contract'],
                inet_form['name'].replace("***", "'"),
                inet_form['address'],
                logger,
        )
        
        
    return render_template("configurator_service.html",
                           config_dict = config_dict,
                           rawdata = rawdata,)


@web_utils_app.route("/configurator_vlan_create", methods=['POST'])
def configurator_vlan_create(msg=''):
    # юзер заполнил форму создания влана. 
    # клиенту отдадим форму с интерфейсами на всех хостах для выбора оконечных портов. 
    vlan_form = {}
    endpoints = request.form.getlist('hostname1_fld[]')
    vlan_form['tag'] = request.form['vlan_tag_fld']
    vlan_form['rate'] = request.form['vlan_rate_fld']
    vlan_form['latin_name'] = request.form['vlan_latname_fld'].replace(' ', '_')
    vlan_form['mtu'] = request.form['mtu_fld']
    vlan_form['tasknum'] = request.form['vlan_tasknum_fld']
    vlan_form['contract'] = request.form['vlan_contract_fld']
    #return configurator_init('no can do: {}'.format(hostname1))
    
    #if vlan_form['rate'] not in config.policer_dict:
    #    return configurator_init('Нет полисера для скорости {}'.format(vlan_form['rate']))
    
    host_dict = {}
    # Берем оконечные хостнеймы, собираем с них всю инфу.
    with ThreadPoolExecutor(max_workers=len(endpoints)) as executor:
        [executor.submit(configurator.get_host, 
           hostname,
           host_dict,
           logger) for hostname in endpoints]
    
    # Проверяем что данные собрались
    for h in endpoints:
        if not h in host_dict:
            logger.error('host_dict: {}'.format(host_dict))
            return configurator_init('Не нашел {} в заббиксе'.format(h))
        if any([x not in host_dict[h] 
                for x in ['model', 'ifaces', 'vlans']]): 
            logger.error('Споткнулся на {}'.format(h))
            logger.error('host_dict: {}'.format(host_dict))
            return configurator_init('Не смог опросить {}'.format(h))
        if host_dict[h]['mpls']: return configurator_init('Девайс {} не может быть конечным'.format(h))
    
    # Проверяем что влан не занят
    # Эта валидация лишняя все-таки
    #hl, free_vids = configurator.vlan_validator(vlan_form['tag'], endpoints, host_dict, logger)
    #if hl:
    #    m = 'Влан {} занят на хостах: {}<br>Свободные вланы на выбранных хостах: {}'
    #    return configurator_init(m.format(vlan_form['tag'],
    #                                      ', '.join(hl),
    #                                      free_vids))
        
    # Собираем все не занятые интерфейсы (без дескрипшна или с OFF в дескрипшне)
    ifaces_dict = configurator.get_free_ifaces(host_dict, endpoints, logger)
    
    # генерим id сессии и складываем host_dict в базу
    storage = {'host_dict': host_dict, 
               'endpoints': endpoints,
               'vlan_form': vlan_form}
    sid = make_session_id()
    date = format(datetime.now(), '%Y-%m-%d')
    storage_json = json.dumps(storage, ensure_ascii=False)
    common_mysql.sql_set_session(sid, storage_json, date, logger)
    
    # Экономим на темплейтах
    next_action = 'configurator_vlan_confirm'
    
    #return configurator_init('no can do: {}'.format(host_dict))
    return render_template("configurator_ifcs.html", 
                           ifaces_dict = ifaces_dict,
                           next_action = next_action,
                           sid = sid)        
        
@web_utils_app.route("/configurator_vlan_confirm_<sid>", methods=['POST'])
def configurator_vlan_confirm(sid):
    # Получили данные по оконечным интерфейсам. Можно генерить схему и конфиги.

    
    # Забираем из SQL уже собранные данные по конечным девайсам
    sid_storage = common_mysql.sql_get_session(sid, logger)
    if not sid_storage: 
        logger.error('Проблема с SQL (Не считал данные)')
        return configurator_init(msg='Проблема с SQL (Не считал данные)')
    data_dict = json.loads(sid_storage[0]['storage'])
    if not 'host_dict' in data_dict:
        logger.error('Проблема с SQL (Не смог распаковать данные)')
        return configurator_init(msg='Проблема с SQL (Не смог распаковать данные)')
    host_dict = data_dict['host_dict']
    endpoints = data_dict['endpoints']
    vlan_form = data_dict['vlan_form']
    # Убиваем сессию. ЭТО НАДО БУДЕТ УБРАТЬ КОГДА НАПИШЕШЬ ПРОДОЛЖЕНИЕ
    common_mysql.sql_del_session(sid, logger)
    
    # Формируем словарь конечных интерфейсов
    # пример end_iface_dict = {'Avtov17-as0': {'gigabitethernet8': 'Access'}}
    end_iface_dict = {}
    for d in data_dict['endpoints']:
        if_arr = request.form.getlist('configurator_iface_{}[]'.format(d))
        mode_arr = request.form.getlist('configurator_iftype_{}[]'.format(d))
        end_iface_dict[d] = {}
        for i, ifc in enumerate(if_arr):
            if ifc == 'None' or mode_arr[i] == 'None': continue
            end_iface_dict[d].update({ifc: mode_arr[i]})
        
    # собираем цепочки от каждого конечного девайса до MPLS железки и строим путь влана.
    chains = []
    
    for hostname in endpoints:
        # all_links это словарь {host: {iface_id: iface_name}} для всех 
        # линков всех девайсов в цепочке hostname >> MPLS device
        # been_there это список всех девайсов в цепочке hostname >> MPLS device
        # зачем он мне если есть all_links? Отличный вопрос. Отличный. Вопрос. Да.
        all_links, been_there = configurator.get_hosts(hostname, 
                                                       host_dict, 
                                                       logger)
        #logger.warning(all_links)
        # Тут убираем лишние интерфейсы, добавляем инфу по типу Trunk/Access и пакуем все цепочки в массив.
        chains.append(configurator.get_chain(all_links, 
                                             been_there, 
                                             host_dict, 
                                             logger))

    # Из всех цепочек крафтим путь между всеми конечными узлами
    vpath = configurator.path_maker(chains, 
                                    host_dict, 
                                    endpoints, 
                                    logger)
    
    # Проверяем что влан свободен
    hl, free_vids = configurator.vlan_validator(vlan_form['tag'], 
                                                vpath, 
                                                host_dict, 
                                                logger)
    if hl:
        m = 'Влан {} занят на хостах: {}<br>Свободные вланы в цепочке: {}'
        return configurator_init(m.format(vlan_form['tag'],
                                 ', '.join(hl),
                                 free_vids))
    
    # Тут надо подумать. Имя влана по номеру заявки не прокатит.
    vlan_name = 'l2_{}_{}'.format(vlan_form['tasknum'], vlan_form['latin_name'])
    
    # Рисуем картинку и получаем ссылку на нее
    node = '' # это заглушка, переменная нужна для настройки инета
    diagram_link = configurator.diagram_maker(vlan_name,
                                              vpath, 
                                              host_dict, 
                                              end_iface_dict, 
                                              endpoints,
                                              node, 
                                              logger)
    
    #Отдаем все полученные данные в генератор конфигов. 
    config_dict = configurator.vlan_config_maker(vlan_form, 
                                                 vlan_name, 
                                                 vpath, 
                                                 host_dict, 
                                                 end_iface_dict, 
                                                 endpoints, 
                                                 logger)
    
    
    # Конфиги заливаем в SQL.
    
    rawdata = [all_links, chains, vpath, config_dict, endpoints, end_iface_dict, vlan_form, host_dict]
    ##time.sleep(5)
    #sid = make_session_id()
    #
    # Полученную схему и конфиги показываем юзеру для подтверждения.
    return render_template("configurator_confirm.html",
                           diagram_link = diagram_link,
                           config_dict = config_dict,
                           rawdata = rawdata,)
        
    #return configurator_init('no can do: {}'.format(ifaces_dict))


    
#@web_utils_app.route("/configurator_vlan_maker_<sid>", methods=['POST'])
#def configurator_vlan_maker(sid):
#    pass

        

    ##gvtest(logger)
    
    #



###
### /Configurator
###


###
### ERTH Inventory
###

@web_utils_app.route("/erth_inventory")
def erth_inventory_in(msg=''):
    return render_template("erth_inventory.html", 
                           msg=msg)
        
@web_utils_app.route("/erth_inventory_out", methods=['POST'])
def erth_inventory_out():
    hostname = request.form['text']
    if not hostname: return erth_inventory_in(msg='Нужен хостнейм')
    hostname = hostname.strip(' \t')

    dlks, ulks, devs = erth_inventory.links_and_stuff(hostname, logger)
    logger.info(dlks)
    logger.info(ulks)
    logger.info(devs)
    table = erth_inventory.table_form(hostname, dlks, ulks, devs, logger)
    
    return render_template("erth_inventory_out.html", 
                           table=table)
###
### /ERTH Inventory
###

###
### 404
###
@web_utils_app.route("/404")
def err404():
    return render_template("404.html")
###
### /404
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
    sid_storage = common_mysql.sql_get_session(sid, logger)
    common_mysql.sql_del_session(sid, logger)
    if not sid_storage: return obi()
    return render_template("obi-wan-out2.html", avar=sid_storage[0]['storage'], avar2=avar2)

@web_utils_app.route("/loading_test", methods=['POST'])
def loading_test():
    time.sleep(10)
    return render_template("obi-wan.html")

if __name__ == "__main__":
    web_utils_app.run(debug=True, host='0.0.0.0', port=4000)