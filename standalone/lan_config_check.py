# -*- coding: utf-8 -*-
#!/usr/local/bin/Python37/LAN_Config/env/bin/
#Python 3.7.3

import config
import subprocess, logging, sys, re, telebot
import pymysql.cursors
from pyzabbix import ZabbixAPI
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from time import gmtime, strftime

from lib.common import common_mysql
from lib.zabbix_common import zabbix_common

from lib.configurator.gatherer import ifaces_and_vlans

sys.path.append('/usr/local/bin/Python37/Common/')
from Vendors import vendors
#vendors.sysobjectid_dict


def gather_services(host_dict, logger):
    try:
        done_dict = {}
        vpls_dict = gather_vpls(host_dict, logger)
        for host in host_dict:
            for vlan in host_dict[host]['vlans']:
                get_chain(host, vlan, host_dict, done_dict, logger)
    
    except Exception as err_message:
        er = '{}: Ошибка в функции gather_services {}'
        logger.error(er.format(host, str(err_message)))
    
def gather_vpls(host_dict, logger):
    try:
        vpls_dict = {}
        for h in host_dict:
            for i in host_dict[h]['ifaces']:
                if 'L3' in host_dict[h]['ifaces'][i] and 'vpls' in host_dict[h]['ifaces'][i]['L3']:
                    vpls_comm = host_dict[h]['ifaces'][i]['L3']['vpls']['vrf-target']['community']
                    vpls_dict.setdefault(vpls_comm, []).append(h)
        return vpls_dict
    except Exception as err_message:
        er = '{}: Ошибка в функции gather_vpls {}'
        logger.error(er.format(host, str(err_message)))
    
def get_chain(host, vlan, host_dict, done_dict, logger):
    try:
        chain = {}
        end_iface_dict = {}
        termination = {}
        host_list = [host]
        been_list = []
        while host_list:
            cur_host = host_list[0]
            while cur_host in host_list:
                host_list.remove(cur_host)
            if cur_host in been_list: continue
            been_list.append(cur_host)
                
            if not vlan in host_dict[cur_host]['vlans']:
                continue
                
            chain.setdefault(cur_host, {})
                
            for ifid, iface in host_dict[cur_host]['ifaces'].items():
                if iface['type'] not in ['6', '161', '117']:
                    continue
                elif any(x in iface['name'] for x in ['.', ':']):
                    # джуники считают все саб интерфейсы агрегата как тип 161 
                    continue
                elif iface['state'] == '6':
                    # 6 = notPresent, такое бывает на кошках, фантомные Po
                    continue
                elif iface['name'] in ['em0', 'em1', 'em2', 'em3', 'em4', 'me0', 'fxp0']:
                    # джуниковские фейк интерфейсы
                    continue
                    
                if 'Untag' in iface: # L2 switch interface
                    # ignore interfaces without current vlan
                    if vlan not in iface['Tag']+iface['Untag']:
                        continue
                        
                    iftype = 'trunk'
                    if (iface['Untag'] and not iface['Tag']): iftype = 'access'
                        
                    mag = re.search(config.mag_regex, iface['description'])
                    
                    if mag and not mag.groupdict()['lag']:

                        nei_host = mag.groupdict()['host']
                        
                        #RB260 can have problems with description length
                        if mag.groupdict()['host'] not in host_dict:
                            if host_dict[cur_host]['sysobjectid'] == 'iso.3.6.1.4.1.14988.2':
                                # берем дескр который предположительно порезан, вычленяем то что идет перед номером дома
                                name_len = len(mag.groupdict()['name'])
                                cut_hname_dict = {}
                                # берем все известные хостнеймы и режем их на ту же длинну что и наш дескр.
                                for host in host_dict:
                                    rh = re.search(config.mag_regex, host)
                                    if not rh: continue
                                    cut_hname = rh.groupdict()['name'][0:name_len]
                                    cut_hname_dict[cut_hname+rh.groupdict()['tail']] = rh.groupdict()['host']
                                # ищем наш дескр в полученном списке порезанных хостнеймов.
                                if mag.groupdict()['host'] in cut_hname_dict:
                                    nei_host = cut_hname_dict[mag.groupdict()['host']]
                                else: 
                                    logging.error('{}: Could not find hostname {} in host_dict'.format(cur_host, nei_host))
                                    continue
                            else: 
                                logging.error('{}: Could not find hostname {} in host_dict'.format(cur_host, nei_host))
                                continue
                        
                        
                        chain[cur_host][nei_host] = {
                            'ifid': ifid, 
                            'port': iface['name'], 
                            'type': iftype,
                        }
                        host_list.append(nei_host)
                        
                    elif not mag:
                        end_iface_dict.setdefault(cur_host, {})
                        end_iface_dict[cur_host][iface['name']] = iftype
                    

                elif 'L3' in iface:
                    if (str(iface['L3']['outer-vlan-id']) != vlan and 
                        str(iface['L3']['inner-vlan-id']) != vlan):
                        continue
                    
                    l2_iftype = 'trunk'
                    # Debatable! I need to think about this one
                    #if (str(iface['L3']['inner-vlan-id']) == vlan and
                    #    str(iface['L3']['outer-vlan-id']) != vlan):
                    #    l2_iftype = 'access'
                    
                    # we need to find l2 iface and its neighbour
                    l2_if = iface['L3']['iface']
                    for ifi, ifc in host_dict[cur_host]['ifaces'].items():
                        if ifc['name'] == l2_if:
                            l2_mag = re.search(config.mag_regex, ifc['description'])
                            if (not l2_mag or 
                                l2_mag.groupdict()['host'] not in host_dict):
                                logger.error('{}: could not find L2 link for {}'.format(cur_host, l2_if))
                                continue
                            l2nei_name = l2_mag.groupdict()['host']
                            chain[cur_host][l2nei_name] = {'ifid': ifi, 'port': l2_if, 'type': l2_iftype}
                    # and now to find mpls neighbour
                    if 'mpls' in iface['L3']:
                        nei_ip = iface['L3']['mpls']['neighbour']
                        nei_name = ip_dict[nei_ip]
                        chain[cur_host][nei_name] = {'ifid': None, 'port': 'mpls', 'type': 'mpls'}
                        host_list.append(nei_name)
                    
                    #{'Cvetoch19-cs1': {'Cvetoch19-cr1': {'ifid': '25', 'port': 'Ethernet1/1/1', 'type': 'trunk'}}, 
                    # 'Cvetoch19-cr1': {'Cvetoch19-cs1': {'ifid': '776', 'port': 'ae0', 'type': 'trunk'}, 
                    #                   'Lig73-cr1': {'ifid': None, 'port': 'mpls', 'type': 'mpls'}}, 
                    # 'Lig73-ds2': {'Lig73-cr1': {'ifid': '25', 'port': 'Ethernet1/0/25', 'type': 'trunk'}}, 
                    # 'Lig73-cr1': {'Lig73-ds2': {'ifid': '616', 'port': 'ae0', 'type': 'trunk'}, 
                    #               'Cvetoch19-cr1': {'ifid': None, 'port': 'mpls', 'type': 'mpls'}}}
                    
                    elif 'vpls' in iface['L3']:
                        # На подумать: может быть несколько интерфейсов в вплс. С разными vid.
                        chain[cur_host]['VPLS'] = {'ifid': None, 'port': 'vpls', 'type': 'vpls'}
                        host_list.append(nei_name)
                        vpls_comm = iface['L3']['vpls']['vrf-target']['community']
                        if vpls_comm in vpls_dict:
                            for vpls_host in vpls_dict[vpls_comm]:
                                if vpls_host != cur_host:
                                    host_list.append(vpls_host)
                            
                    elif 'inet' in iface['L3']:
                        termination.setdefault(cur_host, {})
                        termination[cur_host]['ifname'] = iface['name']
                        termination[cur_host]['description'] = iface['description']
                        termination[cur_host]['ip'] = iface['L3']['inet']
                        termination[cur_host]['type'] = 'inet'

                    elif 'unnumbered' in iface['L3']:
                        termination.setdefault(cur_host, {})
                        termination[cur_host]['ifname'] = iface['name']
                        termination[cur_host]['description'] = iface['description']
                        termination[cur_host]['ip'] = iface['L3']['unnumbered']['static']
                        termination[cur_host]['type'] = 'unnumbered'
                    
                    #end_iface_dict = {'BMor18-ds4': {'Ethernet1/0/3': 'Access', 'Ethernet1/0/8': 'trunk'}}
                    #chain = {'Vish12-as0': {'Mira3-ds2': {'ifid': '1000', 'port': 'Po1', 'type': 'trunk'}},
        
    except Exception as err_message:
        er = 'Ошибка в функции gather_services {}'
        logger.error(er.format(str(err_message)))
        
        
def description_validator(host_dict, config, logger):
    validation_errors = {}
    validation_errors_hosts = {}
    
    try:
        for hname in host_dict:
            #logger.info('TEMP validating {}'.format(hname))
            if not 'ifaces' in host_dict[hname]:
                continue
            for ifid, iface in host_dict[hname]['ifaces'].items():
                if iface['type'] not in ['6', '161', '117']:
                    continue
                elif any(x in iface['name'] for x in ['.', ':']):
                    # джуники считают все саб интерфейсы агрегата как тип 161 
                    continue
                elif iface['state'] == '6':
                    # 6 = notPresent, такое бывает на кошках, фантомные Po
                    continue
                elif iface['name'] in ['em0', 'em1', 'em2', 'em3', 'em4', 'me0', 'fxp0']:
                    # джуниковские фейк интерфейсы
                    continue
                elif not 'description' in iface:
                    logger.warning('{}: no description on iface: {}'.format(hname, iface))
                    continue
                
                internal = re.search(config.internal_regex, iface['description'])
                mag = re.search(config.mag_regex, iface['description'])
                contract = re.search(config.contract_regex, iface['description'])
                voip = re.search(config.voip_regex, iface['description'])
                ups = re.search(config.ups_regex, iface['description'])
                srv = re.search(config.srv_regex, iface['description'])
                isp = re.search(config.isp_regex, iface['description'])
                bad = re.search(config.bad_regex, iface['description'])
                free = re.search(config.free_regex, iface['description'])
                office = re.search(config.office_regex, iface['description'])
                
                if (contract or voip or ups or srv or isp or internal): 
                    if iface['status'] == '2' and 'OFF' not in iface['description']:
                        er = {'Host': hname, 
                              'Interface': iface['name'], 
                              'Description': iface['description'], 
                              'Error': 'Подписанный порт выключен'}
                        validation_errors.setdefault('port_disabled', []).append(er)
                        validation_errors_hosts.setdefault(hname, []).append(er)
                    elif iface['status'] == '1' and 'OFF' in iface['description']:
                        er = {'Host': hname, 
                              'Interface': iface['name'], 
                              'Description': iface['description'], 
                              'Error': 'Порт с отключенным клиентом не погашен'}
                        validation_errors.setdefault('off_enabled', []).append(er)
                        validation_errors_hosts.setdefault(hname, []).append(er)
                    
                elif mag:
                    if mag.groupdict()['lag']:
                        continue
                    if iface['status'] == '2' and 'OFF' not in iface['description']:
                        er = {'Host': hname, 
                              'Interface': iface['name'], 
                              'Description': iface['description'], 
                              'Error': 'Магистральный порт выключен'}
                        validation_errors.setdefault('mag_disabled', []).append(er)
                        validation_errors_hosts.setdefault(hname, []).append(er)
                        
                    elif (iface['state'] == '2' 
                          and mag.groupdict()['host'] not in disabled_hosts):
                        er = {'Host': hname, 
                              'Interface': iface['name'], 
                              'Description': iface['description'], 
                              'Error': 'Нет линка на магистрали'}
                        validation_errors.setdefault('mag_down', []).append(er)
                        validation_errors_hosts.setdefault(hname, []).append(er)
                    
                    elif (mag.groupdict()['host'] not in host_dict):
                        err_switch = True
                        if mag.groupdict()['host'] in disabled_hosts:
                            err_switch = False
                        
                        # Этот блок посвящен микротам со swos, и их 16 символьным дескрипшнам
                        if host_dict[hname]['sysobjectid'] == 'iso.3.6.1.4.1.14988.2':
                            # берем дескр который предположительно порезан, вычленяем то что идет перед номером дома
                            name_len = len(mag.groupdict()['name'])
                            cut_hname_arr = []
                            # берем все известные хостнеймы и режем их на ту же длинну что и наш дескр.
                            for host in host_dict:
                                rh = re.search(config.mag_regex, host)
                                if not rh: continue
                                cut_hname = rh.groupdict()['name'][0:name_len]
                                cut_hname_arr.append(cut_hname+rh.groupdict()['tail'])
                            # ищем наш дескр в полученном списке порезанных хостнеймов.
                            if mag.groupdict()['host'] in cut_hname_arr:
                                #logging.warning('TEMP cut_hname_arr: {}'.format(cut_hname_arr))
                                err_switch = False
                        
                        if err_switch:
                            er = {'Host': hname, 
                                'Interface': iface['name'], 
                                'Description': iface['description'], 
                                'Neighbor': mag.groupdict()['host'],
                                'Error': 'Магистральный дескрипшн не верен или соседа нет в заббиксе'}
                            validation_errors.setdefault('no_neighbor', []).append(er)
                            validation_errors_hosts.setdefault(hname, []).append(er)
                    
                    elif ('ifaces' in host_dict[mag.groupdict()['host']]
                          and not mag.groupdict()['isp']
                          and not any(hname in v['description'] 
                                      for k, v in host_dict[mag.groupdict()['host']]['ifaces'].items()
                                      if 'description' in v)
                         ):
                            
                        err_switch = True
                        
                        # Этот блок посвящен микротам с swos, и их 16 символьным дескрипшнам
                        if host_dict[mag.groupdict()['host']]['sysobjectid'] == 'iso.3.6.1.4.1.14988.2':
                            cut_hname = re.search(config.mag_regex, hname)
                            for v in host_dict[mag.groupdict()['host']]['ifaces'].values():
                                if not 'description' in v:
                                    logger.warning('{}: no description on iface: {}'.format(mag.groupdict()['host'], v))
                                    continue
                                ext_des = re.search(config.mag_regex, v['description'])
                                if not ext_des: continue
                                if (ext_des.groupdict()['tail'] == cut_hname.groupdict()['tail']
                                    and ext_des.groupdict()['name'] in cut_hname.groupdict()['name']):
                                    err_switch = False
                                    
                        if err_switch:
                            er_txt = 'У соседа нет портов подписанных этим хостом'
                            er = {'Host': hname, 
                                'Interface': iface['name'], 
                                'Description': iface['description'], 
                                'Error': er_txt,
                                'Neighbor': mag.groupdict()['host']}
                            validation_errors.setdefault('Neighbor_unaware', []).append(er)
                            validation_errors_hosts.setdefault(hname, []).append(er)
                    
                    elif ('ifaces' in host_dict[mag.groupdict()['host']]
                          and mag.groupdict()['isp']
                          and not any(mag.groupdict()['isp'] in v['description'] 
                                      or hname in v['description']
                                      for k, v in host_dict[mag.groupdict()['host']]['ifaces'].items()
                                      if 'description' in v)
                         ):
                        er_txt = 'У соседа нет стыка с ISP указанным на аплинке'
                        er = {'Host': hname, 
                            'Interface': iface['name'], 
                            'Description': iface['description'], 
                            'ISP': mag.groupdict()['isp'],
                            'Error': er_txt,
                            'Neighbor': mag.groupdict()['host']}
                        validation_errors.setdefault('Neighbor_isp', []).append(er)
                        validation_errors_hosts.setdefault(hname, []).append(er)
                        
                    
                    if int(iface['speed']) < 1000 and iface['state'] == '1':
                        er = {'Host': hname, 
                              'Interface': iface['name'], 
                              'Description': iface['description'],
                              'Speed': iface['speed'],
                              'Error': 'Магистраль меньше 1Гбит'}
                        validation_errors.setdefault('mag_slow', []).append(er)
                        validation_errors_hosts.setdefault(hname, []).append(er)
                    
                # не смачился как магистраль
                elif ('_U_' in iface['description'] or 
                      'UP_' in iface['description'] or
                      'PP_' in iface['description']):
                    er = {'Host': hname, 
                          'Interface': iface['name'], 
                          'Description': iface['description'], 
                          'Error': 'Хостнейм аплинка не опознан'}
                    validation_errors.setdefault('UP_unknown', []).append(er)
                    validation_errors_hosts.setdefault(hname, []).append(er)

                elif bad: 
                    if iface['status'] == '1':
                        er = {'Host': hname, 
                              'Interface': iface['name'], 
                              'Description': iface['description'], 
                              'Error': 'Битый порт включен'}
                        validation_errors.setdefault('bad_enabled', []).append(er)
                        validation_errors_hosts.setdefault(hname, []).append(er)
                        
                elif iface['description'] == '' or free:
                    if iface['state'] == '1':
                        er = {'Host': hname, 
                              'Interface': iface['name'],  
                              'Error': 'Не подписанный порт активен'}
                        validation_errors.setdefault('empty_active', []).append(er)
                        validation_errors_hosts.setdefault(hname, []).append(er)
                    elif iface['status'] != '2':
                        er = {'Host': hname, 
                              'Interface': iface['name'],  
                              'Error': 'Не подписанный порт включен'}
                        validation_errors.setdefault('empty_enabled', []).append(er)
                        validation_errors_hosts.setdefault(hname, []).append(er)
                
                elif office:
                    pass
                else:
                    er = {'Host': hname, 
                          'Interface': iface['name'], 
                          'Description': iface['description'], 
                          'Error': 'Дескрипшн не опознан'}
                    validation_errors.setdefault('desc_unknown', []).append(er)
                    validation_errors_hosts.setdefault(hname, []).append(er)
                    
                    
            desc_arr = [d['description'] 
                        for d in host_dict[hname]['ifaces'].values() 
                        if 'description' in d]
            #logger.warning('TEMP desc_arr: {}'.format(desc_arr)) mag.groupdict()['uplink']
            if all('UP_' not in x  
                   and '_U_' not in x
                   for x in desc_arr) and '-cr' not in hname:
                er = {'Host': hname, 
                      'Error': 'Не нашел аплинк на девайсе'}
                validation_errors.setdefault('no_uplink', []).append(er)
                validation_errors_hosts.setdefault(hname, []).append(er)
                   
            elif all(x == '' 
                     or 'UP_' in x 
                     or 'UP ' in x 
                     or 'U_' in x 
                     or 'OFF' in x 
                     or re.search(config.free_regex, x)
                     for x in desc_arr):
                #logger.warning('TEMP desc_arr: {}'.format(desc_arr))
                er = {'Host': hname, 
                      'Model': host_dict[hname]['model'],
                      'Error': 'На девайсе есть только аплинк'}
                validation_errors.setdefault('uplink_only', []).append(er)
                validation_errors_hosts.setdefault(hname, []).append(er)
            ports_desc_arr = [d['description'] 
                              for d in host_dict[hname]['ifaces'].values() 
                              if d['type'] == '6']
            free_ports = [x for x in ports_desc_arr 
                          if not x 
                          or 'OFF' in x 
                          or re.search(config.free_regex, x)]
            if not free_ports:
                er = {'Host': hname, 
                      'Model': host_dict[hname]['model'],
                      'Error': 'Нет свободных портов'}
                validation_errors.setdefault('ports_busy', []).append(er)
                validation_errors_hosts.setdefault(hname, []).append(er)
                
            #if len(hname) > 12:
            #    er = {'Host': hname, 
            #          'Length': str(len(hname)),
            #          'Error': 'Хостнейм длиннее 12 символов'}
            #    validation_errors.setdefault('long_hname', []).append(er)
            #    validation_errors_hosts.setdefault(hname, []).append(er)
                
        return(validation_errors, validation_errors_hosts)            
    except Exception as err_message:
        er = '{}: Ошибка в функции description_validator {}'
        logger.error(er.format(hname, str(err_message)))
        logger.error('host_dict: {}'.format(host_dict[hname]))
        
def table_maker(err_name, err_dict):
    try:
        cols = len(err_dict[0])-1
        table_head = ('<table id="{}" style="display:none"><thead>'
                     '<tr><th colspan="{}">'
                     '{}</th></tr>').format(err_name,
                                            str(cols), 
                                            err_dict[0]['Error'])
        
        table_cols = ''.join(['<th>{}</th>'.format(x) 
                            for x in err_dict[0] if x != 'Error'])
        table_head = '{}<tr>{}</tr></thead>'.format(table_head, table_cols)
        
        table_body = ''
        for err in err_dict:
            table_body += '<tr>'
            for col in err:
                if col != 'Error':
                    table_body += '<td>{}</td>'.format(err[col])
            table_body += '</tr>'
        table = '{}<tbody>{}</tbody></table>'.format(table_head, table_body)
        return table
                    
    except Exception as err_message:
        er = 'Ошибка в функции table_maker {}'
        logger.error(er.format(str(err_message)))
        
def description_validation_report_tg(host_dict, 
                                     html_link, 
                                     errors, 
                                     errors_hosts, 
                                     logger):
    try:
        bot = telebot.TeleBot(config.TOKEN)
        
        link_msg = "\n<a href=\""+html_link+"\">Тут подробный отчет</a>"
        succeeded = [x for x in host_dict if 'ifaces' in host_dict[x]]
        err_count = len([x for y in errors for x in errors[y]])
        
        report = ('🏷 <b>Дескрипшны</b>\n'
                  'Из заббикса взял {} устройств, '
                  '{} из них успешно опрошены.'.format(len(host_dict), len(succeeded)))
        
        report = report+'\nДевайсов с ошибками: {}'.format(len(errors_hosts))
        report = report+'\nВсего ошибок: {}'.format(err_count)
        report = report+link_msg
        
        
        bot.send_message(config.tg_report_group, report, parse_mode='html')
        
    except Exception as err_message:
        er = '{}: Ошибка в функции description_validation_report_tg {}'
        logger.error(er.format(ip, str(err_message)))
        
def description_validation_report_html(errors, errors_hosts, logger):
    try:
        sort_dict = {x: errors[x][0]['Error']+' ('+str(len(errors[x]))+')' 
                     for x in errors}
        # sort_dict = {'error_name': 'Имя ошибки', ...}
        jscript, buttons = js_buttons_generator(sort_dict, logger)
        style = '''
<style>
table {
    border-collapse: collapse;
}
th {
    cursor: pointer;
}
td,
th {
    /*width: 110px;*/
    padding: 0 10px;
    height: 25px;
    text-align: center;
    border: 1px solid #454545;
}
button {
    width: 30%;
}
</style>'''
        html_report = ('<!DOCTYPE html><html><head>'
                       '<meta charset="utf-8"></head><body>'
                       '{style}\n{jscript}{buttons}<br><br><br>'.format(style=style, 
                                                            jscript=jscript, 
                                                            buttons=buttons))

        for err in errors:
            if not err:
                continue
            html_report += table_maker(err, errors[err])
            #html_report += '<br><hr><br>'
        
        # а нужен нам лог внутри отчета?
        #with open(config.logs_folder+strftime("%A", gmtime())+'.log', 'r') as log_file:
        #    html_report += '<br><h2>Log:</h2>'
        #    for line in log_file:
        #        html_report += line+'<br>'
        html_report += '</body></html>'
        
        filename = 'Descriptions_'+strftime("%A", gmtime())+'.html'
        with open(config.static_html_folder+filename, 'w') as report:
            report.write(html_report)
        html_link = config.static_html_link+filename
        
        return html_link
        
    except Exception as err_message:
        er = '{}: Ошибка в функции description_validation_report_html {}'
        logger.error(er.format(ip, str(err_message)))
        
def js_buttons_generator(sort_dict, logger):
    '''Функция генерит скрипт который сделает нам кнопки для переключения между таблицами.
    Чтобы оно работало, таблицам надо будет раздать id из sort_dict'''
    try:
        if not sort_dict:
            return None
        jscript = '<script type="text/javascript">'
        block = '''
function {button}() {{
  {elems}
  if ({button}.style.display === "none") {{
    {vars_block}
  }} else {{
    {vars_block}
  }}
}}'''
        elem = 'var {} = document.getElementById("{}");'
        disp = '{}.style.display = "none";'
        button_template = '<button onclick="{}()">{}</button>'
        buttons = '<br>'.join([button_template.format(x, sort_dict[x]) 
                               for x in sort_dict])
        for button in sort_dict:
            elems = '\n  '.join([elem.format(x, x) for x in sort_dict])
            vars_block = '{}.style.display = "block";\n'.format(button)
            vars_block = vars_block+'\n    '.join([disp.format(x) 
                                                for x in sort_dict 
                                                if x != button])
            jscript = jscript+block.format(button=button, 
                                        elems=elems, 
                                        vars_block=vars_block)
        return jscript+'</script>', buttons
    except Exception as err_message:
        er = 'Ошибка в функции js_buttons_generator {}'
        logger.error(er.format(str(err_message)))
        
if __name__ == '__main__':
    try:
        logger = logging.getLogger('my_logger')
        #handler = logging.StreamHandler()
        handler = logging.FileHandler(config.logs_folder+strftime("%A", gmtime())+'.log', 'w+')
        formatter = logging.Formatter("[%(asctime)s] %(levelname)s - %(message)s")
        handler.setLevel(logging.INFO)
        handler.setFormatter(formatter)
        logger.setLevel(logging.INFO)
        logger.addHandler(handler)
        
        hosts = zabbix_common.get_hosts(logger, monitored=False)
        disabled_hosts = [x for x in hosts if x['status']=='1']
        hosts = [x for x in hosts if x['status']=='0']
        interfaces = zabbix_common.get_interfaces(logger)
        
        host_dict = {}
        
        for host in hosts:
            ip = zabbix_common.get_interface(host['hostid'], logger, interfaces)
            if host['name'] == ip:
                logger.info('Invalid hostname {}'.format(ip))
            elif '10.60.' in ip or '188.68.187.' in ip or '10.61.' in ip:
                host_dict[host['host']] = {'ip': ip}
        ip_dict = {host_dict[hname]['ip']: hname for hname in host_dict}
        
        #host_dict = {'BB-switch-as1': {'ip': '10.60.0.7'},
        #           'VM devnet.spb.avantel.ru': {'ip': '188.68.187.53'},
        #           '6Verhniy12b-as3': {'ip': '10.60.253.183'},
        #           'Start8-as3': {'ip': '10.60.252.99'},
        #           'Lig73-ds2': {'ip': '10.60.236.98'}}
        #host_dict = {'Mosk177-as10': {'ip': '10.60.240.34'},
        #             'Chkal15-13-as0': {'ip': '10.60.245.19'},
        #             'Chkal15-2-as5': {'ip': '10.60.254.43'}}
        #host_dict = {'BSam45-as4': {'ip': '10.60.254.16'},
        #             'BSam30-as1': {'ip': '10.60.253.182'},
        #             'BSam45-as3': {'ip': '10.60.253.67'}}
        #host_dict = {'Cvetoch19-cr1':  {'ip': '10.60.255.243'}}
        #host_dict = {'Savushkina126-as3' :{'ip': '10.60.241.24'}}
        
        
        with ThreadPoolExecutor(max_workers=100) as executor:
            [executor.submit(
                ifaces_and_vlans.get_all, 
                host_dict[hname]['ip'],
                hname,
                host_dict, 
                vendors.sysobjectid_dict, 
                logger,
            ) for hname in host_dict]
        
        print(set([ifc['type'] for h in host_dict 
                    if 'ifaces' in host_dict[h]
                    for i, ifc in host_dict[h]['ifaces'].items() 
                   ])
             )
        print({h: [ifc['type']+'_'+ifc['name']]
               for h in host_dict
               if 'ifaces' in host_dict[h]
               for i, ifc in host_dict[h]['ifaces'].items()
               if ifc['type'] not in ['6', '161', '53', '24', '131', '136', '1', '22']})
        # 6 = ethernet, 161 = Po,  53 = vlan,  24 = Loopback, 
        # 135 = intOfPo, 131 = tunnel, 22 = propPointToPointSerial
        # 1 = Null, 136 = int vlan, 100 = voiceEM, 209 = bridge
        logger.info(f'TEMP_host_dict: {len(host_dict)}')
        errs, errs_hosts = description_validator(host_dict, 
                                                 config, 
                                                 logger)
        # errs = {'error_name': [{'column1': 'data1', 'Error': 'Название ошибки'}]}
        print(len(errs_hosts))
        html_link = description_validation_report_html(errs, 
                                                       errs_hosts, 
                                                       logger)
        print(html_link)
        description_validation_report_tg(host_dict, 
                                         html_link, 
                                         errs, 
                                         errs_hosts, 
                                         logger)
        
    except Exception as err_message:
        logger.error(str(err_message))