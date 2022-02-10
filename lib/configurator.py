import config, sys, re, os
from datetime import datetime
from lib.snmp_common import snmp_common
from lib.zabbix_common import zabbix_common
from lib.common import mysql
from diagrams import Diagram, Edge
from diagrams.custom import Custom
from diagrams.ibm.network import Bridge
from diagrams.ibm.network import Router
from diagrams.ibm.network import InternetServices
from diagrams.ibm.network import DirectLink
from diagrams.ibm.user import Browser
from diagrams.generic.blank import Blank
#sys.path.append('/usr/local/bin/Python37/WebUtils/env/lib/python3.7/site-packages/graphviz/')
#sys.path.append('/usr/local/bin/Python37/Playground/env/lib/python3.7/site-packages/graphviz/')
#sys.path.append('/usr/local/bin/Python37/WebUtils/env/lib/python3.7/site-packages/')
#sys.path.append('/usr/lib/x86_64-linux-gnu/graphviz/')
#sys.path.append('/usr/share/doc/graphviz/')
#sys.path.append('/usr/share/graphviz/')


sys.path.append('/usr/local/bin/Python37/Common/')
from Vendors import vendors

#class fun_and_interactive:
#    def a(): 
#        pass 

class ifaces_and_vlans:

    def fill_host_dict(ip, hname, host_dict, sysobjectid_dict, logger):
        try:
            sid, community = snmp_common.getSysObjectID(ip, logger)
            if (not sid 
                or sid not in sysobjectid_dict
                or sysobjectid_dict[sid]['type'] not in ['router', 'switch']
                or type(sysobjectid_dict[sid]['vendor']) == str):
                logger.error('{}: Не смог собрать/незнакомый SysObjectID'.format(hname))
                #host_dict.pop(ip)
                return False
            host_dict[hname]['sysobjectid'] = sid
            host_dict[hname]['community'] = community
            host_dict[hname]['type'] = sysobjectid_dict[sid]['type']
            host_dict[hname]['mpls'] = sysobjectid_dict[sid]['mpls']
            if sysobjectid_dict[sid]['model'] != 'ambiguous':
                host_dict[hname]['model'] = sysobjectid_dict[sid]['model']
            else:
                host_dict[hname]['model'] = sysobjectid_dict[sid]['vendor'].get_model(ip, community, logger)
            return True
        
        except Exception as err_message:
            logger.error('{}: Ошибка в функции fill_host_dict {}'.format(ip, str(err_message)))
    
    def get_ifaces_type(ip, hname, host_dict, logger):
        # 6 = ethernet, 161 = Po,  53 = vlan,  24 = Loopback, 
        # 135 = intOfPo, 131 = tunnel, 22 = propPointToPointSerial
        # 1 = Null, 136 = int vlan
        try:
            ifaces_type = snmp_common.request(ip, 
                                          host_dict[hname]['community'], 
                                          '1.3.6.1.2.1.2.2.1.3', 
                                          logger)
            if not ifaces_type: 
                #host_dict.pop(ip)
                logger.error('{}: Не смог собрать типы интерфейсов'.format(hname))
                return False
            td = {x.split(' = INTEGER: ')[0]: {'type': x.split(' = INTEGER: ')[1]} 
                  for x in ifaces_type.replace('iso.3.6.1.2.1.2.2.1.3.', '').split('\n') 
                  if x}
            host_dict[hname]['ifaces'] = td
            #logger.warning('TEMP_host_dict1 {}'.format(host_dict))
            return True
        
        except Exception as err_message:
            logger.error('{}: Ошибка в функции get_ifaces_type {}'.format(hname, str(err_message)))
            
    def get_vlan_names(ip, hname, host_dict, logger):
        try:
            vlans_name = snmp_common.request(ip, 
                                        host_dict[hname]['community'], 
                                        '1.3.6.1.2.1.17.7.1.4.3.1.1', 
                                        logger)
            
            if not vlans_name: 
                logger.error('{}: Не смог собрать имена вланов'.format(hname))
                return False
            
            htt = lambda x: bytes.fromhex(x.split(' = Hex-STRING: ')[1].replace(' ', '')).decode('utf-8').replace('\x00', '')
            if 'Hex-STRING' in vlans_name:
                vd = {x.split(' = Hex-STRING: ')[0]: {'name': htt(x)} 
                    for x in vlans_name.replace('\n', '').split('iso.3.6.1.2.1.17.7.1.4.3.1.1.')
                    if x}
            else:
                vd = {x.split(' = ')[0]: {'name': x.split(' = STRING: ')[1].strip('"\n')} 
                      if 'STRING' in x 
                      else {'name': None} 
                      for x in [l for l in vlans_name.replace('\n', '').split('iso.3.6.1.2.1.17.7.1.4.3.1.1.') if l]}
                
            
            host_dict[hname]['vlans'] = vd
    
        except Exception as err_message:
            logger.error('{}: Ошибка в функции get_vlan_names {}'.format(hname, str(err_message)))
            
    def get_ifaces_name(ip, hname, host_dict, logger):
        try:
            if host_dict[hname]['sysobjectid'] != 'iso.3.6.1.4.1.14988.2':
                
                ifaces_name = snmp_common.request(ip, 
                                            host_dict[hname]['community'], 
                                            '1.3.6.1.2.1.2.2.1.2', 
                                            logger)
                if not ifaces_name: 
                    #host_dict.pop(ip)
                    logger.error('{}: Не смог собрать имена интерфейсов'.format(hname))
                    return False
                nd = {x.split(' = STRING: ')[0]: {'name': x.split(' = STRING: ')[1].strip('"')} 
                    for x in ifaces_name.replace('iso.3.6.1.2.1.2.2.1.2.', '').split('\n') 
                    if x}
                 
            # Если это Mikrotik RB260GS. Он совмещает дескрипшны 
            else:
                nd = {'1': {'name': 'Port1'},
                      '2': {'name': 'Port2'},
                      '3': {'name': 'Port3'},
                      '4': {'name': 'Port4'},
                      '5': {'name': 'Port5'},
                      '6': {'name': 'Port6'}}
    
            # Длинки пишут дичь в именах интерфейсов
            if 'iso.3.6.1.4.1.171' in host_dict[hname]['sysobjectid']:
                for ifc in nd.copy():
                    s = re.search('\d+$', nd[ifc]['name'])
                    if not s:
                        continue
                    nd[ifc]['name'] = s.group()
    
            for i in host_dict[hname]['ifaces']:
                if i in nd:
                    host_dict[hname]['ifaces'][i].update(nd[i])
            #host_dict[hname]['ifaces'] = {i: {**host_dict[hname]['ifaces'][i], **nd[i]} 
            #                            for i in host_dict[hname]['ifaces']}
            #logger.warning('TEMP_host_dict2 {}'.format(host_dict))
            return True
        
        except Exception as err_message:
            logger.error('{}: Ошибка в функции get_ifaces_name {}'.format(hname, str(err_message)))
        
    def get_ifaces_description(ip, hname, host_dict, logger):
        try:
            if host_dict[hname]['sysobjectid'] != 'iso.3.6.1.4.1.14988.2':
                descoid = 'iso.3.6.1.2.1.31.1.1.1.18'
            else: descoid = 'iso.3.6.1.2.1.31.1.1.1.1'
            ifaces_descs = snmp_common.request(ip, 
                                          host_dict[hname]['community'], 
                                          descoid, 
                                          logger)
            if not ifaces_descs: 
                #host_dict.pop(ip)
                logger.error('{}: Не смог собрать дескрипшны'.format(hname))
                return False
            #logger.warning('TEMP ifaces_descs {}'.format(ifaces_descs))
            dd = {x.split(' = STRING: ')[0]: {'description': x.split(' = STRING: ')[1].strip('"')} 
                  for x in ifaces_descs.replace(descoid+'.', '').split('\n') 
                  if x and 'STRING' in x}
            # если дескрипшна для интерфейса нет, повесим пустой
            [dd.update({x: {'description': ''}}) 
                for x in host_dict[hname]['ifaces'] 
                if not x in dd]
            for i in host_dict[hname]['ifaces']:
                if i in dd:
                    host_dict[hname]['ifaces'][i].update(dd[i])
            #host_dict[hname]['ifaces'] = {i: {**host_dict[hname]['ifaces'][i], **dd[i]} 
            #                            for i in host_dict[hname]['ifaces']}
            #logger.warning('TEMP_host_dict3 {}'.format(host_dict))
            return True
        
        except Exception as err_message:
            logger.error('{}: Ошибка в функции get_ifaces_description {}'.format(hname, str(err_message)))
    
    def get_ifaces_status(ip, hname, host_dict, logger):
        #(1 = on, 2 = off)
        try:
            ifaces_status = snmp_common.request(ip, 
                                          host_dict[hname]['community'], 
                                          '1.3.6.1.2.1.2.2.1.7', 
                                          logger)
            if not ifaces_status: 
                #host_dict.pop(ip)
                logger.error('{}: Не смог собрать статус интерфейсов'.format(hname))
                return False
            nd = {x.split(' = INTEGER: ')[0]: {'status': x.split(' = INTEGER: ')[1]} 
                  for x in ifaces_status.replace('iso.3.6.1.2.1.2.2.1.7.', '').split('\n') 
                  if x}
            for i in host_dict[hname]['ifaces']:
                if i in nd:
                    host_dict[hname]['ifaces'][i].update(nd[i])
            #host_dict[hname]['ifaces'] = {i: {**host_dict[hname]['ifaces'][i], **nd[i]} 
            #                            for i in host_dict[hname]['ifaces']}
            #logger.warning('TEMP_host_dict4 {}'.format(host_dict))
            return True
    
        except Exception as err_message:
            logger.error('{}: Ошибка в функции get_ifaces_status {}'.format(hname, str(err_message)))
            
    def get_ifaces_state(ip, hname, host_dict, logger):
        #(1 = up, 2 = down)
        try:
            ifaces_state = snmp_common.request(ip, 
                                          host_dict[hname]['community'], 
                                          '1.3.6.1.2.1.2.2.1.8', 
                                          logger)
            if not ifaces_state: 
                #host_dict.pop(ip)
                logger.error('{}: Не смог собрать состояние интерфейсов'.format(hname))
                return True
            nd = {x.split(' = INTEGER: ')[0]: {'state': x.split(' = INTEGER: ')[1]} 
                  for x in ifaces_state.replace('iso.3.6.1.2.1.2.2.1.8.', '').split('\n') 
                  if x}
            for i in host_dict[hname]['ifaces']:
                if i in nd:
                    host_dict[hname]['ifaces'][i].update(nd[i])
            #host_dict[hname]['ifaces'] = {i: {**host_dict[hname]['ifaces'][i], **nd[i]} 
            #                            for i in host_dict[hname]['ifaces']}
            #logger.warning('TEMP_host_dict5 {}'.format(host_dict))
            return True
        
        except Exception as err_message:
            logger.error('{}: Ошибка в функции get_ifaces_state {}'.format(hname, str(err_message)))
            
    def get_ifaces_speed(ip, hname, host_dict, logger):
        try:
            ifaces_speed = snmp_common.request(ip, 
                                          host_dict[hname]['community'], 
                                          '1.3.6.1.2.1.31.1.1.1.15', 
                                          logger)
            if not ifaces_speed: 
                #host_dict.pop(ip)
                logger.error('{}: Не смог собрать скорость интерфейсов'.format(hname))
                return False
            nd = {x.split(' = Gauge32: ')[0]: {'speed': x.split(' = Gauge32: ')[1].strip('"')} 
                  for x in ifaces_speed.replace('iso.3.6.1.2.1.31.1.1.1.15.', '').split('\n') 
                  if x}
            for i in host_dict[hname]['ifaces']:
                if i in nd:
                    host_dict[hname]['ifaces'][i].update(nd[i])
            #host_dict[hname]['ifaces'] = {i: {**host_dict[hname]['ifaces'][i], **nd[i]} 
            #                            for i in host_dict[hname]['ifaces']}
            #logger.warning('TEMP_host_dict6 {}'.format(host_dict))
            return True
        
        except Exception as err_message:
            logger.error('{}: Ошибка в функции get_ifaces_speed {}'.format(hname, str(err_message)))
            
    def get_ifaces_mtu(ip, hname, host_dict, logger):
        try:
            ifaces_mtu = snmp_common.request(ip, 
                                          host_dict[hname]['community'], 
                                          '1.3.6.1.2.1.2.2.1.4', 
                                          logger)
            if not ifaces_mtu: 
                #host_dict.pop(ip)
                logger.error('{}: Не смог собрать мту интерфейсов'.format(hname))
                return False
            nd = {x.split(' = INTEGER: ')[0]: {'mtu': x.split(' = INTEGER: ')[1].strip('"')} 
                  for x in ifaces_mtu.replace('iso.3.6.1.2.1.2.2.1.4.', '').split('\n') 
                  if x}
            # если девайс не кажет МТУ для интерфейса, назначим ему 0
            [nd.update({x: {'mtu': '0'}}) 
                for x in host_dict[hname]['ifaces'] 
                if not x in nd]
            
            for i in host_dict[hname]['ifaces']:
                if i in nd:
                    host_dict[hname]['ifaces'][i].update(nd[i])
            #host_dict[hname]['ifaces'] = {i: {**host_dict[hname]['ifaces'][i], **nd[i]} 
            #                            for i in host_dict[hname]['ifaces']}
            #logger.warning('TEMP_host_dict7 {}'.format(host_dict))
            return True
        
        except Exception as err_message:
            logger.error('{}: Ошибка в функции get_ifaces_mtu {}'.format(hname, str(err_message)))
            
    def get_ifaces_ip(ip, hname, host_dict, logger):
        try:
            # Mikrotik RB260 не интересен
            if host_dict[hname]['sysobjectid'] == 'iso.3.6.1.4.1.14988.2':
                return True
            #ip_addr = get_SNMP_stuff(ip, 
            #                         host_dict[hname]['community'], 
            #                         'iso.3.6.1.2.1.4.20.1.1', 
            #                         logger)
            ip_iface = snmp_common.request(ip, 
                                     host_dict[hname]['community'], 
                                     'iso.3.6.1.2.1.4.20.1.2', 
                                     logger)
            ip_netmask = snmp_common.request(ip, 
                                        host_dict[hname]['community'], 
                                        'iso.3.6.1.2.1.4.20.1.3', 
                                        logger)
            if not any([ip_iface, ip_netmask]): 
                logger.error('{}: Не смог собрать IP интерфейсов'.format(hname))
                return False
            
            ip_netmask_dict = {line.replace('iso.3.6.1.2.1.4.20.1.3.', '').split(' = IpAddress: ')[0]: 
                               line.replace('iso.3.6.1.2.1.4.20.1.3.', '').split(' = IpAddress: ')[1] 
                               for line in ip_netmask.split('\n') if line}
            ip_iface_dict = {line.replace('iso.3.6.1.2.1.4.20.1.2.', '').split(' = INTEGER: ')[0]: 
                               line.replace('iso.3.6.1.2.1.4.20.1.2.', '').split(' = INTEGER: ')[1] 
                               for line in ip_iface.split('\n') if line}
            for ipad in ip_iface_dict:
                if not ip_iface_dict[ipad] in host_dict[hname]['ifaces']:
                    continue
                elif ipad == '127.0.0.1' or '128.0.0.' in ipad:
                    continue
                host_dict[hname]['ifaces'][ip_iface_dict[ipad]].setdefault('ip', {}).update({ipad: ip_netmask_dict[ipad]})
            #logger.warning('TEMP_host_dict8 {}'.format(host_dict))
            return True
        
        except Exception as err_message:
            logger.error('{}: Ошибка в функции get_ifaces_ip {}'.format(hname, str(err_message)))

            
    def get_all(ip, hname, host_dict, logger):
        try:
            sysobjectid_dict = vendors.sysobjectid_dict
            if not ifaces_and_vlans.fill_host_dict(ip, hname, host_dict, sysobjectid_dict, logger):
                return None
            get_stuff_arr = [ifaces_and_vlans.get_ifaces_type, 
                             ifaces_and_vlans.get_ifaces_name, 
                             ifaces_and_vlans.get_ifaces_description, 
                             ifaces_and_vlans.get_ifaces_status, 
                             ifaces_and_vlans.get_ifaces_state, 
                             ifaces_and_vlans.get_ifaces_speed, 
                             ifaces_and_vlans.get_ifaces_mtu,
                             ifaces_and_vlans.get_ifaces_ip]
            for f in get_stuff_arr:
                if not f(ip, hname, host_dict, logger):
                    break
            
            #VLANs
            vendor_cls = sysobjectid_dict[host_dict[hname]['sysobjectid']]['vendor']
            iface_vlans_dict = ''
            vlan_names = {}
            qinq_names = {}
            print('TEMP_model: {}'.format(host_dict[hname]['model']))
            
            
            # на RB260 вланы собираем отдельно, скачиванием и парсом конфига
            if host_dict[hname]['sysobjectid'] == 'iso.3.6.1.4.1.14988.2':
                
                iface_vlans_dict = vendor_cls.get_parsed_config(ip, 
                                                                hname, 
                                                                config, 
                                                                logger)
                # это чудовище просто генерит имена вланам и делает дикт вида {'2': 'V0002'}. Но зачем?
                vlan_names = {vid: f'V{vid.zfill(4)}' 
                              for vlans in iface_vlans_dict.values() 
                              for vid in set(v for ar in vlans.values() 
                                             for v in ar)}
            # на джунах нужно собрать конфиги интерфейсов. Скачиваем конфиг в json, парсим его
            elif vendor_cls.vendor() == 'Juniper':
                print('TEMP Its JUNIPER!')
                # берем json в виде словаря
                jun_conf = vendor_cls.get_parsed_config(ip, hname, config, logger)
                if not jun_conf: 
                    logger.error('{}: failed to get juniper config'.foramt(hname))
                    return None
                print('TEMP Got config!')
                # забираем интерфейсы в словарь с ключами == имени интерфейса (e.g. ae0.100)
                ifaces_dict = vendor_cls.get_ifaces(ip, hname, logger, config, jun_conf)
                #logger.warning('TEMP '+str(ifaces_dict))
                for interface_id in host_dict[hname]['ifaces']:
                    interface_name = host_dict[hname]['ifaces'][interface_id]['name']
                    if interface_name in ifaces_dict:
                        host_dict[hname]['ifaces'][interface_id]['L3'] = ifaces_dict[interface_name]
                vlan_names, qinq_names = vendor_cls.get_vlans_names(hname, 
                                                                    logger, 
                                                                    config, 
                                                                    ifaces_dict)
            else:
                # проверяем наличие функции get_vlans_names в классе вендора. 
                # Если функции нет, значит имен вланов нам не видать.
                if 'get_vlans_names' in dir(vendor_cls):
                    vlan_names = vendor_cls.get_vlans_names(ip, 
                                                            host_dict[hname]['community'], 
                                                            logger)
                #print(f'TEMP_vlan_names: {vlan_names}')
                iface_vlans_dict = vendor_cls.get_vlans_ports(ip, 
                                                              host_dict[hname]['community'], 
                                                              logger)
                #print(f'TEMP_iface_vlans_dict: {iface_vlans_dict}')
            if iface_vlans_dict:
                for i in host_dict[hname]['ifaces']:
                    if i in iface_vlans_dict:
                        host_dict[hname]['ifaces'][i].update(iface_vlans_dict[i])
            else:
                logger.error('Failed to get iface_vlans_dict for {}'.format(hname))
            #host_dict[hname]['ifaces'] = {i: {**host_dict[hname]['ifaces'][i], **iface_vlans_dict[i]} 
            #                              for i in iface_vlans_dict
            #                              if i in host_dict[hname]['ifaces']}
            #logger.warning('TEMP_host_dict9 {}'.format(host_dict))
            host_dict[hname]['vlans'] = vlan_names
            host_dict[hname]['qinqs'] = qinq_names
            #print(f'TEMP_host_dict: {host_dict}')
            
            #IPs
            #return host_dict
                
        except Exception as err_message:
            logger.error('{}: Ошибка в функции get_all {}'.format(ip, str(err_message)))
            
class configurator:

    def rb260desc_fix(link_host, mag, logger):
        try:
            # сливаем с заббикса все известные хостнеймы
            hostname_list = zabbix_common.get_hostname_list(logger)
            if link_host not in hostname_list:
                # берем дескр который предположительно порезан, вычленяем то что идет перед номером дома
                name_len = len(mag.groupdict()['name'])
                cut_hname_dict = {}
                # берем все известные хостнеймы и режем их на ту же длинну что и наш дескр.
                for host in hostname_list:
                    rh = re.search(config.mag_regex, host)
                    if not rh: continue
                    cut_hname = rh.groupdict()['name'][0:name_len]
                    if cut_hname+rh.groupdict()['tail'] == link_host:
                        return rh.groupdict()['host']
            else: return link_host
        except Exception as err_message:
            logger.error('{}: Ошибка в функции configurator.rb260desc_fix {}'.format(hostname, str(err_message)))
            
    def get_links(hostname, host_dict, logger):
        try:
            uplinks = {}
            pplinks = {}
            links = {}
            #logger.warning('{} ifaces: {}'.format(hostname, host_dict[hostname]['ifaces']))
            for ifid, iface in host_dict[hostname]['ifaces'].items():
                d = ['type', 'name', 'state', 'description']
                if any ([x not in iface for x in d]):
                    logger.error('{} has broken interface {}'.format(hostname, iface))
                    continue
                if iface['type'] not in ['6', '161', '117']:
                    # 6 = ethernet, 161 = Po, 117 = combo
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
                mag = re.search(config.mag_regex, iface['description'])
                if mag:
                    link_host = mag.groupdict()['host']
                else: continue
                #Всратые 260е имеют лимит на количество символов "дескрипшне" который
                # на самом деле имя интерфейса. Работаем с тем что есть.
                if host_dict[hostname]['sysobjectid'] == 'iso.3.6.1.4.1.14988.2':
                    link_host = configurator.rb260desc_fix(link_host, mag, logger)
                
                if mag.groupdict()['lag'] or mag.groupdict()['mgmt']: 
                    continue
                if mag.groupdict()['uplink'] and link_host not in uplinks:
                    uplinks[link_host] = ifid
                if mag.groupdict()['pp'] and link_host not in pplinks:
                    pplinks[link_host] = ifid
                    
                if link_host not in links:
                    links[link_host] = ifid
            #{'host-as1': {'host-as2': '1', 'host-as3': '2'}}
            return uplinks, pplinks, links

        except Exception as err_message:
            logger.error('{}: Ошибка в функции configurator.get_links {}'.format(hostname, str(err_message)))
            
    def get_free_ifaces(host_dict, endpoints, logger):
        try:
            ifaces_dict = {}
            for host in endpoints:
                ifaces_dict[host] = {'None': ''}
                for ifid, iface in host_dict[host]['ifaces'].items():
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
                    elif iface['description'] and 'OFF' not in iface['description']:
                        # интерфейс занят
                        continue
                    
                    ifaces_dict[host][iface['name']] = iface['description']
            return ifaces_dict
        except Exception as err_message:
            logger.error('Ошибка в функции configurator.get_ifaces_names {}'.format(str(err_message)))
            
            
    def get_host(hostname, host_dict, logger):
        try:
            hostid = zabbix_common.hostid_by_name(hostname, logger)
            if not hostid: 
                logger.error('HOST '+str(hostname)+' no hostid')
                return None, None
            hostip = zabbix_common.get_interface(hostid[0]['hostid'], logger)
            if not hostip: 
                logger.error('HOST '+str(hostname)+' no hostip')
                return None, None
            host_dict[hostname] = {'ip': hostip}
            logger.info('HOST '+str(hostname)+' IP '+str(hostip))
            ifaces_and_vlans.get_all(hostip, hostname, host_dict, logger)
            #return host_dict
        except Exception as err_message:
            logger.error('{}: Ошибка в функции configurator.get_host {}'.format(current_hostname, str(err_message)))
            
    def get_hosts(hostname, host_dict, logger, to_mpls = True):
        try:
            logger.info('TEMP HOSTNAME {}'.format(hostname))
            host_list = []
            host_list.append(hostname)
            been_there = []
            all_links = {}
            while host_list:
                logger.info('HOSTLIST '+str(host_list))
                current_hostname = host_list[0]
                while current_hostname in host_list:
                    host_list.remove(current_hostname)
                if current_hostname in been_there:
                    continue
                been_there.append(current_hostname)
                if current_hostname not in host_dict:
                    configurator.get_host(current_hostname, host_dict, logger)
                
                # Ищем все магистрали на девайсе
                uplinks, pplinks, links = configurator.get_links(current_hostname,
                                                                 host_dict, 
                                                                 logger)
                logger.warning('TEMP {} links {}'.format(current_hostname, links))
                # Если не нашли аплинков, пробуем найти mplsный девайс за п2п линками.
                if (not uplinks
                    and to_mpls
                    and pplinks 
                    and not host_dict[current_hostname]['mpls']):
                    for hn in pplinks:
                        if hn in host_list or hn in been_there:
                            continue
                        host_list.append(hn)
                
                for hn in uplinks:
                    if hn in host_list or hn in been_there:
                        continue
                    host_list.append(hn)
                
                for hn in links:
                    ifname = host_dict[current_hostname]['ifaces'][links[hn]]['name']
                    all_links.setdefault(current_hostname, {}).update({hn: {'ifid': links[hn], 
                                                                    'port': ifname}})
                
            return all_links, been_there
            
        except Exception as err_message:
            logger.error('{}: Ошибка в функции configurator.get_hosts {}'.format(current_hostname, str(err_message)))
                    
    def get_chain(all_links, been_there, host_dict, logger):
            # Формируем словарь-цепочку устройств. {Хост1: {Сосед1: {port: fa1, ifid: 1, type: trunk}},
            #                                       Сосед1: {Хост1: {port: fa1, ifid: 1, type: trunk}}}
        try:
            chain = {}
            for hn in all_links:
                for link in all_links[hn]:
                    if link in been_there:
                        ifid = all_links[hn][link]['ifid'] 
                        iftype = 'trunk'
                        if ('Tag' in host_dict[hn]['ifaces'][ifid] 
                            and not host_dict[hn]['ifaces'][ifid]['Tag'] 
                            and host_dict[hn]['ifaces'][ifid]['Untag']):
                            iftype = 'access'
                        ifdict = all_links[hn][link]
                        ifdict.update({'type': iftype})
                        chain.setdefault(hn, {}).update({link: ifdict})
                        
            return chain
        except Exception as err_message:
            logger.error('Ошибка в функции configurator.get_chain {}'.format(str(err_message)))
            
    def path_maker(chains, host_dict, endpoints, logger):
        try:
            #chain_x = list(chains.keys())[0]
            # если у цепочек есть точка пересечения, будет полезно ее знать.
            closest_node = ''
            common_nodes = [node for node in chains[0] 
                            if all(node in chain for chain in chains)]

            megachain = {}
            for chain in chains:
                for node in chain:
                    megachain.setdefault(node, {}).update(chain[node])
            
            mpls_nodes = [n for n in megachain if host_dict[n]['mpls']]
            if len(mpls_nodes) < 2 and common_nodes:
                # У нас только один MPLS узел и во всех цепочках есть общие узлы. Строим чистый L2.
                been_there = []
                to_check = [mpls_nodes[0]]
                while to_check:
                    curhname = to_check[0]
                    while curhname in to_check:
                        to_check.remove(curhname)
                    been_there.append(curhname)
                    if (len(megachain[curhname]) < 3 and curhname not in endpoints 
                        or len(endpoints) == 1 and curhname not in endpoints):
                        # У узла меньше 3 магистралей и он не конечная точка.
                        # Или у нас влан внутри одного свитча и это не он. Удаляем.
                        for link in megachain[curhname]:
                            if link in been_there: continue
                            to_check.append(link)
                        deleted = curhname
                        megachain.pop(curhname)
                    elif deleted:
                        megachain[curhname].pop(deleted)
                        break
                        
            elif len(mpls_nodes) == 2 and not common_nodes:
                # 2 MPLS узла, общих узлов нет, лепим l2circuit.
                
                [megachain[n].update({mplsn: {'ifid': None, 'port': 'mpls', 'type': 'mpls'}}) 
                 for mplsn in mpls_nodes 
                 for n in mpls_nodes
                 if n != mplsn]
                 
            elif len(mpls_nodes) > 2 and not common_nodes:
                # Много MPLS узлов, общих узлов нет, лепим vpls.
                
                [megachain[n].update({'VPLS': {'ifid': None, 'port': 'vpls', 'type': 'vpls'}}) 
                 for n in mpls_nodes]
            
            return megachain
            
        except Exception as err_message:
            logger.error('Ошибка в функции configurator.path_maker {}'.format(str(err_message)))
            
    def vlan_validator(vlan_tag, vpath, host_dict, logger):
        try:
            logger.info('TEMP vpath: {}'.format(vpath))
            #logger.info('TEMP host_dict: {}'.format(host_dict))
            host_list = []
            free_vlans = ''
            for host in vpath:
                if vlan_tag in host_dict[host]['vlans']:
                    host_list.append(host)
            if host_list:
                vlan_set = set([int(vlan) for host in vpath for vlan in host_dict[host]['vlans']])
                logger.info('TEMP vlan_set: {}'.format(vlan_set))
                for vid in range(2,4096):
                    if vid not in vlan_set:
                        if not free_vlans:
                            free_vlans += str(vid)
                            prev_vid = vid
                        elif free_vlans[-1] == ' ':
                            free_vlans += str(vid)
                            prev_vid = vid
                        elif vid == 4095:
                            free_vlans += '-' + str(vid)
                    else:
                        if not free_vlans:
                            continue
                        if prev_vid and vid != 4095 and vid-1 != prev_vid:
                            free_vlans += '-' + str(vid-1) + ', '
                        elif prev_vid and vid-1 == prev_vid:
                            free_vlans += ', '
                        elif prev_vid:
                            free_vlans += '-' + str(vid-1)
                        prev_vid = None
                    
            return host_list, free_vlans
            
            
        except Exception as err_message:
            logger.error('Ошибка в функции configurator.vlan_validator {}'.format(str(err_message)))
            
    def vlan_finder(vpath, host_dict, logger):
        try:
            occupied_vlans = set([v for host in vpath for v in host_dict[host]['vlans']])
            for vid in config.inet_vlan_range:
                if str(vid) not in occupied_vlans:
                    return str(vid)
            return None
            
        except Exception as err_message:
            logger.error('Ошибка в функции configurator.vlan_finder {}'.format(str(err_message)))
            
    def vlan_config_maker(vlan_form, vlan_name, vlanpath, host_dict, end_iface_dict, endpoints, logger):
        try:
            config_dict = {}
            mpls_nodes = [n for n in vlanpath if host_dict[n]['mpls']]
            if not mpls_nodes:
                rate = vlan_form['rate']
            else:
                rate = None
            for host in vlanpath:
                vendor_cls = vendors.sysobjectid_dict[host_dict[host]['sysobjectid']]['vendor']
                config_dict[host] = {
                    'global': [],
                    'config': [],
                    'ifaces': {},
                }
                if not 'config_maker' in dir(vendor_cls):
                    config_dict[host]['global'] = ['ERROR: {} has no config_maker class'.format(host)]
                    continue
                config_maker_cls = vendor_cls.config_maker
                if host in mpls_nodes and len(mpls_nodes) == 2:
                    # mpls
                    mpls_nei = [x for x in mpls_nodes if x != host][0]
                    l2_neighbour = [x for x in vlanpath[host] if x not in mpls_nodes]
                    if len(l2_neighbour) > 1: 
                        config_dict[host]['global'] = ['ERROR: {} has more than 1 l2 nei'.format(host)]
                        continue
                    if not 'mpls' in dir(config_maker_cls):
                        config_dict[host]['global'] = ['ERROR: {} cannot make MPLS'.format(host)]
                        continue
                    l2_interface = vlanpath[host][l2_neighbour[0]]['port']
                    config_maker_cls.mpls(host, 
                                          config_dict, 
                                          vlan_form, 
                                          vlan_name, 
                                          l2_interface, 
                                          host_dict[mpls_nei]['ip'], 
                                          config, 
                                          logger)
                elif host in mpls_nodes and len(mpls_nodes) > 2:
                    # vpls
                    pass
                else:
                    # l2
                    if not 'create_vlan' in dir(config_maker_cls):
                        config_dict[host]['global'] = ['ERROR: {} cannot make vlan'.format(host)]
                        continue
                    if not 'add_vlan_trunk' in dir(config_maker_cls):
                        config_dict[host]['global'] = ['ERROR: {} cannot configure trunk port'.format(host)]
                        continue
                    config_maker_cls.create_vlan(host, 
                                                 config_dict, 
                                                 vlan_form['tag'], 
                                                 vlan_name, 
                                                 logger)
                    config_maker_cls.add_vlan_trunk(host, 
                                                    config_dict, 
                                                    vlan_form['tag'], 
                                                    vlanpath[host], 
                                                    logger)
                    
                if host in endpoints and end_iface_dict[host]:
                    # endpoint iface conf
                    if not 'access_port' in dir(config_maker_cls):
                        config_dict[host]['global'] = ['ERROR: {} cannot make vlan'.format(host)]
                        continue
                    config_maker_cls.access_port(host, 
                                                 config_dict,
                                                 vlan_form['vlan_id'], 
                                                 vlan_form['contract'], 
                                                 vlan_form['latin_name'], 
                                                 rate, 
                                                 end_iface_dict[host], 
                                                 logger,)
                
                #if 'create_vlan' not in dir(vendor_cls):
                #    return '{} cannot create vlan'.format(host)
                #if 'add_port_vlan' not in dir(vendor_cls):
                #    return '{} cannot add vlan to port'.format(host)
                
                
                #links = vlanpath[host]
            logger.warning('TEMP config_dict: {}'.format(config_dict))
            return config_dict    
                
        except Exception as err_message:
            logger.error('Ошибка в функции configurator.vlan_config_maker {}'.format(str(err_message)))
            
    def inet_config_maker(inet_form, 
                          vlan_name, 
                          vlanpath, 
                          host_dict, 
                          end_iface_dict, 
                          vlan_id, 
                          node, 
                          logger):
        try:
            config_dict = {}
            
            #Костыль. Проверяем что узел - джуник. Если нет то резать на Л2 будем.
            if 'iso.3.6.1.4.1.2636' not in host_dict[node]['sysobjectid']: 
                rate = ''
            else:
                rate = inet_form['rate']
            
            for host in vlanpath:
                vendor_cls = vendors.sysobjectid_dict[host_dict[host]['sysobjectid']]['vendor']
                config_dict[host] = {
                    'global': [],
                    'config': [],
                    'ifaces': {},
                }
                if not 'config_maker' in dir(vendor_cls):
                    config_dict[host]['global'] = ['ERROR: {} has no config_maker class'.format(host)]
                    continue
                config_maker_cls = vendor_cls.config_maker

                
                if host == node:
                    if not 'loopback_unnumbered' in dir(config_maker_cls):
                        config_dict[host]['global'] = ['ERROR: {} cannot make unnumbered'.format(host)]
                        continue
                    l2_interface = vlanpath[host][l2_neighbour[0]]['port']
                    config_maker_cls.loopback_unnumbered(host,
                                                         config_dict, 
                                                         l2_interface,
                                                         inet_form['tag'],
                                                         inet_form['tasknum'],
                                                         inet_form['latin_name'],
                                                         rate,
                                                         loopback,
                                                         ip_address,
                                                         logger,)
                    
                else:
                    if not 'create_vlan' in dir(config_maker_cls):
                        config_dict[host]['global'] = ['ERROR: {} cannot make vlan'.format(host)]
                        continue
                    if not 'add_vlan_trunk' in dir(config_maker_cls):
                        config_dict[host]['global'] = ['ERROR: {} cannot configure trunk port'.format(host)]
                        continue
                    config_maker_cls.create_vlan(host, 
                                                 config_dict, 
                                                 vlan_id, 
                                                 vlan_name, 
                                                 logger)
                    config_maker_cls.add_vlan_trunk(host, 
                                                    config_dict, 
                                                    vlan_id, 
                                                    vlanpath[host], 
                                                    logger)
                    
                    if host in endpoints and end_iface_dict[host]:
                        # endpoint iface conf
                        if not 'access_port' in dir(config_maker_cls):
                            config_dict[host]['global'] = ['ERROR: {} cannot make vlan'.format(host)]
                            continue

                        config_maker_cls.access_port(host, 
                                                     config_dict, 
                                                     vlan_id, 
                                                     contract, 
                                                     latin_name, 
                                                     rate, 
                                                     end_iface_dict[host], 
                                                     logger,)
                

                
                #if 'create_vlan' not in dir(vendor_cls):
                #    return '{} cannot create vlan'.format(host)
                #if 'add_port_vlan' not in dir(vendor_cls):
                #    return '{} cannot add vlan to port'.format(host)
                
                
                #links = vlanpath[host]
            logger.warning('TEMP config_dict: {}'.format(config_dict))
            return config_dict    
                
        except Exception as err_message:
            logger.error('Ошибка в функции configurator.inet_config_maker {}'.format(str(err_message)))
            
    def diagram_maker(vlan_name, vlanpath, host_dict, end_iface_dict, endpoints, node, logger):
        try:

            def short_iface(ifname):
                # Сокращаем имена интерфейсов чтобы на схеме красиво было
                short_iface_dict = {
                'gigabitethernet': 'gi',
                'GigabitEthernet': 'gi',
                'fastethernet': 'fa',
                'FastEthernet': 'fa',
                'Ethernet': 'e',
                'Port-Channel': 'po',}
                for templ in short_iface_dict:
                    if templ in ifname:
                        #ifname = ifname.replace(templ, short_iface_dict[templ])
                        ifname = re.sub('^'+templ, short_iface_dict[templ], ifname)
                        break
                return ifname
            
            # Тут мы меняем системную переменную PATH а не внтутренню PATH питона. 
            # Системная может не знать где dot лежит (исполняшка graphviz который и рисует диаграму)
            if '/usr/bin/' not in os.environ.get("PATH").split(os.pathsep):
                os.environ["PATH"] += os.pathsep + '/usr/bin/'
            # таймкод подойдет как уникальное имя файла
            fname = str(datetime.now().timestamp()).replace('.', '')
            diagram_name = '{} ({})'.format(vlan_name, ' - '.join(endpoints))
            with Diagram(diagram_name,
                         direction='LR', 
                         show=False, 
                         filename=config.temp_folder+'/'+fname) as diag: 
                #narr = {x: Bridge(x, shape="circle") 
                #        for x in vlanpath
                #        if not host_dict[x]['mpls']}
                narr = {}
                for x in vlanpath:
                    if not host_dict[x]['mpls'] and x != node:
                        narr.update({x: Bridge(x, height="0.9", width="0.9", shape="circle", fontsize="8")})
                    else:
                        narr.update({x: Router(x, height="0.9", width="0.9", shape="circle", fontsize="8")})
                if any(vlanpath[host][link]['type'] == 'vpls' 
                        for host in vlanpath 
                        for link in vlanpath[host]):
                    narr.update({'vpls': InternetServices('VPLS', 
                                                          height="0.9", 
                                                          width="0.9", 
                                                          shape="circle",
                                                          fontsize="8")})
                
                nifc = {host+link: Blank(short_iface(vlanpath[host][link]['port']), 
                                         labelloc="c", 
                                         shape="plaintext", 
                                         height="0.2",
                                         width="0.6",
                                         fontsize="8") 
                        for host in vlanpath 
                        for link in vlanpath[host] 
                        if vlanpath[host][link]['type'] not in ['vpls', 'mpls']}
                done = []
                for node in vlanpath:
                    # Тут к оконечным девайсам прикрепляем линки до клиентов
                    if node in end_iface_dict:
                        for link in end_iface_dict[node]:
                            l = link+'\n'+end_iface_dict[node][link]
                            narr[node] - Edge(label=l, color="green", fontsize="6") \
                            - Browser(height="0.2", width="0.2", shape="circle")
                    for link in vlanpath[node]:
                        if [node, link] in done or [link, node] in done: 
                            continue
                        if vlanpath[node][link]['type'] == 'mpls':
                            narr[node] - Edge(label="MPLS", 
                                              color="violet", 
                                              style="bold") \
                            - narr[link]
                        elif vlanpath[node][link]['type'] == 'vpls':
                            narr[node] \
                            - Edge(color="violet", style="bold") \
                            - narr['vpls']
                        elif (vlanpath[node][link]['type'] == 'access' or
                              vlanpath[link][node]['type'] == 'access'):
                            narr[node] - Edge(color="black", style="bold") \
                            - nifc[node+link] - Edge(label="QinQ", color="red", style="bold") \
                            - nifc[link+node] - Edge(color="black", style="bold") \
                            - narr[link]
                        elif vlanpath[node][link]['type'] == 'trunk':
                            narr[node] - Edge(color="black", style="bold") \
                            - nifc[node+link] - Edge(color="green", style="bold") \
                            - nifc[link+node] - Edge(color="black", style="bold") \
                            - narr[link]
                        
                        done.append([node, link])
                diag.format = 'png' 
                
            return config.temp_folder_name+'/'+fname+'.png'
            
        except Exception as err_message:
            logger.error('Ошибка в функции configurator.diagram_maker {}'.format(str(err_message)))
            
class nodes_sql_tables:
    def get_nodes(logger):
        #CREATE TABLE configurator_nodes (
        #id MEDIUMINT NOT NULL AUTO_INCREMENT,
        #node VARCHAR(30),
        #vendor VARCHAR(30),
        #mpls BOOL,
        #vpls BOOL,
        #ip_unnumbered BOOL,
        #ip_common BOOL,
        #loopback_iface VARCHAR(30),
        #primary key (id)
        #);
        try:
            connection = mysql.local_sql_conn()
            req = ("select * from configurator_nodes")
            with connection.cursor() as cursor:
                cursor.execute(req)
                nodes_arr = cursor.fetchall()
            connection.close()
            if not nodes_arr:
                logger.error('Failed to get configurator_nodes table')
                return []
            return nodes_arr
        except Exception as err_message:
            logger.error('Ошибка в функции nodes_sql_tables.get_nodes {}'.format(str(err_message)))
            
    def get_vlan_ranges(logger):
        #CREATE TABLE configurator_vlan_ranges (
        #id MEDIUMINT NOT NULL AUTO_INCREMENT,
        #node VARCHAR(30), 
        #range_start SMALLINT,
        #range_end SMALLINT,
        #primary key (id)
        #);
        try:
            connection = mysql.local_sql_conn()
            req = ("select * from configurator_vlan_ranges")
            with connection.cursor() as cursor:
                cursor.execute(req)
                vlans_arr = cursor.fetchall()
            connection.close()
            if not vlans_arr:
                logger.error('Failed to get configurator_vlan_ranges table')
                return []
            return vlans_arr
        except Exception as err_message:
            logger.error('Ошибка в функции nodes_sql_tables.get_vlan_ranges {}'.format(str(err_message)))
            
    def get_ip_ranges(logger):
        #CREATE TABLE configurator_ip_ranges (
        #id MEDIUMINT NOT NULL AUTO_INCREMENT,
        #node VARCHAR(30),
        #range_start VARCHAR(15),
        #range_end VARCHAR(15),
        #subnet VARCHAR(15),
        #gateway VARCHAR(15),
        #primary key (id)
        #);
        try:
            connection = mysql.local_sql_conn()
            req = ("select * from configurator_ip_ranges")
            with connection.cursor() as cursor:
                cursor.execute(req)
                ips_arr = cursor.fetchall()
            connection.close()
            if not ips_arr:
                logger.error('Failed to get configurator_ip_ranges table')
                return []
            return ips_arr
        except Exception as err_message:
            logger.error('Ошибка в функции nodes_sql_tables.get_ip_ranges {}'.format(str(err_message)))
            
    def set_node(node, vendor, mpls, vpls, ip_unnumbered, ip_common, loopback_iface, logger):
        try:
            connection = mysql.local_sql_conn()
            req = ("insert into configurator_nodes(node,vendor,mpls,vpls,ip_unnumbered,ip_common,loopback_iface)"
                   " values ('{}', '{}', {}, {}, {}, {}, '{}');".format(
                       node,vendor,mpls,vpls,ip_unnumbered,ip_common,loopback_iface))
            with connection.cursor() as cursor:
                cursor.execute(req)
            connection.commit()
            connection.close()
        except Exception as err_message:
            logger.error('Ошибка в функции nodes_sql_tables.set_node {}'.format(str(err_message)))
            
    def set_ip_range(node, range_start, range_end, subnet, gateway, logger):
        try:
            connection = mysql.local_sql_conn()
            req = ("insert into configurator_ip_ranges(node,range_start,range_end,subnet,gateway)"
                   " values ('{}', '{}', '{}', '{}', '{}');".format(
                       node,range_start,range_end,subnet,gateway))
            with connection.cursor() as cursor:
                cursor.execute(req)
            connection.commit()
            connection.close()
        except Exception as err_message:
            logger.error('Ошибка в функции nodes_sql_tables.set_ip_range {}'.format(str(err_message)))
            
    def set_vlan_range(node, range_start, range_end, logger):
        try:
            connection = mysql.local_sql_conn()
            req = ("insert into configurator_vlan_ranges(node,range_start,range_end)"
                   " values ('{}', '{}', '{}');".format(
                       node,range_start,range_end))
            with connection.cursor() as cursor:
                cursor.execute(req)
            connection.commit()
            connection.close()
        except Exception as err_message:
            logger.error('Ошибка в функции nodes_sql_tables.set_vlan_range {}'.format(str(err_message)))
            
    def edit_node(logger):
        try:
            pass
        except Exception as err_message:
            logger.error('Ошибка в функции nodes_sql_tables.edit_node {}'.format(str(err_message)))
            
    def del_node(node_id, logger):
        try:
            connection = mysql.local_sql_conn()
            req = ("delete from configurator_nodes where id = '{}'".format(node_id))
            logger.info('executing {}'.format(req))
            with connection.cursor() as cursor:
                cursor.execute(req)
            connection.commit()
            connection.close()
        except Exception as err_message:
            logger.error('Ошибка в функции nodes_sql_tables.del_node {}'.format(str(err_message)))
            
    def del_ip_range(ipr_id, logger):
        try:
            connection = mysql.local_sql_conn()
            req = ("delete from configurator_ip_ranges where id = '{}'".format(ipr_id))
            logger.info('executing {}'.format(req))
            with connection.cursor() as cursor:
                cursor.execute(req)
            connection.commit()
            connection.close()
        except Exception as err_message:
            logger.error('Ошибка в функции nodes_sql_tables.del_ip_range {}'.format(str(err_message)))
            
    def del_vlan_range(vlr_id, logger):
        try:
            connection = mysql.local_sql_conn()
            req = ("delete from configurator_vlan_ranges where id = '{}'".format(vlr_id))
            logger.info('executing {}'.format(req))
            with connection.cursor() as cursor:
                cursor.execute(req)
            connection.commit()
            connection.close()
        except Exception as err_message:
            logger.error('Ошибка в функции nodes_sql_tables.del_vlan_range {}'.format(str(err_message)))
