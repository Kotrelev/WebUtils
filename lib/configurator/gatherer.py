import config, sys, re
from lib.snmp_common import snmp_common

sys.path.append('/usr/local/bin/Python37/Common/')
from Vendors import vendors

class ifaces_and_vlans:

    def fill_host_dict(ip, hname, host_dict, sysobjectid_dict, logger):
        try:
            sid, community = snmp_common.get_sysobjectid(ip, logger)
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
            ifaces_type, community = snmp_common.generic_request(ip, 
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
            vlans_name, community = snmp_common.generic_request(ip, 
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
                
                ifaces_name, community = snmp_common.generic_request(ip, 
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
            ifaces_descs, community = snmp_common.generic_request(ip, 
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
            ifaces_status, community = snmp_common.generic_request(ip, 
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
            ifaces_state, community = snmp_common.generic_request(ip, 
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
            ifaces_speed, community = snmp_common.generic_request(ip, 
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
            ifaces_mtu, community = snmp_common.generic_request(ip, 
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
            ip_iface, community = snmp_common.generic_request(ip, 
                                     'iso.3.6.1.2.1.4.20.1.2', 
                                     logger)
            ip_netmask, community = snmp_common.generic_request(ip, 
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