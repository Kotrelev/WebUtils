import config, sys, re
from lib.snmp_common import snmp_common
from lib.zabbix_common import zabbix_common
sys.path.append('/usr/local/bin/Python37/Common/')
from Vendors import vendors


class erth_inventory: 
    def links_and_stuff(hostname, logger):
        
        isp_rx = '(_(?P<service>(vlan|qnq|inet|fiber))(?P<isp>[a-zA-Z\-]+))?'
        port_rx = '(_(?P<ptype>[fegps])(?P<pnum>\d{1,2}))?(?P<mc>_mc)?'
        hname_rx = '(?P<host>(?P<name>([A-Z]+\.)?(\d+)?[a-zA-Z\-]+)(?P<tail>[a-z0-9\-]+([A-Z]+)?(k\d+)?-(as|ds|cs|dr|cr)\d+))'
        mag_regex = f'(?P<uplink>UP_|[S1-6]_UP?_)?{hname_rx}{port_rx}{isp_rx}'
        
        interfaces = zabbix_common.get_interfaces(logger)
        if not interfaces: logger.error('zabbix_common.get_interfaces failed')
        all_hnames = zabbix_common.get_hostname_list(logger)
        if not all_hnames: logger.error('zabbix_common.get_hostname_list failed')
        #logger.info(all_hnames)
        #logger.info(interfaces)
        devices_arr = []
        #ip, host_id = ip_by_hostname(hostname, logger)
        #hostid = zabbix_common.hostid_by_name(hostname, logger)
        #logger.info(hostid)
        #ip = zabbix_common.get_interface(hostid[0]['hostid'], logger, interfaces)
        #logger.info(ip)
        #zabbix_common.get_interface(hostid[0]['hostid'], logger)
        #if not ip: 
        #    logger.info('Не смог определить IP для {}'.format(hostname))
        #    return None
        devices_arr.append(hostname)
        #chain = {1:[hostname]}
        downlinks = {hostname:[]}
        
        devices_arr = list(set(devices_arr))
        all_devices_arr = []
        # в devices_arr будем записывать все девайсы в цепочке 
        
        dlks = {}
        ulks = {}
        devs = {}
        #logger.info('HERE')
        while devices_arr != []:
            try:
                
                # берем первый ip из списка на обработку
                hostname = devices_arr[0]
                if hostname in all_devices_arr:
                    # Уже видели девайс, пропускаем
                    devices_arr.remove(hostname)
                    continue
                # в all_devices_arr записываем тоже что и в devices_arr но отсюда девайсы не будем удалять после обработки
                all_devices_arr.append(hostname)
                
                hostid = zabbix_common.hostid_by_name(hostname, logger)
                if not hostid: 
                    logger.error('не нашел hostid: {}'.format(hostname))
                    devices_arr.remove(hostname)
                    continue
                ip = zabbix_common.get_interface(hostid[0]['hostid'], logger, interfaces)
                if not ip: 
                    logger.error('не нашел ip: {}'.format(hostname))
                    devices_arr.remove(hostname)
                    continue
                #logger.info('HERE')
                # собираем getSysObjectID из за mikrotik RB260 у которых дискрипшны прям в названиях интерфейсов. 
                # Заодно проверяем доступность железки.
                sysobjectid, comm = snmp_common.getSysObjectID(ip, logger)
                if not sysobjectid:
                    devices_arr.remove(hostname)
                    continue
                else:
                    if sysobjectid == 'iso.3.6.1.4.1.14988.2':
                        descoid = '1.3.6.1.2.1.31.1.1.1.1'
                    else: descoid = '1.3.6.1.2.1.31.1.1.1.18'
                #logger.info('HERE1')
                if vendors.sysobjectid_dict[sysobjectid]['model'] != 'ambiguous':
                    model = vendors.sysobjectid_dict[sysobjectid]['model']
                else:
                    model = vendors.sysobjectid_dict[sysobjectid]['vendor'].get_model(ip, comm, logger)
                
                if not model:
                    logger.error('не нашел model: {}'.format(hostname))
                #logger.info('HERE1')
                zaddrmode, zaddress = zabbix_common.get_address_a(hostname, logger)
                if not zaddrmode or not zaddress:
                    zaddress = ''
                #logger.info('HERE2')
                devs[hostname] = {'model': model, 'ip': ip, 'addr': zaddress, 'span': 1, 'bh': False, 'bh2': False, 'c': 0}
                
                #logger.info('HERE')
                
                # собираем дескрипшны
                descs = snmp_common.request(ip, config.community, descoid, logger)
                if not descs: 
                    logger.error('{}: Не нашел подписей на портах'.format(hostname))
                    continue
                descs_arr = [x.strip('STRING: ').strip('"') for x in descs.split('\n')]
                for desc in descs_arr:
                    if not desc: continue
                    # мачим даунлинк
                    downlink = re.search('([a-zA-Z0-9\-\.]+-(as|ds|cs|dr)\d+)', desc)
                    if downlink:
                        if 'UP' in desc or 'U_' in desc:
                            mag = downlink.group(1)
                            
                            #
                            if sysobjectid == 'iso.3.6.1.4.1.14988.2' and mag not in devs:
                                # берем дескр который предположительно порезан, вычленяем то что идет перед номером дома
                                mag_rx = re.search(mag_regex, mag)
                                name_len = len(mag_rx.groupdict()['name'])
                                cut_hname_arr = []
                                # берем все известные хостнеймы и режем их на ту же длинну что и наш дескр.
                                for host in all_hnames:
                                    rh = re.search(mag_regex, host)
                                    if not rh: continue
                                    cut_hname = rh.groupdict()['name'][0:name_len]+rh.groupdict()['tail']
                                    if mag == cut_hname:
                                        mag = host
                                    #cut_hname_arr.append(cut_hname+rh.groupdict()['tail'])
                            
                            if hostname in ulks:
                                if ulks[hostname] in devs:
                                    continue
                            ulks[hostname] = mag
                            #hostid = zabbix_common.hostid_by_name(hostname, logger)
                            
                            #ipx = zabbix_common.get_interface(hostid[0]['hostid'], logger, interfaces)
                        else:
                            dlks.setdefault(hostname, []).append(downlink.group(1))
                            # loop detection
                            #hostid = zabbix_common.hostid_by_name(hostname, logger)
                            #ipx = zabbix_common.get_interface(hostid, logger, interfaces)
                            if downlink.group(1) in all_devices_arr:
                                continue
                            devices_arr.append(downlink.group(1))

                devices_arr.remove(hostname)
                
            except Exception as err_message:
                logger.error('Ошибка в функции links_and_stuff {}: {}'.format(hostname,str(err_message)))
                return str(err_message)
        return dlks, ulks, devs
    
    
    def table_form(initial, dlks, ulks, devs, logger):
        try:
            #logger.info('HERE1')
            for x in dlks.copy(): 
                for h in dlks[x].copy(): 
                    if h not in devs: 
                        while h in dlks[x]:
                            dlks[x].remove(h)
                        if not dlks[x]:
                            dlks.pop(x)
                            
            for x in ulks.copy():
                if ulks[x] not in devs and x != initial:
                    logger.error('{} has wrong UPLink!'.format(x))
                    ulks.pop(x)
                    devs.pop(x)
                    for d in dlks.copy():
                        for h in dlks[d]:
                            if h == x:
                                while h in dlks[d]:
                                    dlks[d].remove(h)
                                if not dlks[d]:
                                    dlks.pop(d)
                            
            #logger.info('HERE2')
            for host in devs:
                if host not in dlks:
                    h = host
                    while h != initial:
                        if devs[ulks[h]]['bh'] == False: 
                            devs[ulks[h]]['bh'] = True
                            h = ulks[h]
                            continue
                        devs[ulks[h]]['span'] += 1
                        h = ulks[h]
            #logger.info('HERE3')
            
        except Exception as err_message:
            logger.error('Ошибка в функции table_form: {}'.format(str(err_message)))
            
        try:
            table = '<table id="tblNotification" class="sortable"><tr>'
            h = initial
            all_ends = [x for x in devs if x not in dlks]
            while all_ends:
                row = ''
                if devs[h]['bh2'] != True:

                    if h != initial and devs[ulks[h]]['c'] > 1:
                        row += '<tr>'
                    devs[h]['c'] += 1
                    rowspan = devs[h]['span']
                    model = devs[h]['model']
                    ip = devs[h]['ip']
                    addr = devs[h]['addr']
                    row += (f'<td rowspan="{rowspan}">{h}</td>'
                            f'<td rowspan="{rowspan}">{addr}</td>'
                            f'<td rowspan="{rowspan}">{model}</td>'
                            f'<td rowspan="{rowspan}">{ip}</td>')
                    devs[h]['bh2'] = True
                if h not in dlks:
                    row += '</tr>'
                    while h in dlks[ulks[h]]:
                        dlks[ulks[h]].remove(h)
                    while h in all_ends:
                        all_ends.remove(h)
                    h = ulks[h]
                elif not dlks[h]:
                    while h in dlks[ulks[h]]:
                        dlks[ulks[h]].remove(h)
                    h = ulks[h]
                else:
                    h = dlks[h][0]
                table += row
            table += '</table>'
            return table
            
        except Exception as err_message:
            logger.error('Ошибка в функции table_form ({}): {}'.format(h, str(err_message)))