import config, sys, re, os, random, ipaddress
from datetime import datetime
from lib.zabbix_common import zabbix_common
from lib.configurator.gatherer import ifaces_and_vlans
from lib.configurator import config_templates
from lib.common import common
from diagrams import Diagram, Edge
from diagrams.custom import Custom
from diagrams.ibm.network import Bridge
from diagrams.ibm.network import Router
from diagrams.ibm.network import InternetServices
from diagrams.ibm.network import DirectLink
from diagrams.ibm.user import Browser
from diagrams.generic.blank import Blank

sys.path.append('/usr/local/bin/Python37/Common/')
from Vendors import vendors
            
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
                                                 vlan_form['tag'], 
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
            
    def inet_router_config(inet_form, logger):
        try:
            wifi_password = 'av'+''.join(x for x in inet_form['contract'] if x.isdigit())
            while len(wifi_password) < 8: 
                wifi_password += str(random.randint(0, 9))
            identity = inet_form['contract']+'_'+inet_form['latin_name']
            admin_password = common.id_generator(10, logger)
            router_conf = config_templates.router.mikrotik.format(
                ssid = inet_form['latin_name'],
                wifi_password = wifi_password,
                ip_address = ipaddresses['ip'][0],
                subnet = ipaddresses['mask_bits'],
                gateway = ipaddresses['gateway'],
                identity = identity,
                contract = inet_form['contract'],
                admin_password = admin_password,
                )
            return router_conf
            
            
        except Exception as err_message:
            logger.error('Ошибка в функции configurator.inet_router_config {}'.format(str(err_message)))
            
    def inet_config_maker(
        inet_form,  
        vlanpath, 
        host_dict, 
        end_iface_dict, 
        ip_addresses, 
        logger
    ):
        try:
            
            config_dict = {
                'Summary': {
                    'global': 
                        ['IP {}'.format(i) for i in ip_addresses['ip']] + [
                        'NM {}'.format(ip_addresses['mask']),
                        'GW {}'.format(ip_addresses['gateway']),
                        'DNS1 188.68.187.2',
                        'DNS2 188.68.186.2',
                        'vlan {}'.format(inet_form['tag']),
                    ],
                    'config': [],
                    'ifaces': {},
                    }
            }
            
            #Костыль. Проверяем что узел - джуник. Если нет то резать на Л2 будем.
            if 'iso.3.6.1.4.1.2636' not in host_dict[inet_form['node']]['sysobjectid']: 
                rate = ''
            else:
                rate = inet_form['rate']
            
            # Тут я буду искать QinQ
            #cur_host = inet_form['hostname']
            #host_list = []
            #while cur_host not in host_list:
            #    for mag in vlanpath[cur_host]:
            #        if mag not in host_list:
            #            cur_host = mag
            #
            #    host_list.append(cur_host)
            
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

                
                if host == inet_form['node']:
                    if not 'loopback_unnumbered' in dir(config_maker_cls):
                        config_dict[host]['global'] = ['ERROR: {} cannot make unnumbered'.format(host)]
                        continue
                    l2_neighbour = list(vlanpath[host].keys())[0]
                    l2_interface = vlanpath[host][l2_neighbour]['port']
                    config_maker_cls.loopback_unnumbered(host, 
                                                         inet_form, 
                                                         config_dict, 
                                                         l2_interface, 
                                                         rate, 
                                                         ip_addresses, 
                                                         config, 
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
                                                 inet_form['tag'], 
                                                 inet_form['vlan_name'], 
                                                 logger)
                    config_maker_cls.add_vlan_trunk(host, 
                                                    config_dict, 
                                                    inet_form['tag'], 
                                                    vlanpath[host], 
                                                    logger)
                    
                    if host in end_iface_dict:
                        # endpoint iface conf
                        if not 'access_port' in dir(config_maker_cls):
                            config_dict[host]['global'] = ['ERROR: {} cannot make vlan'.format(host)]
                            continue

                        config_maker_cls.access_port(host, 
                                                     config_dict, 
                                                     inet_form['tag'], 
                                                     inet_form['contract'], 
                                                     inet_form['latin_name'], 
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