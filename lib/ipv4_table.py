# -*- coding: utf-8 -*-

import config, requests, ipaddress

class ipv4_table:
    def get_ipv4(logger):
        try:
            response = requests.get(config.get_ipv4_api)
            if response.ok and response.content != b'[]':
                return response.json()
            return None
        except Exception as err_message:
            logger.error('Ошибка в функции ipv4_table.get_ipv4 {}'.format(str(err_message)))
    
    def set_ipv4_address(logger):
        try:
            params = 'ipv4?ip={ipadr}&net={network}&netdescr=&contract={contract}&name="{customer}"&address="{address}"'
            req = set_contract_api+params
            response = requests.put(req)
            if response.ok:
                return response.json()
            return None
        except Exception as err_message:
            logger.error('Ошибка в функции ipv4_table.set_ipv4_address {}'.format(str(err_message)))
    
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
                               'mask_bits': str(gw_iface.network.prefixlen),
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
            
            