import config
from pyzabbix import ZabbixAPI

class zabbix_common:
    """
    zabbix_common class contanes generic functions for various purposes. 
    They all interact with zabbix in some way.
    """
    
    def get_hosts(logger, monitored=True):
        """
        get_hosts returns list of dicts from zabbix's hosts table
    
        :param logger: just logger to log things
        :param monitored: can be set to false if we need to get all devices
        :return: list of dicts like this: 
        {'hostid': '10504',
         'proxy_hostid': '0',
         'host': 'Finlyand35-as2',
         'status': '0',
         'disable_until': '0',
         'error': '',
         'available': '0',
         'errors_from': '0',
         'lastaccess': '0',
         'ipmi_authtype': '-1',
         'ipmi_privilege': '2',
         'ipmi_username': '',
         'ipmi_password': '',
         'ipmi_disable_until': '0',
         'ipmi_available': '0',
         'snmp_disable_until': '0',
         'snmp_available': '1',
         'maintenanceid': '0',
         'maintenance_status': '0',
         'maintenance_type': '0',
         'maintenance_from': '0',
         'ipmi_errors_from': '0',
         'snmp_errors_from': '0',
         'ipmi_error': '',
         'snmp_error': '',
         'jmx_disable_until': '0',
         'jmx_available': '0',
         'jmx_errors_from': '0',
         'jmx_error': '',
         'name': 'Finlyand35-as2',
         'flags': '0',
         'templateid': '0',
         'description': '',
         'tls_connect': '1',
         'tls_accept': '1',
         'tls_issuer': '',
         'tls_subject': '',
         'tls_psk_identity': '',
         'tls_psk': '',
         'proxy_address': '',
         'auto_compress': '1'}
        """ 
        try:
            zabbix_conn = ZabbixAPI(config.zabbix_link,
                                    user=config.zabbix_user,
                                    password=config.zabbix_pass)
            
            hosts = zabbix_conn.host.get(output='extend') #monitored_hosts=1, 
            zabbix_conn.user.logout()
            if monitored:
                return [x for x in hosts if x['status']=='0']
            return hosts
        except Exception as err_message:
            logger.error('Ошибка в функции zabbix_common.get_hosts {}'.format(str(err_message)))
    
    def get_hostname_list(logger, monitored=True):
        """
        get_hostname_list returns list of hosts from zabbix (not names)
    
        :param logger: just logger to log things
        :param monitored: can be set to false if we need to get all devices
        :return: sorted list of strings. e.g. ['BMor18-as2', 'Pirog17-as1']
        """ 
        try:
            zabbix_conn = ZabbixAPI(config.zabbix_link,
                                    user=config.zabbix_user,
                                    password=config.zabbix_pass)
            if monitored:
                hosts = zabbix_conn.host.get(monitored_hosts=1, output=['host'])
            else:
                hosts = zabbix_conn.host.get(output=['host'])
            zabbix_conn.user.logout()
            return sorted([h['host'] 
                           for h in hosts 
                           if any(x in h['host'] 
                                  for x in ['-as', '-ds', '-cs', '-cr'])
                          ])
        except Exception as err_message:
            logger.error('Ошибка в функции zabbix_common.get_hostname_list {}'.format(str(err_message)))
            
    def get_interfaces(logger):
        """
        get_interfaces returns list of interfaces as it gets it from zabbix
        
        :param logger: just logger to log things
        :return: list of dicts. Keys: ip, hostid
        """
        try:
            zabbix_conn = ZabbixAPI(config.zabbix_link,
                                    user=config.zabbix_user,
                                    password=config.zabbix_pass)
            interfaces = zabbix_conn.hostinterface.get()
            zabbix_conn.user.logout()
            return interfaces
        
        except Exception as err_message:
            logger.error('Ошибка в функции zabbix_common.get_interfaces {}'.format(str(err_message)))
            
    def get_interface(hostid, logger, interfaces=False):
        """
        get_interface returns specific ip address by hostname
        
        :param hostid: host id in zabbix
        :param logger: just logger to log things
        :param interfaces: if we already took all interfaces from zabbix we can put it here, to make it run faster
        :return: string (ip address) e.g.: '1.1.1.1'
        """
        try:
            if not interfaces:
                interfaces = zabbix_common.get_interfaces(logger)
            for interface in interfaces:
                if interface['hostid'] == hostid:
                    return interface['ip']
                
        except Exception as err_message:
            logger.error('Ошибка в функции zabbix_common.get_interface {}'.format(str(err_message)))
        
    def hostid_by_name(host, logger):
        """
        hostid_by_name used to get hostid by hostname
        
        :param host: host id in zabbix
        :param logger: just logger to log things
        :return: array with one dict with keys 'hostid', 'host' and 'name'. e.g. [{'hostid': '10934', 'host': 'BMor18-cs2', 'name': 'BMor18-cs2'}]
        """
        try:
            zabbix_conn = ZabbixAPI(config.zabbix_link,
                                    user=config.zabbix_user,
                                    password=config.zabbix_pass)
            dev_arr = zabbix_conn.host.get(filter={'name': host}, 
                                           output=['hostid','host','name'])
            if not dev_arr:
                dev_arr = zabbix_conn.host.get(filter={'host': host}, 
                                               output=['hostid','host','name'])
            zabbix_conn.user.logout()
            return dev_arr # [{'hostid': '10934', 'host': 'BMor18-cs2', 'name': 'BMor18-cs2'}]
        except Exception as err_message:
            logger.error('Ошибка в функции hostid_by_name {}'.format(str(err_message)))
            return None
        
    def get_address_a(host, logger):
        try:
            zabbix_conn = ZabbixAPI(config.zabbix_link,
                                    user=config.zabbix_user,
                                    password=config.zabbix_pass)
            dev_arr = zabbix_conn.host.get(filter={'host': host}, 
                                           output=['host', 'name', 'inventory'], 
                                           selectInventory=['inventory_mode', 'site_address_a'])
            zabbix_conn.user.logout()

            if 'site_address_a' in dev_arr[0]['inventory']:
                return(dev_arr[0]['inventory']['inventory_mode'], 
                       dev_arr[0]['inventory']['site_address_a'])
            return(None, None)
        except Exception as err_message:
            logger.error('Ошибка в функции get_address_a {}'.format(str(err_message)))
            return None
        
    def get_item(host_id, logger):
        """
        """
        try:
            zabbix_conn = ZabbixAPI(config.zabbix_link,
                                    user=config.zabbix_user,
                                    password=config.zabbix_pass)
            items = zabbix_conn.do_request('item.get', {'hostids':[host_id],
                                           'output': ['itemid','name']})
            zabbix_conn.user.logout()
            return items
        
        except Exception as err_message:
            logger.error('Ошибка в функции zabbix_common.get_item {}'.format(str(err_message)))
        