#!/usr/local/bin/Python37/Playground/env/bin/
#Python 3.7.3

import config
import subprocess, os, re, logging, argparse
from pyzabbix import ZabbixAPI
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter

from inventory import getSysObjectID, getSysDescr, getModelAmbiguous, getModelByCurl, getModel, get_interface, ping

no_serial_arr = []
no_model_arr = []
no_access_arr = []
unknown_arr = []            # SysObjectID not in sysobjectid_dict
ignored_arr = []            # It answers, but script does not know what to do
no_communication_arr = []   # No snmp/web connection
no_ping_arr = []
models_dict = {}

specific_model_dict = config.specific_model_dict
sysobjectid_dict = config.sysobjectid_dict
    
if __name__ == '__main__':
    try:
        logger = logging.getLogger('my_logger')
        handler = logging.StreamHandler()
        formatter = logging.Formatter("[%(asctime)s] %(levelname)s - %(message)s")
        handler.setLevel(logging.INFO)
        handler.setFormatter(formatter)
        logger.setLevel(logging.INFO)
        logger.addHandler(handler)
        
        z = ZabbixAPI('https://monitor.spb.avantel.ru/zabbix', 
                    user='DevNet', 
                    password='ezHMgkK6NbeKXgTN')
        
        hosts = z.host.get(monitored_hosts=1, output='extend')
        interfaces = z.hostinterface.get()
        
        z.user.logout()
        
        parser = argparse.ArgumentParser(description='ip')
        parser.add_argument('str', type=str, help='ip')
        args = parser.parse_args()
        logger.info('got arg: '+args.str)
        
        ip_dict = {}
        if re.match('\d+\.\d+\.\d+\.\d+',args.str):
            models_dict = getModel(args.str, models_dict, logger)
            logger.info('models_dict: \n'+str(models_dict))
        else:
            for host in hosts:
                ip = get_interface(host['hostid'])
                if '10.60.' in ip or '188.68.187.' in ip or '10.61.' in ip:
                    ip_dict[ip] = [host['name']]
            
            with ThreadPoolExecutor(max_workers=500) as executor:
                results = [executor.submit(getModel, ip, models_dict, logger) for ip in ip_dict]
            for v in models_dict:
                print(v+'\n')
                for m in models_dict[v]:
                    print('  '+m+'\n'+str(models_dict[v][m]))
            print('-----')
            print('No serial number: {}'.format(str(no_serial_arr)))
            print('No model: {}'.format(str(no_model_arr)))
            print('No access: {}'.format(str(no_access_arr)))
            print('Unknown SysObjectID: {}'.format(str(unknown_arr)))
            print('Ignored: \n')
            for ip in ignored_arr:
                print(' {}: {}'.format(ip, ip_dict[ip]))
            print('No communication:\n')
            for ip in no_communication_arr:
                print(' {}: {}'.format(ip, ip_dict[ip]))
            print('No Ping:\n')
            for ip in no_ping_arr:
                print(' {}: {}'.format(ip, ip_dict[ip]))
            
    except Exception as err_message:
        logger.error(str(err_message))