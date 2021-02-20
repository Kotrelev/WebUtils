import config
import os, os.path, time, shutil, subprocess, re
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from time import gmtime, strftime

class eaton:
    def vendor():
        return 'Eaton'
    
    def get_stuff(ip, community, logger):
        return {'serial': eaton.get_serial(ip, community, logger),
                'hardware': 'unknown',
                'firmware': eaton.get_fw(ip, community, logger),
                'hostname': eaton.get_hostname(ip, community, logger),
                'location': eaton.get_location(ip, community, logger),
                'mac': eaton.get_mac(ip, community, logger)}
                
    def get_model(ip, community, logger):
        try:
            oid = '1.3.6.1.2.1.33.1.1.2.0'
            proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
                                    stdout=subprocess.PIPE,shell=True)
            (out,err) = proc.communicate()
            if out:
                return out.decode('utf-8').strip('STRING: ').strip(' \"\n')
            else:
                return None
        except Exception as err_message:
            logger.error('{}: Error in function eaton.get_model {}'.format(ip, str(err_message)))
    
    def get_serial(ip, community, logger):
        try:
            oid = 'iso.3.6.1.2.1.33.1.1.5.0'
            proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
                                    stdout=subprocess.PIPE,shell=True)
            (out,err) = proc.communicate()
            if out:
                return re.search('ID: (?P<serial>\S+)', out.decode('utf-8')).group(1)
            else:
                return None
        except Exception as err_message:
            logger.error('Error in function eaton.get_serial {}'.format(str(err_message)))
            
    def get_fw(ip, community, logger):
        try:
            oids = ['iso.3.6.1.2.1.33.1.1.3.0', 'iso.3.6.1.4.1.705.1.1.4.0', 'iso.3.6.1.4.1.534.1.1.3.0']
            for oid in oids:
                proc = subprocess.Popen("snmpwalk -Ov -t 4 -v1 -c {} {} {}".format(community, ip, oid),
                                        stdout=subprocess.PIPE,shell=True)
                (out,err) = proc.communicate()
                soft = out.decode('utf-8').strip('STRING: ').strip(' \"\n')
                if soft and 'End of MIB' not in soft:
                    if 'INV' in soft: 
                        soft = re.search('INV: (.+)', soft)
                    if soft: return soft.group(1)
            return 'unknown'
        except Exception as err_message:
            logger.error('{}: Error in function eaton.get_fw {}'.format(ip, str(err_message)))
            
    def get_hostname(ip, community, logger):
        try:
            oid = 'iso.3.6.1.2.1.1.5.0'
            proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
                                    stdout=subprocess.PIPE,shell=True)
            (out,err) = proc.communicate()
            if out:
                hostname = out.decode('utf-8').strip('STRING: ').strip(' \"\n')
                if hostname: return hostname
            return 'unknown'
        except Exception as err_message:
            logger.error('{}: Error in function eaton.get_hostname {}'.format(ip, str(err_message)))
            
    def get_location(ip, community, logger):
        try:
            oid = 'iso.3.6.1.2.1.1.6.0'
            proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
                                    stdout=subprocess.PIPE,shell=True)
            (out,err) = proc.communicate()
            if out:
                location = out.decode('utf-8').strip('STRING: ').replace('\"','').strip(' \"\n\\')
                if location: return location
            return 'unknown'
        except Exception as err_message:
            logger.error('{}: Error in function eaton.get_location {}'.format(ip, str(err_message)))
    
    def get_mac(ip, community, logger):
        try:
            oids = ['iso.3.6.1.2.1.2.2.1.6.1', 'iso.3.6.1.2.1.2.2.1.6.2']
            for oid in oids:
                proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
                                    stdout=subprocess.PIPE,shell=True)
                (out,err) = proc.communicate()
                mac = out.decode('utf-8').strip('Hex-STRING: ').strip(' \"\n').replace(' ', '')
                if mac and re.match('^[0-9A-F]{12}$', mac): return mac
            return 'unknown'
        except Exception as err_message:
            logger.error('{}: Error in function eaton.get_mac {}'.format(ip, str(err_message)))