import config
import os, os.path, time, shutil, subprocess, re
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from time import gmtime, strftime

class apc:
    def vendor():
        return 'APC'
    
    def get_stuff(ip, community, logger):
        return {'serial': apc.get_serial(ip, community, logger),
                'hardware': 'unknown',
                'firmware': apc.get_fw(ip, community, logger),
                'hostname': apc.get_hostname(ip, community, logger),
                'location': apc.get_location(ip, community, logger),
                'mac': apc.get_mac(ip, community, logger)}
                
    def get_model(ip, community, logger):
        try:
            oid = '1.3.6.1.4.1.318.1.1.1.1.1.1.0'
            proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
                                    stdout=subprocess.PIPE,shell=True)
            (out,err) = proc.communicate()
            if out:
                return out.decode('utf-8').strip('STRING: ').strip(' \"\n')
            else:
                return None
        except Exception as err_message:
            logger.error('{}: Error in function apc.get_model {}'.format(ip, str(err_message)))
    
    def get_serial(ip, community, logger):
        try:
            oids = ['iso.3.6.1.4.1.318.1.1.1.1.2.3.0', 'iso.3.6.1.4.1.318.1.4.2.2.1.3.1']
            for oid in oids:
                proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
                                        stdout=subprocess.PIPE,shell=True)
                (out,err) = proc.communicate()
                if out:
                    return out.decode('utf-8').strip('STRING: ').strip(' \"\n')
                    #snmpModel(out.decode('utf-8').strip('OID: ').strip('\n'), ip)
            return None
        except Exception as err_message:
            logger.error('Error in function apc.get_serial {}'.format(str(err_message)))
            
    def get_fw(ip, community, logger):
        try:
            oids = ['iso.3.6.1.4.1.318.1.4.2.4.1.4.1', 'iso.3.6.1.4.1.318.1.4.2.4.1.4.2']
            for oid in oids:
                proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
                                        stdout=subprocess.PIPE,shell=True)
                (out,err) = proc.communicate()
                if out:
                    return out.decode('utf-8').strip('STRING: ').strip(' \"\n')
            return None
        except Exception as err_message:
            logger.error('Error in function apc.get_fw {}'.format(str(err_message)))
            
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
            logger.error('{}: Error in function apc.get_hostname {}'.format(ip, str(err_message)))
            
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
            logger.error('{}: Error in function apc.get_location {}'.format(ip, str(err_message)))
            
    def get_mac(ip, community, logger):
        try:
            oid = 'iso.3.6.1.2.1.2.2.1.6.2'
            proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
                                    stdout=subprocess.PIPE,shell=True)
            (out,err) = proc.communicate()
            if out:
                mac = out.decode('utf-8').strip('Hex-STRING: ').strip(' \"\n').replace(' ', '')
                if mac and re.match('^[0-9A-F]{12}$', mac): return mac
            return 'unknown'
        except Exception as err_message:
            logger.error('{}: Error in function apc.get_mac {}'.format(ip, str(err_message)))