#!/usr/local/bin/Python37/Avantel_ConfigBackup/env/bin/
#Python 3.7.3

import config, logging, time, os, os.path, shutil, paramiko, subprocess
from netmiko import ConnectHandler, NetmikoTimeoutException
from paramiko import SSHClient
from scp import SCPClient
from time import gmtime, strftime

class ats:
    def vendor():
        return 'ATS'
    
    def get_stuff(ip, community, logger):
        return {'serial': ats.get_serial(ip, community, logger),
                'hardware': 'unknown',
                'firmware': ats.get_fw(ip, community, logger),
                'hostname': ats.get_hostname(ip, community, logger),
                'location': ats.get_location(ip, community, logger),
                'mac': 'unknown'}
                
    def get_model(ip, community, logger):
        try:
            oid = '1.3.6.1.4.1.22138.1.10.2.1.0'
            proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
                                    stdout=subprocess.PIPE,shell=True)
            (out,err) = proc.communicate()
            if out:
                if 'ATS' not in out.decode('utf-8'):
                    return None
                return out.decode('utf-8').strip('STRING: ').strip(' \"\n')
            return None
        except Exception as err_message:
            logger.error('{}: Error in function ats.get_model {}'.format(ip, str(err_message)))
    
    def get_serial(ip, community, logger):
        try:
            oid = 'iso.3.6.1.4.1.22138.1.10.10.0'
            proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
                                    stdout=subprocess.PIPE,shell=True)
            (out,err) = proc.communicate()
            if out:
                serial = out.decode('utf-8').strip('End of MIB\nSTRING: ').strip(' \"\n')
                if serial.isdigit() and len(serial) == 14:
                    return serial
            return None
        except Exception as err_message:
            logger.error('Error in function getSysObjectID {}'.format(str(err_message)))
            
    def get_fw(ip, community, logger):
        try:
            oid = 'iso.3.6.1.4.1.22138.1.10.8.0'
            proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
                                    stdout=subprocess.PIPE,shell=True)
            (out,err) = proc.communicate()
            if out:
                return out.decode('utf-8').strip('STRING: ').strip(' \"\n').strip('WEBtel II ES AUX ver: ')
            return 'unknown'
        except Exception as err_message:
            logger.error('{}: Error in function ats.get_fw {}'.format(ip, str(err_message)))
            
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
            logger.error('{}: Error in function ats.get_hostname {}'.format(ip, str(err_message)))
            
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
            logger.error('{}: Error in function ats.get_location {}'.format(ip, str(err_message)))