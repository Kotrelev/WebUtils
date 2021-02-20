# -*- coding: utf-8 -*-
#Python 3.7.3

import config
import os, os.path, time, shutil, subprocess, re
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from time import gmtime, strftime

class eltex:
    def vendor():
        return 'Eltex'
    
    def get_stuff(ip, community, logger):
        return {'serial': eltex.get_serial(ip, community, logger),
                'hardware': 'unknown',
                'firmware': eltex.get_fw(ip, community, logger),
                'hostname': eltex.get_hostname(ip, community, logger),
                'location': eltex.get_location(ip, community, logger),
                'mac': eltex.get_mac(ip, community, logger)}
    
    def get_serial(ip, community, logger):
        try:
            oids = ['iso.3.6.1.4.1.35265.4.3.0', 'iso.3.6.1.2.1.1.6.0']
            for oid in oids:
                proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
                                        stdout=subprocess.PIPE,shell=True)
                (out,err) = proc.communicate()
                if out:
                    serial = out.decode('utf-8').strip('STRING: ').strip(' \"\n')
                    if not 'VI' in serial: continue
                    return serial
                    #snmpModel(out.decode('utf-8').strip('OID: ').strip('\n'), ip)
        except Exception as err_message:
            logger.error('{}: Error in function eltex.get_serial {}'.format(ip, str(err_message)))
            
    def get_fw(ip, community, logger):
        try:
            oids = ['iso.3.6.1.4.1.35265.1.9.3.0', 'iso.3.6.1.4.1.35265.4.5.0']
            for oid in oids:
                proc = subprocess.Popen("snmpwalk -Ov -t 4 -v1 -c {} {} {}".format(community, ip, oid),
                                        stdout=subprocess.PIPE,shell=True)
                (out,err) = proc.communicate()
                if out:
                    fw = out.decode('utf-8').strip('STRING: ').strip(' #\"\n')
                    if 'Linux' in fw:
                        return re.search('(Linux version \S+)', fw).group()
                    elif fw: return fw
            return 'unknown'
        except Exception as err_message:
            logger.error('{}: Error in function eltex.get_fw {}'.format(ip, str(err_message)))
            
    def get_hostname(ip, community, logger):
        try:
            oid = 'iso.3.6.1.2.1.1.5.0'
            proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
                                    stdout=subprocess.PIPE,shell=True)
            (out,err) = proc.communicate()
            if out:
                hostname = out.decode('utf-8').strip('STRING: ').strip(' \"\n')
                if hostname and not 'Hex-STRING' in hostname: return hostname
            return 'unknown'
        except Exception as err_message:
            logger.error('{}: Error in function eltex.get_hostname {}'.format(ip, str(err_message)))
            
    def get_location(ip, community, logger):
        try:
            oid = 'iso.3.6.1.2.1.1.6.0'
            proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
                                    stdout=subprocess.PIPE,shell=True)
            (out,err) = proc.communicate()
            if out:
                location = out.decode('utf-8').strip('STRING: ').replace('\"','').strip(' \"\n\\')
                if location and not 'Hex-STRING:' in location: return location
            return 'unknown'
        except Exception as err_message:
            logger.error('{}: Error in function eltex.get_location {}'.format(ip, str(err_message)))
    
    def get_mac(ip, community, logger):
        try:
            oid = 'iso.3.6.1.4.1.35265.4.15.0'
            proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
                                    stdout=subprocess.PIPE,shell=True)
            (out,err) = proc.communicate()
            if out:
                mac = out.decode('utf-8').strip('STRING: ').strip(' \"\n').replace(':', '')
                if mac and re.match('^[0-9A-F]{12}$', mac): return mac
            return 'unknown'
        except Exception as err_message:
            logger.error('{}: Error in function eltex.get_mac {}'.format(ip, str(err_message)))
            
class eltex2:
    def vendor():
        return 'Eltex'
    
    def get_stuff(ip, community, logger):
        stuff = eltex2.get_serial(ip, community, logger)
        if stuff:
            return {'serial': stuff['serial'],
                    'firmware': stuff['firmware'],
                    #'model': stuff['model'],
                    'mac': stuff['mac'].replace(':', ''),
                    'hardware': 'unknown',
                    'hostname': eltex2.get_hostname(ip, community, logger),
                    'location': eltex2.get_location(ip, community, logger),
                    #'mac': eltex2.get_mac(ip, community, logger)
               }
        return None
        
    def get_model(ip, vendor, logger):
        try:
            curl = '/cgi-bin/login'
            crl, err = subprocess.Popen("curl --silent --connect-timeout 5 http://"+ip+curl,
                                    stdout=subprocess.PIPE,shell=True).communicate()
            rcrl = re.search('<title>(TAU-\S+|RG-\S+):', crl.decode('utf-8'))
            if rcrl:
                return rcrl.group(1)
        except Exception as err_message:
            logger.error('{}: Ошибка в функции eltex2.get_model {}'.format(ip, str(err_message)))
    
    def get_serial(ip, community, logger):
        try:
            url = "http://"+ip+"/cgi-bin/login"
            user = config.voip_username2
            passw = config.voip_password2
            action = "\"username="+user+"&password="+passw+"&sbm=%&referrer=\""
            curl = "curl --silent -c /tmp/cookie"+ip+" --data "+action+" "+url
            crl, err = subprocess.Popen(curl ,stdout=subprocess.PIPE,shell=True).communicate()
            curl2 = 'curl --silent -b /tmp/cookie'+ip+' http://'+ip+'/cgi-bin/webif/admin/info.sh'
            crl2, err = subprocess.Popen(curl2 ,stdout=subprocess.PIPE,shell=True).communicate()

            stuff_regex = '<.+>Версия прошивки</td><.+>\n(?P<firmware>.+)\n</td></tr>.+'
            stuff_regex += '<.+>Тип устройства</td><.+>\n(?P<model>.+)\n</td></tr>.+'
            stuff_regex += '<.+>Серийный номер</td><.+>\n(?P<serial>.+)\n</td></tr>.+'
            stuff_regex += 'адрес</td><.+>\n(?P<mac>.+)\n</td></tr>.+'
            stuff = re.search(stuff_regex, crl2.decode('utf-8'), re.DOTALL)
            
            if stuff:
                return stuff.groupdict()
            return None
            
        except Exception as err_message:
            logger.error('Error in function eltex2.get_serial {}'.format(str(err_message)))
            
    def get_hostname(ip, community, logger):
        try:
            oid = 'iso.3.6.1.2.1.1.5.0'
            proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
                                    stdout=subprocess.PIPE,shell=True)
            (out,err) = proc.communicate()
            if out:
                hostname = out.decode('utf-8').strip('STRING: ').strip(' \"\n')
                if hostname and len(hostname) < 30: return hostname
            return 'unknown'
        except Exception as err_message:
            logger.error('{}: Error in function eltex2.get_hostname {}'.format(ip, str(err_message)))
            
    def get_location(ip, community, logger):
        try:
            oid = 'iso.3.6.1.2.1.1.6.0'
            proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
                                    stdout=subprocess.PIPE,shell=True)
            (out,err) = proc.communicate()
            if out:
                location = out.decode('utf-8').strip('STRING: ').replace('\"','').strip(' \"\n\\')
                if location and len(location) < 30: return location
            return 'unknown'
        except Exception as err_message:
            logger.error('{}: Error in function eltex2.get_location {}'.format(ip, str(err_message)))
    
    def get_mac(ip, community, logger):
        try:
            oid = 'iso.3.6.1.2.1.2.2.1.6.2'
            proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
                                    stdout=subprocess.PIPE,shell=True)
            (out,err) = proc.communicate()
            if out:
                return out.decode('utf-8').strip('Hex-STRING: ').strip(' \"\n').replace(' ', '')
            return 'unknown'
        except Exception as err_message:
            logger.error('{}: Error in function eltex2.get_mac {}'.format(ip, str(err_message)))
            
            