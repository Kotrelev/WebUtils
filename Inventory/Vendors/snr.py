# -*- coding: utf-8 -*-
#!/usr/local/bin/Python37/Avantel_ConfigBackup/env/bin/
#Python 3.7.3

import config, logging, time, os, os.path, shutil, paramiko, subprocess, re
from netmiko import ConnectHandler, NetmikoTimeoutException
from paramiko import SSHClient
from time import gmtime, strftime

class snr:
    def vendor():
        return 'SNR'
    
    def get_stuff(ip, community, logger):
        return {'serial': snr.get_serial(ip, community, logger),
                'hardware': snr.get_hw(ip, community, logger),
                'firmware': snr.get_fw(ip, community, logger),
                'hostname': snr.get_hostname(ip, community, logger),
                'location': snr.get_location(ip, community, logger),
                'mac': snr.get_mac(ip, community, logger)}
    
    def get_hw(ip, community, logger):
        try:
            oids = ['iso.3.6.1.2.1.47.1.1.1.1.8.1']
            for oid in oids:
                proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
                                        stdout=subprocess.PIPE,shell=True)
                (out,err) = proc.communicate()
                if out:
                    return out.decode('utf-8').strip('STRING: ').strip(' \"\n')
            return None
        except Exception as err_message:
            logger.error('{}: Error in function snr.get_hw {}'.format(ip, str(err_message)))
    
    def get_fw(ip, community, logger):
        try:
            oids = ['iso.3.6.1.4.1.40418.7.100.1.3.0', 
                    'iso.3.6.1.2.1.47.1.1.1.1.10.1']
            for oid in oids:
                proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
                                        stdout=subprocess.PIPE,shell=True)
                (out,err) = proc.communicate()
                if out:
                    return out.decode('utf-8').strip('STRING: ').strip(' \"\n')
            return None
        except Exception as err_message:
            logger.error('{}: Error in function snr.get_fw {}'.format(ip, str(err_message)))
    
    def get_serial(ip, community, logger):
        try:
            oids = ['iso.3.6.1.2.1.47.1.1.1.1.11.1']
            for oid in oids:
                proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
                                        stdout=subprocess.PIPE,shell=True)
                (out,err) = proc.communicate()
                if out:
                    return out.decode('utf-8').strip('STRING: ').strip(' \"\n')
            return None
        except Exception as err_message:
            logger.error('{}: Error in function snr.get_serial {}'.format(ip, str(err_message)))
            
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
            logger.error('{}: Error in function snr.get_hostname {}'.format(ip, str(err_message)))
            
    def get_location(ip, community, logger):
        try:
            oid = 'iso.3.6.1.2.1.1.6.0'
            proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
                                    stdout=subprocess.PIPE,shell=True)
            (out,err) = proc.communicate()
            if out:
                location = out.decode('utf-8').strip('STRING: ').replace('\"', '').strip(' \"\n\\')
                if location: return location
            return 'unknown'
        except Exception as err_message:
            logger.error('{}: Error in function snr.get_location {}'.format(ip, str(err_message)))
    
    def get_mac(ip, community, logger):
        try:
            oids = ['iso.3.6.1.2.1.2.2.1.6.11001', 
                    'iso.3.6.1.2.1.55.1.5.1.8.11001', 
                    'iso.3.6.1.2.1.2.2.1.6']
            for oid in oids:
                proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
                                        stdout=subprocess.PIPE,shell=True)
                (out,err) = proc.communicate()
                if out:
                    mac = re.search('[0-9A-F]{12}$', out.decode('utf-8').replace(' ', ''))
                    #mac = out.decode('utf-8').strip('Hex-STRING: ').strip(' \"\n').replace(' ', '')
                    if mac: return mac.group()
            return 'unknown'
        except Exception as err_message:
            logger.error('{}: Error in function snr.get_mac {}'.format(ip, str(err_message)))
    
    def login(ip, logger):
        try:
            conf = {
                'device_type': 'cisco_ios',
                'host': ip,
                'username': config.ssh_tacacs_username,
                'password': config.ssh_tacacs_password,
                'port' : 22,
                'secret': config.enable_pass
            }
    
            net_connect = ConnectHandler(**conf)
            time.sleep(2)
            enable = net_connect.check_enable_mode(check_string='#')
            if not enable:
                try:
                    net_connect.enable()
                except:
                    net_connect.enable()
                    # странная конструкция, да. Но с первого раза в enable он не заходит, вылетает
                    # в exception timeout. Приходится после вылета еще раз заходить.
            enable = net_connect.check_enable_mode(check_string='#')
            if not enable:
                net_connect.disconnect()
                logger.warning(ip+' enable mode failed')
                return False
            return net_connect
            
        except NetmikoTimeoutException:
            logger.warning(ip+' SSH timeout')
            return False
        except Exception as err:
            logger.error(ip+' '+str(err))
            return False
            
    def save_config(ip, logger):
        try:
            net_connect = snr.login(ip, logger)
            if not net_connect:
                logger.warning(ip+' failed to connect')
                return False
            
            save = net_connect.save_config(cmd='copy running-config startup-config', 
                                        confirm=True, confirm_response='Y')
            result = net_connect.read_channel()
            net_connect.disconnect()
            if '#' in result:
                return True
            else:
                logger.warning(ip+' copy failed:\n   '+save+'\n   '+result)
                return False
        except NetmikoTimeoutException:
            logger.warning(ip+' SSH timeout')
            return False
        except Exception as err:
            logger.error(ip+' '+str(err))
            return False
    
    
    def upload_config(ip, hostname, logger):
        try:
            net_connect = snr.login(ip, logger)
            if not net_connect:
                logger.warning(ip+' failed to connect')
                return False
            
            filename = hostname+'_'+ip+'.cfg'
            command = 'copy running-config tftp://'+config.backup_srv_internal+'/'+filename
            copy = net_connect.save_config(command, confirm=True, confirm_response='Y')
            time.sleep(3)
            net_connect.disconnect()
            if not 'complete' in copy:
                logger.warning(ip+' copy to tftp failed')
                return False
            
            if os.path.exists('/srv/tftp/'+filename):
                with open('/srv/tftp/'+filename, 'r') as file:
                    if '\nend' not in open('/srv/tftp/'+filename).read():
                        logger.warning(ip+' file is broken')
                        return False
                shutil.copy('/srv/tftp/'+filename, 
                            config.storage_last)
                shutil.copy('/srv/tftp/'+filename, 
                            config.storage_daily+strftime("%A", gmtime()))
                shutil.copy('/srv/tftp/'+filename, 
                            config.storage_monthly+strftime("%B", gmtime()))
                os.remove('/srv/tftp/'+filename)
                
            return True
        except IOError as e:
            logger.error(ip+'  IOERROR '+str(e))
            return False
        except EOFError as e:
            logger.error(ip+" EOFError "+str(e))
            return False
        except Exception as e:
            logger.error(ip+" OTHER EXCEPTION "+str(e))
            return False