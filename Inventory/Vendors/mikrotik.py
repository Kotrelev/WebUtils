#!/usr/local/bin/Python37/Avantel_ConfigBackup/env/bin/
#Python 3.7.3

import config, logging, time, os, os.path, shutil, paramiko, subprocess, re
from netmiko import ConnectHandler, NetmikoTimeoutException
from paramiko import SSHClient
from scp import SCPClient
from time import gmtime, strftime

class mikrotik:
    def vendor():
        return 'Mikrotik'
    
    def get_stuff(ip, community, logger):
        return {'serial': mikrotik.get_serial(ip, community, logger),
                'hardware': mikrotik.get_hw(ip, community, logger),
                'firmware': mikrotik.get_fw(ip, community, logger),
                'hostname': mikrotik.get_hostname(ip, community, logger),
                'location': mikrotik.get_location(ip, community, logger),
                'mac': mikrotik.get_mac(ip, community, logger)}
                
    def get_model(ip, community, logger):
        try:
            oid = '1.3.6.1.2.1.1.1.0'
            proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
                                    stdout=subprocess.PIPE,shell=True)
            (out,err) = proc.communicate()
            if out:
                return out.decode('utf-8').strip('STRING: ').strip(' \"\n')
            else:
                return None
        except Exception as err_message:
            logger.error('{}: Error in function mikrotik.get_model {}'.format(ip, str(err_message)))
    
    def get_serial(ip, community, logger):
        try:
            oid = 'iso.3.6.1.4.1.14988.1.1.7.3.0'
            proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
                                    stdout=subprocess.PIPE,shell=True)
            (out,err) = proc.communicate()
            if out:
                return out.decode('utf-8').strip('STRING: ').strip(' \"\n')
            else:
                return None
        except Exception as err_message:
            logger.error('{}: Error in function mikrotik.get_serial {}'.format(ip, str(err_message)))

    def get_hw(ip, community, logger):
        try:
            oids = ['iso.3.6.1.2.1.47.1.1.1.1.7.65536']
            for oid in oids:
                proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
                                        stdout=subprocess.PIPE,shell=True)
                (out,err) = proc.communicate()
                if out:
                    return out.decode('utf-8').strip('STRING: ').strip(' \"\n')
            return 'unknown'
        except Exception as err_message:
            logger.error('{}: Error in function mikrotik.get_hw {}'.format(ip, str(err_message)))
            
    def get_fw(ip, community, logger):
        try:
            oids = ['iso.3.6.1.4.1.14988.1.1.7.4.0']
            for oid in oids:
                proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
                                        stdout=subprocess.PIPE,shell=True)
                (out,err) = proc.communicate()
                if out:
                    return out.decode('utf-8').strip('STRING: ').strip(' \"\n')
            return 'unknown'
        except Exception as err_message:
            logger.error('{}: Error in function mikrotik.get_fw {}'.format(ip, str(err_message)))
            
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
            logger.error('{}: Error in function mikrotik.get_hostname {}'.format(ip, str(err_message)))
            
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
            logger.error('{}: Error in function mikrotik.get_location {}'.format(ip, str(err_message)))
            
    def get_mac(ip, community, logger):
        try:
            oid = 'iso.3.6.1.2.1.17.1.1.0'
            proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
                                    stdout=subprocess.PIPE,shell=True)
            (out,err) = proc.communicate()
            if out:
                mac = out.decode('utf-8').strip('Hex-STRING: ').strip(' \"\n').replace(' ', '')
                if mac and re.match('^[0-9A-F]{12}$', mac): return mac
            return 'unknown'
        except Exception as err_message:
            logger.error('{}: Error in function mikrotik.get_mac {}'.format(ip, str(err_message)))
            
    def save_config(ip, logger):
        try:
            conf = {
                'device_type': 'mikrotik_routeros',
                'host': ip,
                'username': config.ssh_tacacs_username,
                'password': config.ssh_tacacs_password,
                'port' : 22,
                'global_delay_factor': 7
            }
    
            net_connect = ConnectHandler(**conf)
            
            net_connect.send_config_set('export compact file=config')
            net_connect.send_config_set('system backup save name=backup')
            net_connect.disconnect()
            return True
        except NetmikoTimeoutException:
            logger.warning(ip+' SSH timeout')
            return False
        except Exception as err:
            logger.error(ip+' '+str(err))
            return False
    
    
    def upload_config(ip, hostname, logger):
        try:
            filename = hostname+'_'+ip
            transport = paramiko.Transport((ip, 22))
            transport.connect(username=config.ssh_tacacs_username, password=config.ssh_tacacs_password)
            sftp = paramiko.SFTPClient.from_transport(transport)
            sftp.get('/config.rsc', config.storage_last+filename+'.rsc')
            time.sleep(3)
            if os.path.exists(config.storage_last+filename+'.rsc'):
                # вырезаем из первой строки дату и время, чтобы они не попадали в коммит
                with open(config.storage_last+filename+'.rsc', "r") as configuration:
                    lines = configuration.readlines()
                    if ' by ' in lines[0]:
                        lines[0] = '# '+lines[0].split(' by ')[1]
                with open(config.storage_last+filename+'.rsc', "w") as configuration:
                    configuration.writelines(lines)
                shutil.copy(config.storage_last+filename+'.rsc', 
                            config.storage_daily+strftime("%A", gmtime()))
                shutil.copy(config.storage_last+filename+'.rsc', 
                            config.storage_monthly+strftime("%B", gmtime()))
            else:
                logger.warning('RouterOS '+filename+' file not found')
            sftp.get('/backup.backup', config.storage_last+filename+'.backup')
            time.sleep(3)
            if os.path.exists(config.storage_last+filename+'.backup'):
                shutil.copy(config.storage_last+filename+'.backup', 
                            config.storage_daily+strftime("%A", gmtime()))
                shutil.copy(config.storage_last+filename+'.backup',
                            config.storage_monthly+strftime("%B", gmtime()))
            else:
                logger.warning('RouterOS '+filename+' file not found')
                return False
            sftp.close()
            transport.close()
            return True
        except IOError as e:
            logger.error(ip+' IOERROR '+str(e))
            return False
        except EOFError as e:
            logger.error(ip+" EOFError "+str(e))
            return False
        except Exception as e:
            logger.error(ip+" OTHER EXCEPTION "+str(e))
            return False