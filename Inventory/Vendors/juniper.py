#!/usr/local/bin/Python37/Avantel_ConfigBackup/env/bin/
#Python 3.7.3

import config, logging, time, os, os.path, shutil, paramiko, gzip, subprocess, re
from time import gmtime, strftime
from netmiko import ConnectHandler, NetmikoTimeoutException, file_transfer
from paramiko import SSHClient

class juniper:
    def vendor():
        return 'Juniper'
    
    def get_stuff(ip, community, logger):
        return {'serial': juniper.get_serial(ip, community, logger),
                'hardware': juniper.get_hw(ip, community, logger),
                'firmware': juniper.get_fw(ip, community, logger),
                'hostname': juniper.get_hostname(ip, community, logger),
                'location': juniper.get_location(ip, community, logger),
                'mac': juniper.get_mac(ip, community, logger)}
    
    def get_serial(ip, community, logger):
        try:
            oids = ['iso.3.6.1.4.1.2636.3.1.3.0', 'iso.3.6.1.2.1.47.1.1.1.1.11.1']
            for oid in oids:
                proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
                                        stdout=subprocess.PIPE,shell=True)
                (out,err) = proc.communicate()
                if out:
                    serial = out.decode('utf-8').strip('STRING: ').strip(' \"\n')
                    if not serial: 
                        continue
                    return serial
            return None
        except Exception as err_message:
            logger.error('{}: Error in function juniper.get_serial {}'.format(ip, str(err_message)))
            
    def get_hw(ip, community, logger):
        try:
            oids = ['iso.3.6.1.2.1.47.1.1.1.1.7.1', 
                    'iso.3.6.1.2.1.47.1.1.1.1.7.33']
            for oid in oids:
                proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
                                        stdout=subprocess.PIPE,shell=True)
                (out,err) = proc.communicate()
                if out:
                    return out.decode('utf-8').strip('STRING: ').strip(' \"\n')
            return 'unknown'
        except Exception as err_message:
            logger.error('{}: Error in function juniper.get_hw {}'.format(ip, str(err_message)))
            
    def get_fw(ip, community, logger):
        try:
            oids = ['iso.3.6.1.2.1.47.1.1.1.1.10.1', 
                    'iso.3.6.1.2.1.25.6.3.1.2.2', 
                    'iso.3.6.1.2.1.54.1.1.1.1.4.2']
            for oid in oids:
                proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
                                        stdout=subprocess.PIPE,shell=True)
                (out,err) = proc.communicate()
                if out:
                    soft = out.decode('utf-8').strip('STRING: ').strip(' \"\n')
                    if '[' in soft: 
                        soft = re.search('\[(.+)\]' ,soft).group(1)
                    return soft
            return None
        except Exception as err_message:
            logger.error('{}: Error in function juniper.get_fw {}'.format(ip, str(err_message)))
            
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
            logger.error('{}: Error in function juniper.get_hostname {}'.format(ip, str(err_message)))
            
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
            logger.error('{}: Error in function juniper.get_location {}'.format(ip, str(err_message)))
            
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
            logger.error('{}: Error in function dlink.get_mac {}'.format(ip, str(err_message)))
            
    def save_config_set(ip, hostname, logger):
        try:
            junos = {
                'device_type': 'juniper_junos',
                'host': ip,
                'username': config.ssh_tacacs_username,
                'password': config.ssh_tacacs_password,
                }
            
            filename = hostname+'_'+ip+'_dset.cfg'
            
            # Create the Netmiko SSH connection
            ssh_conn = ConnectHandler(**junos, global_delay_factor=2)
            output = ssh_conn.send_command('show configuration | display set | save '+filename)
            ssh_conn.disconnect()
            if not 'Wrote' in output:
                return False
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

    def upload_config_sftp(ip, hostname, logger):
        try:
            filename = hostname+'_'+ip
            transport = paramiko.Transport((ip, 22))
            transport.connect(username=config.ssh_tacacs_username, password=config.ssh_tacacs_password)
            sftp = paramiko.SFTPClient.from_transport(transport)
            sftp.get('/config/juniper.conf.gz', config.storage_last+filename+'.conf.gz')
            
            time.sleep(3)
            if os.path.exists(config.storage_last+filename+'.conf.gz'):
                with gzip.open(config.storage_last+filename+'.conf.gz', 'rb') as gzip_file:
                    with open(config.storage_last+filename+'.conf', 'wb') as conf_file:
                        shutil.copyfileobj(gzip_file, conf_file)
                
                shutil.copy(config.storage_last+filename+'.conf', 
                            config.storage_daily+strftime("%A", gmtime()))
                shutil.copy(config.storage_last+filename+'.conf', 
                            config.storage_monthly+strftime("%B", gmtime()))
                os.remove(config.storage_last+filename+'.conf.gz')
            else:
                logger.warning('Juniper '+filename+' file not found')
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
            
            
    def upload_config_scp(ip, hostname, logger):
        try:
            junos = { 
                'device_type': 'juniper_junos',
                'host': ip,
                'username': config.ssh_tacacs_username,
                'password': config.ssh_tacacs_password,
                }
            
            filename = hostname+'_'+ip
            file_system = '/config'
            source_file = 'juniper.conf.gz'
            dest_file = config.storage_last+filename+'.conf.gz'
            direction = 'get'
            
            # Create the Netmiko SSH connection
            ssh_conn = ConnectHandler(**junos)
            transfer_dict = file_transfer(ssh_conn,
                                        source_file=source_file, 
                                        dest_file=dest_file,
                                        file_system=file_system, 
                                        direction=direction,
                                        overwrite_file=True)
            ssh_conn.disconnect()
            if not transfer_dict['file_exists'] == True:
                logger.warning(ip+' remote config file not found')
                return False
            if not transfer_dict['file_transferred'] == True:
                logger.warning(ip+' file transfer failed')
                return False
            if not transfer_dict['file_verified'] == True:
                logger.warning(ip+' config file copy failed')
                return False
            
            with gzip.open(config.storage_last+filename+'.conf.gz', 'rb') as gzip_file:
                with open(config.storage_last+filename+'.conf', 'wb') as conf_file:
                    shutil.copyfileobj(gzip_file, conf_file)
            
            shutil.copy(config.storage_last+filename+'.conf', 
                        config.storage_daily+strftime("%A", gmtime()))
            shutil.copy(config.storage_last+filename+'.conf', 
                        config.storage_monthly+strftime("%B", gmtime()))
            os.remove(config.storage_last+filename+'.conf.gz')
            return True
            
        except NetmikoTimeoutException:
            logger.warning(ip+' SSH timeout')
            return False
        except IOError as e:
            logger.error(ip+' IOERROR '+str(e))
            return False
        except EOFError as e:
            logger.error(ip+" EOFError "+str(e))
            return False
        except Exception as e:
            logger.error(ip+" OTHER EXCEPTION "+str(e))
            return False
    
    # качаем сформированыый в save_config_set конфиг
    def upload_config_dset_scp(ip, hostname, logger):
        try:
            junos = { 
                'device_type': 'juniper_junos',
                'host': ip,
                'username': config.ssh_tacacs_username,
                'password': config.ssh_tacacs_password,
                }
            
            filename = hostname+'_'+ip+'_dset.cfg'
            file_system = '/var/home/'+config.ssh_tacacs_username+'/'
            dest_file = config.storage_last+filename
            direction = 'get'
            
            # Create the Netmiko SSH connection
            ssh_conn = ConnectHandler(**junos)
            transfer_dict = file_transfer(ssh_conn,
                                        source_file=filename, 
                                        dest_file=dest_file,
                                        file_system=file_system, 
                                        direction=direction,
                                        overwrite_file=True)
            ssh_conn.disconnect()
            if not transfer_dict['file_exists'] == True:
                logger.warning(ip+' remote config file not found')
                return False
            if (not transfer_dict['file_transferred'] == True and 
                not transfer_dict['file_verified'] == True):
                logger.warning(ip+' file transfer failed')
                return False
            if not transfer_dict['file_verified'] == True:
                logger.warning(ip+' config file copy failed')
                return False
            
            shutil.copy(config.storage_last+filename, 
                        config.storage_daily+strftime("%A", gmtime()))
            shutil.copy(config.storage_last+filename, 
                        config.storage_monthly+strftime("%B", gmtime()))
            return True
            
        except NetmikoTimeoutException:
            logger.warning(ip+' SSH timeout')
            return False
        except IOError as e:
            logger.error(ip+' IOERROR '+str(e))
            return False
        except EOFError as e:
            logger.error(ip+" EOFError "+str(e))
            return False
        except Exception as e:
            logger.error(ip+" OTHER EXCEPTION "+str(e))
            return False