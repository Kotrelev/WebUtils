# -*- coding: utf-8 -*-
#!/usr/local/bin/Python37/Avantel_ConfigBackup/env/bin/
#Python 3.7.3

import config, logging, time, os, os.path, shutil, paramiko, subprocess, re
from netmiko import ConnectHandler, NetmikoTimeoutException
from paramiko import SSHClient
from time import gmtime, strftime

class cisco_smb:
    def vendor():
        return 'Cisco'
    
    def get_stuff(ip, community, logger):
        return {'serial': cisco_smb.get_serial(ip, community, logger),
                'hardware': cisco_smb.get_hw(ip, community, logger),
                'firmware': cisco_smb.get_fw(ip, community, logger),
                'hostname': cisco_smb.get_hostname(ip, community, logger),
                'location': cisco_smb.get_location(ip, community, logger),
                'mac': cisco_smb.get_mac(ip, community, logger)}
    
    def get_hw(ip, community, logger):
        try:
            oids = ['iso.3.6.1.2.1.47.1.1.1.1.8.67108992', 
                    'iso.3.6.1.4.1.9.6.1.101.2.11.1.0', 
                    'iso.3.6.1.4.1.9.6.1.101.53.14.1.4.1']
            for oid in oids:
                proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
                                        stdout=subprocess.PIPE,shell=True)
                (out,err) = proc.communicate()
                if out:
                    return out.decode('utf-8').strip('STRING: ').strip(' \"\n')
            return None
        except Exception as err_message:
            logger.error('{}: Error in function cisco_smb.get_hw {}'.format(ip, str(err_message)))
            
    def get_fw(ip, community, logger):
        try:
            oids = ['iso.3.6.1.2.1.47.1.1.1.1.10.67108992', 
                    'iso.3.6.1.4.1.9.6.1.101.2.4.0', 
                    'iso.3.6.1.4.1.9.6.1.101.2.16.1.1.5.1',
                    'iso.3.6.1.4.1.9.6.1.101.53.14.1.2.1']
            for oid in oids:
                proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
                                        stdout=subprocess.PIPE,shell=True)
                (out,err) = proc.communicate()
                if out:
                    return out.decode('utf-8').strip('STRING: ').strip(' \"\n')
            return None
        except Exception as err_message:
            logger.error('{}: Error in function cisco_smb.get_fw {}'.format(ip, str(err_message)))
    
    def get_serial(ip, community, logger):
        try:
            oids = ['iso.3.6.1.2.1.47.1.1.1.1.11.67108992', 'iso.3.6.1.4.1.9.6.1.101.53.14.1.5.1']
            for oid in oids:
                proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
                                        stdout=subprocess.PIPE,shell=True)
                (out,err) = proc.communicate()
                if out:
                    return out.decode('utf-8').strip('STRING: ').strip(' \"\n')
                    #snmpModel(out.decode('utf-8').strip('OID: ').strip('\n'), ip)
            return None
        except Exception as err_message:
            logger.error('Error in function cisco_smb.get_serial {}'.format(str(err_message)))
            
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
            logger.error('{}: Error in function cisco_smb.get_hostname {}'.format(ip, str(err_message)))
            
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
            logger.error('{}: Error in function cisco_smb.get_location {}'.format(ip, str(err_message)))
    
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
            logger.error('{}: Error in function cisco_smb.get_mac {}'.format(ip, str(err_message)))
            
    def login(ip, logger):
        try:
            conf = {
                'device_type': 'cisco_ios',
                'host': ip,
                'username': config.ssh_tacacs_username,
                'password': config.ssh_tacacs_password,
                'port' : 22,
                'secret': config.enable_pass,
                'global_delay_factor': 7
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
            logger.error(ip+' login error: '+str(err))
            return False
            
    def save_config(ip, logger):
        try:
            net_connect = cisco_smb.login(ip, logger)
            if not net_connect:
                logger.warning(ip+' failed to connect')
                return False
            
            save = net_connect.save_config(cmd='copy running-config startup-config', 
                                        confirm=True, confirm_response='Y')
            net_connect.disconnect()
            if 'succeeded' in save:
                return True
            else:
                result = net_connect.read_channel()
                logger.warning(ip+' copy failed:\n   '+save+'\n   '+result)
                return False
        except NetmikoTimeoutException:
            logger.warning(ip+' SSH timeout')
            return False
        except Exception as err:
            logger.error(ip+' save cfg error: '+str(err))
            return False
    
    
    def upload_config(ip, hostname, logger):
        try:
            net_connect = cisco_smb.login(ip, logger)
            if not net_connect:
                logger.warning(ip+' failed to connect')
                return False
            
            filename = hostname+'_'+ip+'.cfg'
            command = 'copy running-config tftp://'+config.backup_srv_internal+'/'+filename+' exclude'
            copy = net_connect.send_command(command, expect_string='#')
            time.sleep(3)
            net_connect.disconnect()
            if not 'copied' in copy:
                logger.warning(ip+' copy to tftp failed')
                return False
            
            if os.path.exists('/srv/tftp/'+filename):
                if 'ip default-gateway' not in open('/srv/tftp/'+filename).read():
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
            logger.error(ip+" upload cfg error: "+str(e))
            return False
    
    
    # Ниже все то-же самое, но реализованное на paramiko а не на netmiko.
    # paramiko дает больше контроля над происходящим, т.к. каждый шаг надо самостоятельно прописывать
    # но приходится расставлять бесконечные time.sleep из-за того что железо (да и ssh) жутко медленное.
    
    
    def login_paramiko(ip, logger):
        try:
            ssh = SSHClient()
            ssh.load_system_host_keys()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, username=config.ssh_tacacs_username, 
                        password=config.ssh_tacacs_password, 
                        look_for_keys=False, allow_agent=False)
            connection = ssh.invoke_shell()
            time.sleep(5)
            stream = str(connection.recv(300))
            if not '>' in stream:
                logger.warning('Cisco '+ip+' login failed:\n   '+stream)
                connection.close()
                return False
            connection.send('enable\n')
            time.sleep(2)
            stream = str(connection.recv(300))
            if not 'assword' in stream:
                logger.warning('Cisco '+ip+' login failed:\n   '+stream)
                connection.close()
                return False
            connection.send(config.enable_pass+'\n')
            time.sleep(2)
            stream = str(connection.recv(300))
            if not '#' in stream:
                logger.warning('Cisco '+ip+' enable failed:\n   '+stream)
                connection.send('exit\n')
                connection.close()
                return False
            return connection
        except Exception as err:
            logger.error(ip+' '+str(err))
            return False
            
            
    def save_config_paramiko(ip, logger):
        try:
            connection = cisco_smb.login_paramiko(ip, logger)
            if not connection:
                logger.warning('Cisco '+ip+' failed to connect')
                return False
            
            connection.send('copy running-config startup-config\n')
            time.sleep(2)
            stream = str(connection.recv(300))
            if not 'Y/N' in stream:
                logger.warning('Cisco '+ip+' copy command failed:\n   '+stream)
                connection.send('exit\n')
                connection.close()
            connection.send('Y\n')
            time.sleep(5)
            stream = str(connection.recv(300))
            if not 'succeeded' in stream:
                logger.warning('Cisco '+ip+' save failed:\n   '+stream)
                connection.send('exit\n')
                connection.close()
            else:
                return True
    
        except Exception as err:
            logger.error(ip+' '+str(err))
            return False
    
            
    def upload_config_paramiko(ip, hostname, logger):
        try:
            connection = cisco_smb.login_paramiko(ip, logger)
            if not connection:
                logger.warning('Cisco '+ip+' failed to connect')
                return False
            
            filename = ip+'_'+hostname+'.cfg'
            command = 'copy running-config tftp://'+config.backup_srv_internal+'/'+filename+' exclude\n'
            connection.send(command)
            time.sleep(30)
            stream = str(connection.recv(300))
            if not 'copied' in stream:
                connection.send('exit\n')
                connection.close()
                logger.warning('Cisco '+ip+' copy to tftp failed: \n   '+stream)
                return False
            connection.send('exit\n')
            connection.close()
            
            if os.path.exists('/srv/tftp/'+filename):
                with open('/srv/tftp/'+filename, 'r') as file:
                    if not 'ip default-gateway' in file:
                        connection.send('exit\n')
                        connection.close()
                        logger.warning('Cisco '+filename+' file is broken')
                        return False
                shutil.copy('/srv/tftp/'+filename, 
                            config.storage_last)
                shutil.copy('/srv/tftp/'+filename, 
                            config.storage_daily+strftime("%A", gmtime()))
                shutil.copy('/srv/tftp/'+filename, 
                            config.storage_monthly+strftime("%B", gmtime()))
                os.remove('/srv/tftp/'+filename)
                return True
            else:
                connection.send('exit\n')
                connection.close()
                logger.warning('Cisco '+filename+' file not found')
                return False
                
        except IOError as e:
            logger.error(ip+'  IOERROR '+str(e))
            return False
        except EOFError as e:
            logger.error(ip+" EOFError "+str(e))
            return False
        except Exception as e:
            logger.error(ip+" OTHER EXCEPTION "+str(e))
            return False