# -*- coding: utf-8 -*-
#!/usr/local/bin/Python37/Avantel_ConfigBackup/env/bin/
#Python 3.7.3

import config, logging, time, os, os.path, shutil, paramiko, subprocess, re
from paramiko import SSHClient
from time import gmtime, strftime

class dlink:
    def vendor():
        return 'D-link'
    
    def get_stuff(ip, community, logger):
        return {'serial': dlink.get_serial(ip, community, logger),
                'hardware': dlink.get_hw(ip, community, logger),
                'firmware': dlink.get_fw(ip, community, logger),
                'hostname': dlink.get_hostname(ip, community, logger),
                'location': dlink.get_location(ip, community, logger),
                'mac': dlink.get_mac(ip, community, logger)}
    
    def get_hw(ip, community, logger):
        try:
            oids = ['iso.3.6.1.2.1.47.1.1.1.1.8.1', 'iso.3.6.1.2.1.16.19.3.0']
            for oid in oids:
                proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
                                        stdout=subprocess.PIPE,shell=True)
                (out,err) = proc.communicate()
                if out:
                    return out.decode('utf-8').strip('STRING: ').strip(' \"\n')
            return 'unknown'
        except Exception as err_message:
            logger.error('{}: Error in function dlink.get_hw {}'.format(ip, str(err_message)))
    
    def get_fw(ip, community, logger):
        try:
            oids = ['iso.3.6.1.2.1.47.1.1.1.1.9.1', 'iso.3.6.1.2.1.16.19.2.0']
            for oid in oids:
                proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
                                        stdout=subprocess.PIPE,shell=True)
                (out,err) = proc.communicate()
                if out:
                    return out.decode('utf-8').strip('STRING: ').strip(' \"\n').strip('Build ')
            return None
        except Exception as err_message:
            logger.error('{}: Error in function dlink.get_fw {}'.format(ip, str(err_message)))
    
    def get_serial(ip, community, logger):
        try:
            oids = ['iso.3.6.1.2.1.47.1.1.1.1.11.1', 'iso.3.6.1.4.1.171.12.1.1.12.0']
            for oid in oids:
                proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
                                        stdout=subprocess.PIPE,shell=True)
                (out,err) = proc.communicate()
                if out:
                    return out.decode('utf-8').strip('STRING: ').strip(' \"\n')
            return None
        except Exception as err_message:
            logger.error('Error in function dlink.get_serial {}'.format(str(err_message)))
    
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
            logger.error('{}: Error in function dlink.get_hostname {}'.format(ip, str(err_message)))
            
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
            logger.error('{}: Error in function dlink.get_location {}'.format(ip, str(err_message)))
    
    def get_mac(ip, community, logger):
        try:
            oid = 'iso.3.6.1.2.1.2.2.1.6.1'
            proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
                                    stdout=subprocess.PIPE,shell=True)
            (out,err) = proc.communicate()
            if out:
                mac = out.decode('utf-8').strip('Hex-STRING: ').strip(' \"\n').replace(' ', '')
                if mac and re.match('^[0-9A-F]{12}$', mac): return mac
            return 'unknown'
        except Exception as err_message:
            logger.error('{}: Error in function dlink.get_mac {}'.format(ip, str(err_message)))
    
    
    def login(ip, logger):
        try:
            ssh = SSHClient()
            ssh.load_system_host_keys()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, username=config.ssh_tacacs_username, 
                        password=config.ssh_tacacs_password, 
                        look_for_keys=False, allow_agent=False)
            connection = ssh.invoke_shell()
            connection.settimeout(50)
            time.sleep(5)
            stream = str(connection.recv(1300))
            if not '#' in stream:
                logger.warning('Dlink '+ip+' login failed:\n   '+stream)
                connection.close()
                return False
#            connection.send('enable\n')
#            time.sleep(2)
#            stream = str(connection.recv(300))
#            if not 'assword' in stream:
#                logger.warning('Cisco '+ip+' login failed:\n   '+stream)
#                connection.close()
#                return False
#            connection.send(config.enable_pass+'\n')
#            time.sleep(2)
#            stream = str(connection.recv(300))
#            if not '#' in stream:
#                logger.warning('Cisco '+ip+' enable failed:\n   '+stream)
#                connection.send('exit\n')
#                connection.close()
#                return False
            return connection
        except Exception as err:
            logger.error(ip+' '+str(err))
            return False
            
            
    def save_config(ip, logger):
        try:
            connection = dlink.login(ip, logger)
            if not connection:
                logger.warning('Dlink '+ip+' failed to connect')
                return False
            
            connection.send('save\n')
            time.sleep(5)
            stream = str(connection.recv(300))
            if not 'Success' in stream:
                logger.warning('Dlink '+ip+' save failed:\n   '+stream)
                connection.send('exit\n')
                connection.close()
            else:
                return True
    
        except Exception as err:
            logger.error(ip+' '+str(err))
            return False
    
            
    def upload_config(ip, hostname, logger):
        try:
            connection = dlink.login(ip, logger)
            if not connection:
                logger.warning('Dlink '+ip+' failed to connect')
                return False
            
            filename = ip+'_'+hostname+'.cfg'
            command = 'upload cfg_toTFTP '+config.backup_srv_internal+' '+filename+'\n'
            connection.send(command)
            time.sleep(10)
            stream = str(connection.recv(300))
            logger.info(stream)
            if not 'Success' in stream:
                #connection.send('logout\n')
                #connection.close()
                logger.warning('Dlink '+ip+' copy to tftp failed: \n   '+stream)
                return False
            #connection.send('logout\n')
            #connection.close()
            
            if os.path.exists('/srv/tftp/'+filename):
                if 'End of configuration' not in open('/srv/tftp/'+filename).read():
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
            else:
                #connection.send('logout\n')
                #connection.close()
                logger.warning('Dlink '+filename+' file not found')
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
            
    def upload_config_c1(ip, hostname, logger):
        try:
            connection = dlink.login(ip, logger)
            if not connection:
                logger.warning('Dlink '+ip+' failed to connect')
                return False
            
            filename = ip+'_'+hostname+'.cfg'
            command = 'upload cfg_toTFTP '+config.backup_srv_internal+' dest_file '+filename+'\n'
            connection.send(command)
            time.sleep(10)
            stream = str(connection.recv(300))
            logger.info(stream)
            if not 'Success' in stream:
                #connection.send('logout\n')
                #connection.close()
                logger.warning('Dlink '+ip+' copy to tftp failed: \n   '+stream)
                return False
            #connection.send('logout\n')
            #connection.close()
            
            if os.path.exists('/srv/tftp/'+filename):
                if 'End of configuration' not in open('/srv/tftp/'+filename).read():
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
            else:
                #connection.send('logout\n')
                #connection.close()
                logger.warning('Dlink '+filename+' file not found')
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