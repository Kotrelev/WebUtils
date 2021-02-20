# -*- coding: utf-8 -*-
#!/usr/local/bin/Python37/Inventory/env/bin/
#Python 3.7.3

import config, logging, time, os, os.path, shutil, paramiko, subprocess, re
from netmiko import ConnectHandler, NetmikoTimeoutException
from paramiko import SSHClient
from time import gmtime, strftime

class cisco:
    def vendor():
        return 'Cisco'
    
    def get_stuff(ip, community, logger):
        return {'serial': cisco.get_serial(ip, community, logger),
                'hardware': cisco.get_hw(ip, community, logger),
                'firmware': cisco.get_fw(ip, community, logger),
                'hostname': cisco.get_hostname(ip, community, logger),
                'location': cisco.get_location(ip, community, logger),
                'mac': cisco.get_mac(ip, community, logger)
                }
    
    def get_hw(ip, community, logger):
        try:
            oids = ['iso.3.6.1.4.1.9.3.6.2.0', 'iso.3.6.1.4.1.9.5.1.3.1.1.18.1']
            for oid in oids:
                proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
                                        stdout=subprocess.PIPE,shell=True)
                (out,err) = proc.communicate()
                if out:
                    return out.decode('utf-8').strip('STRING: ').strip(' \"\n')
            return 'unknown'
        except Exception as err_message:
            logger.error('{}: Error in function cisco.get_hw {}'.format(ip, str(err_message)))
            
    def get_fw(ip, community, logger):
        try:
            oids = ['iso.3.6.1.2.1.47.1.1.1.1.10.1',
                    'iso.3.6.1.2.1.47.1.1.1.1.9.1001',
                    'iso.3.6.1.2.1.47.1.1.1.1.9.2001',
                    'iso.3.6.1.4.1.9.5.1.3.1.1.19.1',
                    'iso.3.6.1.4.1.9.5.1.3.1.1.19.2',
                    'iso.3.6.1.4.1.9.5.1.3.1.1.20.1',
                    'iso.3.6.1.2.1.47.1.1.1.1.10.1001',
                    'iso.3.6.1.2.1.47.1.1.1.1.10.3',
                    'iso.3.6.1.2.1.47.1.1.1.1.10.2001',
                    'iso.3.6.1.4.1.9.5.1.3.1.1.20.2',
                    'iso.3.6.1.2.1.1.1.0']
            for oid in oids:
                proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
                                        stdout=subprocess.PIPE,shell=True)
                (out,err) = proc.communicate()
                if out:
                    fw = out.decode('utf-8').strip('STRING: ').strip(' \"\n')
                    if 'Version' in fw:
                        fw = re.search('Version (\S+),', fw).group(1)
                    if fw: return fw
            return 'unknown'
        except Exception as err_message:
            logger.error('{}: Error in function cisco.get_fw {}'.format(ip, str(err_message)))
    
    def get_serial(ip, community, logger):
        try:
            oids = ['iso.3.6.1.2.1.47.1.1.1.1.11.1', 
                    'iso.3.6.1.2.1.47.1.1.1.1.11.1001', 
                    'iso.3.6.1.4.1.9.6.1.101.53.14.1.5.1', 
                    'iso.3.6.1.2.1.47.1.1.1.1.11.2001']
            for oid in oids:
                proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
                                        stdout=subprocess.PIPE,shell=True)
                (out,err) = proc.communicate()
                if out:
                    serial = out.decode('utf-8').strip('STRING: ').strip(' \"\n')
                    if serial: return serial
            return None
        except Exception as err_message:
            logger.error('{}: Error in function cisco.get_serial {}'.format(ip, str(err_message)))
        
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
            logger.error('{}: Error in function cisco.get_hostname {}'.format(ip, str(err_message)))
            
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
            logger.error('{}: Error in function cisco.get_location {}'.format(ip, str(err_message)))
    
    def get_mac(ip, community, logger):
        try:
            oid = 'iso.3.6.1.2.1.2.2.1.6'
            proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
                                    stdout=subprocess.PIPE,shell=True)
            (out,err) = proc.communicate()
            if out:
                mac = re.match('^Hex-STRING:.+\nHex-STRING: (.+) \n' ,out.decode('utf-8'))
                if mac:
                    mac = mac.group(1).replace(' ', '')
                if mac and re.match('^[0-9A-F]{12}$', mac): return mac
            return 'unknown'
        except Exception as err_message:
            logger.error('{}: Error in function cisco.get_mac {}'.format(ip, str(err_message)))
        
    def login(ip, logger):
        try:
            conf = {
                'device_type': 'cisco_ios',
                'host': ip,
                'username': config.ssh_tacacs_username,
                'password': config.ssh_tacacs_password,
                'port' : 22,
                'secret': config.enable_pass,
                'global_delay_factor': 3
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
            net_connect = cisco.login(ip, logger)
            if not net_connect:
                logger.warning(ip+' failed to connect')
                return False
            
            save = net_connect.save_config(cmd='copy running-config startup-config', 
                                        confirm=True, confirm_response='\n')
            result = net_connect.read_channel()
            net_connect.disconnect()
            if 'OK' in result:
                return True
            else:
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
            net_connect = cisco.login(ip, logger)
            if not net_connect:
                logger.warning(ip+' failed to connect')
                return False
            
            filename = hostname+'_'+ip+'.cfg'
            command = 'copy running-config tftp://'+config.backup_srv_internal+'/'+filename
            addr_conf = net_connect.send_command(command, expect_string='Address or name')
            dest_conf = net_connect.send_command('\n', expect_string='Destination filename')
            copy = net_connect.send_command('\n', expect_string='#')
            time.sleep(3)
            net_connect.disconnect()
            if not 'copied' in copy:
                logger.warning(ip+' copy to tftp failed')
                return False
            
            if os.path.exists('/srv/tftp/'+filename):
                if '\nend' not in open('/srv/tftp/'+filename).read():
                    logger.warning(ip+' file is broken')
                    return False
                with open('/srv/tftp/'+filename, "r") as input:
                    with open(config.storage_last+filename, "w") as output: 
                        for line in input:
                            if not "ntp clock-period" in line:
                                output.write(line)
                shutil.copy(config.storage_last+filename, 
                            config.storage_daily+strftime("%A", gmtime()))
                shutil.copy(config.storage_last+filename, 
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