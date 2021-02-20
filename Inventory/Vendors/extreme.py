# -*- coding: utf-8 -*-
#!/usr/local/bin/Python37/Avantel_ConfigBackup/env/bin/
#Python 3.7.3

import config, logging, time, os, os.path, shutil, paramiko, subprocess, re
from netmiko import ConnectHandler, NetmikoTimeoutException
from time import gmtime, strftime

class extreme:
    def vendor():
        return 'Extreme'
    
    def get_stuff(ip, community, logger):
        return {'serial': extreme.get_serial(ip, community, logger),
                'hardware': extreme.get_hw(ip, community, logger),
                'firmware': extreme.get_fw(ip, community, logger),
                'hostname': extreme.get_hostname(ip, community, logger),
                'location': extreme.get_location(ip, community, logger),
                'mac': extreme.get_mac(ip, community, logger)}
        
    def get_hw(ip, community, logger):
        try:
            oids = ['iso.3.6.1.2.1.47.1.1.1.1.8.1']
            for oid in oids:
                proc = subprocess.Popen("snmpwalk -Ov -t 4 -v1 -c {} {} {}".format(community, ip, oid),
                                        stdout=subprocess.PIPE,shell=True)
                (out,err) = proc.communicate()
                if out:
                    return out.decode('utf-8').strip('STRING: ').strip(' \"\n')
            return None
        except Exception as err_message:
            logger.error('{}: Error in function extreme.get_hw {}'.format(ip, str(err_message)))
    
    def get_fw(ip, community, logger):
        try:
            oids = ['iso.3.6.1.2.1.47.1.1.1.1.10.1', 'iso.3.6.1.2.1.16.19.2.0']
            for oid in oids:
                proc = subprocess.Popen("snmpwalk -Ov -t 4 -v1 -c {} {} {}".format(community, ip, oid),
                                        stdout=subprocess.PIPE,shell=True)
                (out,err) = proc.communicate()
                if out:
                    return out.decode('utf-8').strip('STRING: ').strip(' \"\n')
            return None
        except Exception as err_message:
            logger.error('{}: Error in function extreme.get_fw {}'.format(ip, str(err_message)))
    
    def get_serial(ip, community, logger):
        try:
            oid = 'iso.3.6.1.2.1.47.1.1.1.1.11.1'
            proc = subprocess.Popen("snmpwalk -Ov -t 4 -v1 -c {} {} {}".format(community, ip, oid),
                                    stdout=subprocess.PIPE,shell=True)
            (out,err) = proc.communicate()
            if out:
                return out.decode('utf-8').strip('STRING: ').strip(' \"\n')
                #snmpModel(out.decode('utf-8').strip('OID: ').strip('\n'), ip)
            else:
                return None
        except Exception as err_message:
            logger.error('{}: Error in function extreme.get_serial {}'.format(ip, str(err_message)))
    
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
            logger.error('{}: Error in function extreme.get_hostname {}'.format(ip, str(err_message)))
            
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
            logger.error('{}: Error in function extreme.get_location {}'.format(ip, str(err_message)))
    
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
            logger.error('{}: Error in function extreme.get_mac {}'.format(ip, str(err_message)))
    
    def login(ip, logger):
        try:
            conf = {
                'device_type': 'extreme',
                'host': ip,
                'username': config.ssh_tacacs_username,
                'password': config.ssh_tacacs_password,
                'port' : 22,
                'global_delay_factor': 7
            }
    
            net_connect = ConnectHandler(**conf)
            time.sleep(2)
            return net_connect
            
        except NetmikoTimeoutException:
            logger.warning(ip+' SSH timeout')
            return False
        except Exception as err:
            logger.error(ip+' login error: '+str(err))
            return False
            
    def save_config(ip, logger):
        try:
            net_connect = extreme.login(ip, logger)
            if not net_connect:
                logger.warning(ip+' failed to connect')
                return False
            
            save = net_connect.save_config(cmd='save', confirm=True)
            net_connect.disconnect()
            if 'successfully' in save:
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
            net_connect = extreme.login(ip, logger)
            if not net_connect:
                logger.warning(ip+' failed to connect')
                return False
            
            filename = hostname+'_'+ip+'.cfg'
            command = 'upload configuration '+config.backup_srv_internal+' '+filename+' vr "VR-Default"'
            copy = net_connect.send_command(command, expect_string='#')
            time.sleep(3)
            net_connect.disconnect()
            if not 'done' in copy:
                logger.warning(ip+' copy to tftp failed')
                return False
            
            if os.path.exists('/srv/tftp/'+filename):
                if 'Module vsm configuration' not in open('/srv/tftp/'+filename).read():
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