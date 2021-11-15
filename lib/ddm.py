import config
import subprocess, logging
from lib.zabbix_common import zabbix_common
from lib.snmp_common import snmp_common
from concurrent.futures import ThreadPoolExecutor, as_completed

class ddm:
            
    def port_desc(ip, port, comm, logger):
        try:
            cm = f"/bin/snmpwalk -t 2 -v1 -c {comm} {ip} iso.3.6.1.2.1.31.1.1.1.18.{port}"
            proc = subprocess.Popen(cm, stdout=subprocess.PIPE,shell=True)
            (out,err) = proc.communicate()
            #logger.warning(out.decode('utf-8'))
            if 'STRING' in out.decode('utf-8'):
                return out.decode('utf-8').split(' = STRING: ')[1].strip('\n').strip('"')
            return 'None'
        except Exception as err_message:
            logger.error('{}: Ошибка в функции ddm.port_desc {}'.format(ip, str(err_message)))
        
    def snr_ddm(ip, hname, alarm_dict, logger):
        try:
            soi, comm = snmp_common.getSysObjectID(ip, logger)
            if soi and '40418' in soi:
                #logger.warning('TEMP found SNR! '+ip)
                oid = 'iso.3.6.1.4.1.40418.7.100.30.1.1.17'
                cm = f"/bin/snmpwalk -t 2 -v1 -c {comm} {ip} {oid}"
                proc = subprocess.Popen(cm, stdout=subprocess.PIPE,shell=True)
                (out,err) = proc.communicate()
                for line in out.decode('utf-8').split(oid+'.'):
                    if not line or '(' not in line: 
                        continue
                    #logger.warning('TEMP found ERR! '+line)
                    port = line.split(' = STRING: ')[0]
                    desc = ddm.port_desc(ip, port, comm, logger)
                    rx = line.replace(port+' = STRING: ', '').strip('\n').strip('"')
                    alarm_dict[hname+' port {}'.format(port)] = {'desc': desc, 
                                                                'rx': rx,
                                                                'hname': hname,
                                                                'port': port}
        except Exception as err_message:
            logger.error('{}: Ошибка в функции ddm.snr_ddm {}'.format(ip, str(err_message)))
            
    def get_alarms(logger):
        try:
            hosts = zabbix_common.get_hosts(logger)
            interfaces = zabbix_common.get_interfaces(logger) 
            host_dict = {}
            
            for host in hosts:
                ip = zabbix_common.get_interface(host['hostid'], logger, interfaces)
                if '10.60.' in ip or '188.68.187.' in ip or '10.61.' in ip:
                    host_dict[host['host']] = {'ip': ip}
                                
            alarm_dict = {}
            with ThreadPoolExecutor(max_workers=100) as executor:
                [executor.submit(ddm.snr_ddm,
                                 host_dict[hname]['ip'],
                                 hname,
                                 alarm_dict,
                                 logger) for hname in host_dict]
            
            #logger.warning('TEMP found alarm_dict! '+str(alarm_dict))
            return alarm_dict
                
        except Exception as err_message:
            logger.error('Ошибка в функции ddm.ddm: {}'.format(str(err_message)))