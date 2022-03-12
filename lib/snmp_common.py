import config, subprocess

class snmp_common:
    def generic_request(ip, oid, logger, omit_oid=False):
        try:
            if omit_oid: ov = '-Ov'
            else: ov = ''
            for community in config.snmp_comm_ro:
                swalk = "/bin/snmpwalk {} -t 4 -v1 -c {} {} {}".format(ov, community, ip, oid)
                proc = subprocess.Popen(
                    swalk,
                    stdout=subprocess.PIPE,shell=True)
                (out,err) = proc.communicate()
                if out:
                    return out.decode('utf-8'), community
            return None
        except Exception as err_message:
            logger.error('{}: Ошибка в функции request {}'.format(ip, str(err_message)))
        
    def get_sysobjectid(ip, logger):
        try:
            for community in config.snmp_comm_ro:
                swalk = "/bin/snmpwalk -Ov -t 2 -v1 -c {} {} 1.3.6.1.2.1.1.2"
                proc = subprocess.Popen(swalk.format(community, ip),
                                        stdout=subprocess.PIPE,shell=True)
                (out,err) = proc.communicate()
                if out:
                    return out.decode('utf-8').strip('OID: ').strip('\n'), community
            return None, None
        except Exception as err_message:
            logger.error('{}: Ошибка в функции getSysObjectID {}'.format(ip, str(err_message)))