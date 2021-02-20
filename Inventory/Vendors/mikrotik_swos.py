import config
import os, os.path, time, shutil, subprocess, re
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from time import gmtime, strftime

class mikrotik_swos:
    def vendor():
        return 'Mikrotik'
    
    def get_stuff(ip, community, logger):
        return {'serial': mikrotik_swos.get_serial(ip, community, logger),
                'hardware': mikrotik_swos.get_hw(ip, community, logger),
                'firmware': mikrotik_swos.get_fw(ip, community, logger),
                'hostname': mikrotik_swos.get_hostname(ip, community, logger),
                'location': mikrotik_swos.get_location(ip, community, logger),
                'mac': mikrotik_swos.get_mac(ip, community, logger)}
    
    def get_serial(ip, community, logger):
        try:
            oid = 'iso.3.6.1.2.1.1.4.0'  #SysContact! This is crutches!
            proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
                                    stdout=subprocess.PIPE,shell=True)
            (out,err) = proc.communicate()
            if out:
                serial = out.decode('utf-8').strip('STRING: ').strip(' \"\n')
                if re.match('^[A-Z0-9]{12}$', serial):
                    return serial
            return None
        except Exception as err_message:
            logger.error('{}: Error in function getSysObjectID {}'.format(ip, str(err_message)))
            
    def get_hw(ip, community, logger):
        try:
            oid = '1.3.6.1.2.1.1.1.0'
            proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
                                    stdout=subprocess.PIPE,shell=True)
            (out,err) = proc.communicate()
            if out:
                soft = out.decode('utf-8').strip('STRING: ').strip(' \"\n')
                return re.search('(.+)\sSwOS' ,soft).group(1)
            else:
                return None
        except Exception as err_message:
            logger.error('{}: Error in function mikrotik_swos.get_hw {}'.format(ip, str(err_message)))
            
    def get_fw(ip, community, logger):
        try:
            oid = '1.3.6.1.2.1.1.1.0'
            proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
                                    stdout=subprocess.PIPE,shell=True)
            (out,err) = proc.communicate()
            if out:
                soft = out.decode('utf-8').strip('STRING: ').strip(' \"\n')
                return re.search('SwOS\s(.+)' ,soft).group(1)
            else:
                return None
        except Exception as err_message:
            logger.error('{}: Error in function mikrotik_swos.get_fw {}'.format(ip, str(err_message)))
            
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
            logger.error('{}: Error in function mikrotik_swos.get_hostname {}'.format(ip, str(err_message)))
            
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
            logger.error('{}: Error in function mikrotik_swos.get_location {}'.format(ip, str(err_message)))
            
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
            logger.error('{}: Error in function mikrotik_swos.get_mac {}'.format(ip, str(err_message)))
            
    def invoke_driver(logger):
        try:
            chrome_path = '/usr/bin/google-chrome'
            chromedriver_path = '/usr/local/bin/Python37/Avantel_ConfigBackup/chromedriver'
            window_size = "1920,1080"
            
            chrome_options = Options()  
            chrome_options.add_argument("--headless")  
            chrome_options.add_argument("--window-size=%s" % window_size)
            chrome_options.add_argument('--no-sandbox')
            chrome_options.binary_location = chrome_path
            
            driver = webdriver.Chrome(executable_path=chromedriver_path, chrome_options=chrome_options)  
            time.sleep(10)
            return driver
    
        except Exception as e:
            logger.error(ip+" OTHER EXCEPTION "+str(e))
            
    def get_scrs(driver, ip, hostname, logger):
        try:
            foldername = hostname+'_'+ip
            link_with_login = "http://"+config.local_username+':'+config.local_password+'@'+ip
            path_last = config.storage_last+foldername
            path_daily = config.storage_daily+strftime("%A", gmtime())+'/'+foldername
            path_monthly = config.storage_monthly+strftime("%B", gmtime())+'/'+foldername
    
            if not os.path.exists(path_last):
                os.mkdir(path_last)
            if not os.path.exists(path_daily):
                os.mkdir(path_daily)
            if not os.path.exists(path_monthly):
                os.mkdir(path_monthly)
                
            links_arr = ['link', 'forwarding', 'vlan', 'vlans', 'snmp', 'acl', 'system']
            for page in links_arr:
                driver.get(link_with_login+"/index.html#"+page)
                time.sleep(2)
                content = driver.find_element_by_xpath("//*[@id='content']/table")
                content.screenshot(path_last+'/'+page+'.png')
                if os.path.exists(path_last+'/'+page+'.png'):
                    shutil.copy(path_last+'/'+page+'.png', path_daily)
                    shutil.copy(path_last+'/'+page+'.png', path_monthly)
                else:
                    logger.info('Failed scr copy: Mikrotik RB260 '+ip+' '+hostname+' '+page)
            logger.info('Succesful scr copy: Mikrotik RB260 '+ip+' '+hostname)
        except Exception as e:
            logger.error(ip+" OTHER EXCEPTION "+str(e))
            
    def get_cfg(ip, hostname, logger):
        try:
            fname = hostname+'_'+ip

            path_last = config.storage_last+fname
            path_daily = config.storage_daily+strftime("%A", gmtime())+'/'+fname
            path_monthly = config.storage_monthly+strftime("%B", gmtime())+'/'+fname
            
            if not os.path.exists(path_last):
                os.mkdir(path_last)
            if not os.path.exists(path_daily):
                os.mkdir(path_daily)
            if not os.path.exists(path_monthly):
                os.mkdir(path_monthly)
                
            credentials = config.local_username+':'+config.local_password
            subprocess.Popen("curl --silent --anyauth -u "+credentials+" http://"+ip+
                             "/backup.swb -o "+path_last+"/"+fname+".swb", 
                             stdout=subprocess.PIPE,shell=True)
            time.sleep(5)
            timeout = time.time() + 30
            while not os.path.exists(path_last+"/"+fname+".swb"):
                if time.time() < timeout:
                    time.sleep(3)
                else:
                    logger.info('Failed copy: Mikrotik RB260 '+ip+' '+hostname)
                    break
            else:
                if 'pwd:' not in open(path_last+"/"+fname+".swb").read():
                    logger.info('Failed copy(damaged file): Mikrotik RB260 '+ip+' '+hostname)
                else:
                    shutil.copy(path_last+'/'+fname+'.swb', path_daily)
                    shutil.copy(path_last+'/'+fname+'.swb', path_monthly)
                    logger.info('Succesful cfg copy: Mikrotik RB260 '+ip+' '+hostname)
        except Exception as e:
            logger.error(ip+" invoke_driver error "+str(e))

    # Этот костыль нужен чтобы не запускать для каждого микрота отдельный браузер.
    def get_scrs_many(ip_dict, logger):
        driver = Mk_rb260.invoke_driver(logger)
        for ip in ip_dict:
            if ip_dict[ip]['model'] == 'Mikrotik RB260':
                Mk_rb260.get_scrs(driver, ip, ip_dict[ip]['hostname'], logger)
                Mk_rb260.get_cfg(ip, ip_dict[ip]['hostname'], logger)
        driver.close()