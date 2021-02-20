# -*- coding: utf-8 -*-
#!/usr/local/bin/Python37/Inventory/env/bin/
#Python 3.7.3

import config
import os, os.path, time, shutil, subprocess, re
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from time import gmtime, strftime

class cisco_spa:
    def vendor():
        return 'Cisco'
    
    def get_stuff(ip, community, logger):
        stuff = cisco_spa.get_serial(ip, community, logger)
        if stuff:
            return {'serial': stuff['serial'],
                    'firmware': stuff['firmware'],
                    #'model': stuff['model'],
                    'hardware': stuff['hardware'],
                    'hostname': cisco_spa.get_hostname(ip, community, logger),
                    'location': cisco_spa.get_location(ip, community, logger),
                    'mac': cisco_spa.get_mac(ip, community, logger)
                }
        return None
               
    def get_model(ip, community, logger):
        try:
            oid = '1.3.6.1.2.1.47.1.1.1.1.7.1'
            proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
                                    stdout=subprocess.PIPE,shell=True)
            (out,err) = proc.communicate()
            if out:
                return out.decode('utf-8').strip('STRING: ').strip(' \"\n')
            else:
                return None
        except Exception as err_message:
            logger.error('{}: Error in function cisco_spa.get_model {}'.format(ip, str(err_message)))
    
    def get_serial(ip, community, logger):
        try:
            url = "\"http://"+ip+"/login.cgi\""
            user = "admin"
            passw = "d5e4dde90374956631e2ced4b1c84c37  -"
            action = "\"submit_button=login&keep_name=0&enc=1&user="+user+"&pwd="+passw+"\""
            curl = "curl --silent --connect-timeout 5 --data "+action+" "+url
            crl, err = subprocess.Popen(curl ,stdout=subprocess.PIPE, shell=True).communicate()
            curl2 = "curl --silent --connect-timeout 10 http://"+ip+"/admin/config.xml"
            crl2, err = subprocess.Popen(curl2, stdout=subprocess.PIPE, shell=True).communicate()

            stuff_regex = '<System_Model_Number>(?P<model>.+)</System_Model_Number>.+'
            stuff_regex += '<Firmware_Version>(?P<firmware>.+)</Firmware_Version>.+'
            stuff_regex += '<Version_ID>(?P<hardware>.+)</Version_ID>.+'
            stuff_regex += '<Serial_Number>(?P<serial>.+)</Serial_Number>'
            stuff = re.search(stuff_regex, crl2.decode('utf-8'), re.DOTALL)
            
            if stuff:
                return stuff.groupdict()
                #return stuff.groupdict()
            unauth = re.search('<title>Login Page</title>', crl.decode('utf-8'), re.DOTALL)
            if unauth:
                return 'AuthFailed'
            else:
                return None
        except Exception as e:
            logger.error(ip+" get_stuff_1xx error "+str(e))
    
    def get_serial_1xx_chrome(ip, community, logger):
        try:
            driver = invoke_driver(logger)
            driver.get("http://"+ip)
            time.sleep(2)
            pass_field = driver.find_element_by_xpath('/html/body/form/div/table/tbody/tr[3]/td[3]/table/tbody/tr[3]/td[2]/input')
            pass_field.send_keys('avan123tel!')
            login_button = driver.find_element_by_xpath('/html/body/form/div/table/tbody/tr[3]/td[3]/table/tbody/tr[4]/td[2]/input')
            login_button.click()
            time.sleep(2)
            st = driver.find_element_by_xpath('//*[@id="trt_Status_Router.asp"]')
            st.click()
            time.sleep(2)
            sn_xpath = '/html/body/form/div/table/tbody/tr[3]/td/table/tbody/tr/td[3]/div/table/tbody/tr[2]/td/table/tbody/tr[11]/td[2]'
            sn =  driver.find_element_by_xpath(sn_xpath)
            serial = sn.text
            driver.close()
            return serial
        except Exception as e:
            logger.error(ip+" get_serial1xx error "+str(e))
            
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
            logger.error('{}: Error in function cisco_spa.get_hostname {}'.format(ip, str(err_message)))
            
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
            logger.error('{}: Error in function cisco_spa.get_location {}'.format(ip, str(err_message)))
    
    def get_mac(ip, community, logger):
        try:
            oid = 'iso.3.6.1.2.1.2.2.1.6.2'
            proc = subprocess.Popen("snmpwalk -Ov -t 2 -v1 -c {} {} {}".format(community, ip, oid),
                                    stdout=subprocess.PIPE,shell=True)
            (out,err) = proc.communicate()
            if out:
                mac = out.decode('utf-8').strip('Hex-STRING: ').strip(' \"\n').replace(' ', '')
                if mac and re.match('^[0-9A-F]{12}$', mac): return mac
            return 'unknown'
        except Exception as err_message:
            logger.error('{}: Error in function cisco_spa.get_mac {}'.format(ip, str(err_message)))
            
    def get_stuff8000(ip, logger):
        try:
            curl = "curl --silent -L --anyauth -u "+config.voip_username+":"+config.voip_password+" --connect-timeout 5 --max-time 10 http://"+ip+"/"
            crl, err = subprocess.Popen(curl, stdout=subprocess.PIPE,shell=True).communicate()

            stuff = re.search('Product Name:.*<td><.+>(?P<model>.+)</font><.+>Serial Number:.*<td><.+>(?P<serial>.+)</font>\n<.+><.+>Software Version:.*<td><.+>(?P<firmware>.+)</font><.+>Hardware Version:.*<td><.+>(?P<hardware>.+)</font>\n<.+><.+>MAC Address:.*<td><.+>(?P<mac>.+)</font><.+>Client Certificate',crl.decode('cp437'))
            if stuff:
                stuff_dict = stuff.groupdict()
                stuff_dict['hostname'] = 'unknown'
                stuff_dict['location'] = 'unknown'
                return stuff_dict
            unauth = re.search('Cisco SPA Configuration.+401 Unauthorized', crl.decode('cp437'), re.DOTALL)
            if unauth:
                return 'AuthFailed'
            else:
                return None
        except Exception as e:
            logger.error(ip+" get_stuff8000 error "+str(e))
            
    def invoke_driver(logger):
        try:
            chrome_path = '/usr/bin/google-chrome'
            chromedriver_path = '/usr/local/bin/Python37/Avantel_ConfigBackup/chromedriver'
            window_size = "640,480"
            
            chrome_options = Options()  
            chrome_options.add_argument("--headless")  
            chrome_options.add_argument("--window-size=%s" % window_size)
            chrome_options.add_argument('--no-sandbox')
            chrome_options.binary_location = chrome_path
            
            driver = webdriver.Chrome(executable_path=chromedriver_path, chrome_options=chrome_options)  
            time.sleep(10)
            return driver
    
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