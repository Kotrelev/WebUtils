import ipaddress, urllib

class inventory_mysql:
    states = {0: '<font color="#ff0000">Suspended</font>', 
              1: '<font color="#009900">Active</font>'}
    def get_dynamic_month(connection, model, logger):
        # уникальная модель с макс датой за последний год
        try:
            req = ('SELECT DISTINCT '
            ' FIRST_VALUE(date) OVER (PARTITION BY model, MONTH(date), YEAR(date) ORDER BY date desc ) as date,'
            ' FIRST_VALUE(quantity) OVER (PARTITION BY model, MONTH(date), YEAR(date) ORDER BY date desc ) as quantity'
            ' FROM InventoryDynamic WHERE model = \"{}\" and date > DATE_SUB(NOW(),INTERVAL 1 YEAR);'.format(model))
            with connection.cursor() as cursor:
                cursor.execute(req)
                dynamic = cursor.fetchall()
            return dynamic
        except Exception as err_message:
            logger.error('Ошибка в функции sql_dynamic_month {}'.format(str(err_message)))
            
    
    def get_dynamic_models(connection, logger):
        # уникальные модели
        try:
            req = ('select type, vendor, model from InventoryDynamic GROUP BY model;')
            with connection.cursor() as cursor:
                cursor.execute(req)
                dynamic = cursor.fetchall()
            return dynamic
        except Exception as err_message:
            logger.error('Ошибка в функции sql_dynamic_models {}'.format(str(err_message)))
    
    
    def get_serial(connection, serial, logger):
        # берем серийник, возвращаем запись из Inventory, последнюю запись из Vars и все записи из Inventory+Vars
        try:
            req_inv = ('select * from Inventory where serial = \'{}\';'.format(serial))
            req_vars = ('select * from InventoryVars where date=(select MAX(date) '
                        'from InventoryVars where serial = \'{}\') and serial = \'{}\';'.format(serial, serial))
            # Есть идея выдавать инвентарные данные и последние переменные одной строкой.
            #req = ('SELECT * FROM Inventory, InventoryVars'
            #       ' WHERE Inventory.serial = InventoryVars.serial'
            #       ' and date=(select MAX(date) from InventoryVars where InventoryVars.serial = \'{}\')'
            #       ' and Inventory.serial = \'{}\';'.format(serial, serial))
            
            #req3 = ('select * from InventoryVars where serial = \'{}\';'.format(serial))
            req_history = ('SELECT * FROM Inventory, InventoryVars'
                   ' WHERE Inventory.serial = InventoryVars.serial'
                   ' and Inventory.serial = \'{}\';'.format(serial))
            cursor = connection.cursor()
            cursor.execute(req_inv)
            inventory = cursor.fetchall()
            if not inventory:
                cursor.close()
                return None, None, None
            # tuple to list и заодно уберем лишний индекс
            inventory = list(inventory[0])
            # подменяем код состояния текстом.
            inventory[6] = inventory_mysql.states[inventory[6]]
            cursor.execute(req_vars)
            inventory_vars = cursor.fetchall()
            cursor.execute(req_history)
            inventory_vars_history = cursor.fetchall()
            # tuple >> list
            inventory_vars_history = [list(line) for line in inventory_vars_history]
            # подменяем коды состояний текстом
            for x in range(len(inventory_vars_history)):
                inventory_vars_history[x][6] = inventory_mysql.states[inventory_vars_history[x][6]]
            cursor.close()
            return inventory, inventory_vars[0], inventory_vars_history
        except Exception as err_message:
            logger.error('Ошибка в функции sql_inventory_serial: {}'.format(str(err_message)))
            
    
    
    def get_ipname(connection, ipname, logger):
        # берем имя/IP, возвращаем запись из Inventory, последнюю запись из Vars и все записи из Inventory+Vars
        try:
            ipaddress.ip_address(ipname)
        # не нашли ип, видимо это имя. Имя ищем через "like" чтобы можно было искать по части имени
        except:
            vars_req = ('select * from InventoryVars '
                        ' where date=(select MAX(date) from InventoryVars where name like "%{}%")'
                        ' and name like "%{}%";'.format(ipname, ipname))
            # тут берем самые новые записи для уникальных серийных по указанному имени
            hist_req = ('SELECT * FROM Inventory, InventoryVars'
                        ' WHERE Inventory.serial = InventoryVars.serial'
                        ' and date=(select MAX(date) from InventoryVars where InventoryVars.serial = Inventory.serial)'
                        ' and InventoryVars.name like "%{}%";'.format(ipname))
        # нашли ип
        else:
            vars_req = ('select * from InventoryVars '
                        ' where date=(select MAX(date) from InventoryVars where ip = "{}")'
                        ' and ip = "{}";'.format(ipname, ipname))
            # тут берем самые новые записи для уникальных серийных по указанному ip
            hist_req = ('SELECT * FROM Inventory, InventoryVars'
                        ' WHERE Inventory.serial = InventoryVars.serial'
                        ' and date=(select MAX(date) from InventoryVars where InventoryVars.serial = Inventory.serial)'
                        ' and InventoryVars.ip = "{}";'.format(ipname))
        try:
            cursor = connection.cursor()
            cursor.execute(vars_req)
            last_vars = cursor.fetchall()
            if not last_vars:
                cursor.close()
                return None, None, None
            # для самого нового девайса в vars запросим инфу из Inventory
            inv_req = ('select * from Inventory where serial = "{}";'.format(last_vars[0][0]))
            cursor.execute(inv_req)
            inventory = cursor.fetchall()
            inventory = list(inventory[0])
            inventory[6] = inventory_mysql.states[inventory[6]]
            cursor.execute(hist_req)
            inventory_vars_history = cursor.fetchall()
            inventory_vars_history = [list(line) for line in inventory_vars_history]
            for x in range(len(inventory_vars_history)):
                url = 'https://devnet.spb.avantel.ru/inventory_serial_{}'.format(
                                    urllib.parse.quote(inventory_vars_history[x][0].replace('/','slash'), safe=''))
                model_url = '<a href={}>{}</a>'.format(url, inventory_vars_history[x][0])
                inventory_vars_history[x][0] = model_url
                inventory_vars_history[x][6] = inventory_mysql.states[inventory_vars_history[x][6]]
            cursor.close()
            return inventory, last_vars[0], inventory_vars_history
        except Exception as err_message:
            logger.error('Ошибка в функции sql_inventory_ipname: {}'.format(str(err_message)))
            
    def get_many_ip(connection, ip, logger):
        # уникальные серийники с макс. датой по ip
        try:
            many_ip_arr = []
            # уникальные серийники с макс. датой по ip
            req = ('SELECT DISTINCT'
                   ' serial,'
                   ' FIRST_VALUE(date) OVER (PARTITION BY ip, MONTH(date), YEAR(date) ORDER BY date desc ) as date'
                   ' FROM InventoryVars where ip = \'{}\';'.format(ip))
            with connection.cursor() as cursor:
                cursor.execute(req)
                serials = cursor.fetchall()
                for serial in serials:
                    # собираем в одну строку данные из инвентори и варс
                    req2 = ('SELECT * FROM Inventory, InventoryVars '
                            ' WHERE Inventory.serial = InventoryVars.serial'
                            ' and date=(select MAX(date) from InventoryVars where InventoryVars.serial = \"{}\")'
                            ' and Inventory.serial = \"{}\";'.format(serial[0], serial[0])
                            )
                    cursor.execute(req2)
                    data = cursor.fetchall()
                    many_ip_arr.append(data[0])
            return many_ip_arr
        except Exception as err_message:
            logger.error('Ошибка в функции sql_many_ip {}'.format(str(err_message)))
        
    def get_vmt(connection, req, vmt, logger):
        # inventory + vars по типу/вендору/модели
        try:
            dev_req = ('SELECT * FROM Inventory, InventoryVars'
                ' WHERE Inventory.serial = InventoryVars.serial'
                ' and date=(select MAX(date) from InventoryVars where InventoryVars.serial = Inventory.serial)'
                ' and Inventory.{} = "{}";'.format(vmt, req))
            cursor = connection.cursor()
            cursor.execute(dev_req)
            dev_arr = cursor.fetchall()
            if not dev_arr:
                cursor.close()
                return None
            dev_arr = [list(line) for line in dev_arr]
            for x in range(len(dev_arr)):
                url = 'https://devnet.spb.avantel.ru/inventory_serial_{}'.format(
                                            urllib.parse.quote(dev_arr[x][0].replace('/','slash'), safe=''))
                model_url = '<a href={}>{}</a>'.format(url, dev_arr[x][0])
                
                dev_arr[x][0] = model_url
                dev_arr[x][6] = inventory_mysql.states[dev_arr[x][6]]
            cursor.close()
            return dev_arr
        except Exception as err_message:
            logger.error('Ошибка в функции sql_inventory_vmt: {}'.format(str(err_message)))
            
    
    def get_suspended(connection, logger):
        # inventory suspended
        try:
            dev_req = ('SELECT * FROM Inventory WHERE monitored = "0";')
            cursor = connection.cursor()
            cursor.execute(dev_req)
            dev_arr = cursor.fetchall()
            if not dev_arr:
                cursor.close()
                return None
            dev_arr = [list(line) for line in dev_arr]
            for x in range(len(dev_arr)):
                url = 'https://devnet.spb.avantel.ru/inventory_serial_{}'.format(
                                            urllib.parse.quote(dev_arr[x][0].replace('/','slash'), safe=''))
                model_url = '<a href={}>{}</a>'.format(url, dev_arr[x][0])
                
                dev_arr[x][0] = model_url
                dev_arr[x][6] = inventory_mysql.states[dev_arr[x][6]]
            cursor.close()
            return dev_arr
        except Exception as err_message:
            logger.error('Ошибка в функции sql_inventory_suspended: {}'.format(str(err_message)))