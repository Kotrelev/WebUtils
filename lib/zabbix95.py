from lib.common import mysql
from lib.common import zabbix_common

class zabbix95:
    def get_ifaces(logger):
        try:
            connection = mysql.local_sql_conn()
            req = ("select * from Zabbix95")
            with connection.cursor() as cursor:
                cursor.execute(req)
                zabbix95 = cursor.fetchall()
            connection.close()
            
            # преобразуем список словарей из базы в словарь
            zabbix95_ifaces = {p['peer']: {n['node']: {i['interface']: i['id']
                for i in zabbix95 if i['peer'] == p['peer'] and i['node'] == n['node']} 
                for n in zabbix95 if n['peer'] == p['peer']} for p in zabbix95}
                
            return zabbix95_ifaces
    
        except Exception as err_message:
            logger.error('Ошибка в функции get_zabbix95_ifaces {}'.format(str(err_message)))
    
    def sql_del_iface(int_id):
        try:
            connection = mysql.local_sql_conn()
            req = ("delete from Zabbix95 where id = '{}'".format(int_id))
            with connection.cursor() as cursor:
                cursor.execute(req)
            connection.commit()
            connection.close()
        except Exception as err_message:
            logger.error('Ошибка в функции sql_del_iface_zabbix95 {}'.format(str(err_message)))
            
    def sql_add_iface(neighbour, node, interface, logger):
        try:
            connection = mysql.local_sql_conn()
            req = ("insert into Zabbix95(peer, node, interface)"
                   " values ('{}', '{}', '{}');".format(neighbour, node, interface))
            with connection.cursor() as cursor:
                cursor.execute(req)
            connection.commit()
            connection.close()
        except Exception as err_message:
            logger.error('Ошибка в функции sql_add_iface_zabbix95 {}'.format(str(err_message)))
            
    def validate_iface(neighbour, node, iface, logger):
        try:
            host_arr = zabbix_common.hostid_by_name(node, logger)
            host_id = ''
            if not host_arr:
                return None, 'Узел {} не найден в Zabbix'.format(node)
            for host in host_arr:
                if host['host'] == node or host['name'] == node:
                    host_id = host['hostid']
            if not host_id:
                return None, 'Узел {} не найден в Zabbix'.format(node)
                
            items = get_item(host_id, logger)
                                        
            iface_full = [re.search('Interface (.+\)):', x['name']).group(1) 
                        for x in items['result'] 
                        if any(y in x['name'] for y in [iface+'(', '('+iface+')']) 
                        and 'received' in x['name']]
            if len(iface_full) != 1:
                return None, 'Порт не найден на узле {}'.format(node)
                
            return iface_full[0], 'Порт добавлен'
                
        except Exception as err_message:
            logger.error('Ошибка в функции validate_zabbix95_iface {}'.format(str(err_message)))
            
    def validate_base(zabbix95_ifaces, logger):
        try:
            zabbix_conn = ZabbixAPI(config.zabbix_link,
                                    user=config.zabbix_user,
                                    password=config.zabbix_pass)
            
            validation_msg = ''
            nodes_set = {node for neigh in zabbix95_ifaces 
                         for node in zabbix95_ifaces[neigh]}
            nodes_dict = {x: [] for x in nodes_set}
            for node in nodes_set:
                host_arr = hostid_by_name(zabbix_conn, node, logger)
                host_id = ''
                if not host_arr:
                    validation_msg += 'Узел {} не найден в Zabbix<br>'.format(node)
                    continue
                for host in host_arr:
                    if host['host'] == node or host['name'] == node:
                        host_id = host['hostid']
                if not host_id:
                    validation_msg += 'Узел {} не найден в Zabbix<br>'.format(node)
                    continue
                
                items = zabbix_conn.do_request('item.get', {'hostids':[host_id],
                                               'output': ['itemid','name']})
                                               
                for nei in zabbix95_ifaces:
                    for host in zabbix95_ifaces[nei]:
                        if host != node:
                            continue
                        for iface in zabbix95_ifaces[nei][host]:
                            if any(iface in x['name'] for x in items['result']):
                                continue
                            validation_msg += 'Интерфейс не найден {} | {} | {}<br>'.format(nei, host, iface)
                                               
            zabbix_conn.user.logout()
                
            return validation_msg
                
        except Exception as err_message:
            logger.error('Ошибка в функции validate_zabbix95_base {}'.format(str(err_message)))
            
    def message_form(msg, values_tx, values_rx, values_all):
    
        if not values_tx or not values_rx:
            msg = msg + 'No data<br>'
            return msg
        msg = msg + str('Data elements (quantity): '+str(len(values_all))+'<br>')
        msg = msg + str('Max traffic tx: '+
                        str(round(sorted(values_tx)[-1]/1000000000, 3))+' Gbit<br>')
        msg = msg + str('Max traffic rx: '+
                        str(round(sorted(values_rx)[-1]/1000000000, 3))+' Gbit<br>')
        msg = msg + str('Max traffic all: '+
                        str(round(sorted(values_all)[-1]/1000000000, 3))+' Gbit<br>')
        # сортируем список значений (в битах)
        # обрезаем последние 0,5% списка (самые большие)
        # берем последнее значение и три раза делим на 1000 (лярд) чтобы получить Гбит
        tx95 = str('95Percentile tx: {} Gbit'.format(
            str(round(sorted(values_tx)[int(len(values_tx)*0.95)-1]/1000000000, 3))))
        msg = msg + tx95 + '<br>'
        rx95 = str('95Percentile rx: {} Gbit'.format(
            str(round(sorted(values_rx)[int(len(values_rx)*0.95)-1]/1000000000, 3))))
        msg = msg + rx95 + '<br>'
        msg = msg + str('95Percentile all: '+str(
                        round(sorted(values_all)[int(len(values_all)*0.95)-1]/1000000000, 3)
                        )+' Gbit<br>')
        return msg
           
    def create_report(zabbix95_ifaces, fromd, tilld, checked, logger):
        try:
            html_report = []
            zabbix_conn = ZabbixAPI(config.zabbix_link,
                                    user=config.zabbix_user,
                                    password=config.zabbix_pass)
            for neighbour in checked:
                # Генерячим словарик с таймкодами каждой минуты за прошедший месяц
                values_aggregated_tx = {m: 0 for m in range(fromd, tilld, 60)}
                values_aggregated_rx = {m: 0 for m in range(fromd, tilld, 60)}
                values_aggregated_all = {m: 0 for m in range(fromd, tilld, 60)}
                msg = '<h2>'+neighbour+'</h2><br>'
                for hostname in zabbix95_ifaces[neighbour]:
                    host_id = ''
                    host_arr = hostid_by_name(zabbix_conn, hostname, logger)
                    if not host_arr:
                        return 'Узел {} не найден в Zabbix'.format(hostname)
                    for host in host_arr:
                        if host['host'] == hostname or host['name'] == hostname:
                            host_id = host['hostid']
                    if not host_id:
                        return 'Узел {} не найден в Zabbix'.format(hostname)
    
                    msg = msg + '<b>' + hostname+'</b><br>'
                    for port in zabbix95_ifaces[neighbour][hostname]:
                        items = zabbix_conn.do_request('item.get', {'hostids':[host_id], 
                                                       'output': ['itemid','name'], 'search':{'name': port}})
                        if not items['result']:
                            return('Потерял порт '+neighbour+' | '+hostname+' | '+port)
                
                        for item in items['result']:
                            if 'sent' in item['name']:
                                tx_item = item
                            elif 'received' in item['name']:
                                rx_item = item
                        values_tx = []
                        values_rx = []
                        values_all = []
                        history_tx = zabbix_conn.history.get(itemids=tx_item['itemid'],time_from=fromd, time_till=tilld)
                        history_rx = zabbix_conn.history.get(itemids=rx_item['itemid'],time_from=fromd, time_till=tilld)
                        if not history_tx or not history_rx:
                            msg += 'Для {}: {} нет данных!<br>'.format(hostname, port)
    
                        # переделываем данные в словари. Ключ - таймкод. Сразу округляем до минут.
                        history_tx = {int(x['clock']) - (int(x['clock']) % 60): x for x in history_tx}
                        history_rx = {int(x['clock']) - (int(x['clock']) % 60): x for x in history_rx}
                        
                        # перетаскиваем данные в массивы и агрегируем их же в словари
                        for t in history_tx:
                            values_tx.append(int(history_tx[t]['value']))
                            values_aggregated_tx[t] += int(history_tx[t]['value'])
                            values_aggregated_all[t] += int(history_tx[t]['value'])
                        for r in history_rx:
                            values_rx.append(int(history_rx[r]['value']))
                            values_aggregated_rx[r] += int(history_rx[r]['value'])
                            values_aggregated_all[r] += int(history_rx[r]['value'])
                            
                        # добиваем недостающие данные нулями
                        data_len = len(values_aggregated_all)
                        for x in range(min(len(values_tx),len(values_rx))):
                            values_all.append(values_tx[x]+values_rx[x])
                        if len(values_tx) < data_len:
                            values_tx += [0 for x in range(data_len-len(values_tx))]
                        if len(values_rx) < data_len:
                            values_rx += [0 for x in range(data_len-len(values_rx))]
                        if len(values_all) < data_len:
                            values_all += [0 for x in range(data_len-len(values_all))]
                                        
                        msg = msg + '<b>'+port+'</b><br>'
                        # Если у нейбора больше одного порта, выплевываем промежуточный итог
                        if (len(zabbix95_ifaces[neighbour]) > 1 or
                            len(zabbix95_ifaces[neighbour][hostname]) > 1):
                            msg = msg + str(tx_item['name'])+'<br>'
                            msg = msg + str(rx_item['name'])+'<br>'
                            msg = message_form(msg, values_tx, values_rx, values_all)
                            
                if (len(zabbix95_ifaces[neighbour]) > 1 or
                    any(len(zabbix95_ifaces[neighbour][hn]) > 1 
                        for hn in zabbix95_ifaces[neighbour])):
                    msg = msg + '<br><b>Aggregated:</b><br>'
                # Конвертим дикты в списки, таймкоды больше не нужны
                values_tx = [values_aggregated_tx[tcode] for tcode in values_aggregated_tx]
                values_rx = [values_aggregated_rx[tcode] for tcode in values_aggregated_rx]
                values_all = [values_aggregated_all[tcode] for tcode in values_aggregated_all]
                msg = message_form(msg, values_tx, values_rx, values_all)
                html_report.append(msg)
            zabbix_conn.user.logout()
            return html_report
            
        except Exception as err_message:
            logger.error('Ошибка в функции zabbix95_create_report {}'.format(str(err_message)))
            return('Ошибка в функции zabbix95_create_report {}'.format(str(err_message)))