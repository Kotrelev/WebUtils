import config
from pyzabbix import ZabbixAPI

class avalibility:
    def get_report(fromd, tilld, logger):
        try:
            zabbix_conn = ZabbixAPI(config.zabbix_link,
                                    user=config.zabbix_user,
                                    password=config.zabbix_pass)
            
            hosts = zabbix_conn.host.get(monitored_hosts = 1, 
                                         output = ['name'], 
                                         selectGroups = [], 
                                         selectGraphs = [])
            graphs = zabbix_conn.graph.get(output = ['graphid'], 
                                           search = {'name': 'Доступность'})
            graphs_arr =  [g['graphid'] for g in graphs]
            host_list = [h['hostid'] for h in hosts]
            events = zabbix_conn.event.get(time_from = fromd, 
                                           time_till = tilld, 
                                           hostids = host_list,
                                           output = ['eventid', 
                                                     'clock', 
                                                     'name', 
                                                     'r_eventid',
                                                     'value'])
    
            #[{'hostid': '10258', 'name': 'RTU2 iLo4', 'groups': [{'groupid': '15'}]}, {...}]
            groups = zabbix_conn.hostgroup.get(output = 'extend', 
                                               search = {'name':'Avantel'})
            #[{'groupid': '15', 'name': 'Avantel IPMI', 'internal': '0', 'flags': '0'}, {...}]
            zabbix_conn.user.logout()
            #ppi = [x for x in pp['result'] if 'ICMP' in x['name']]
            icmp_events = {x['eventid']: x for x in events 
                        if 'Unavailable by ICMP ping' in x['name'] 
                        or 'не доступен по ICMP' in x['name']}
            
            # список диктов в дикт диктов, индексируем именами
            host_id_dict = {h['name']: h for h in hosts}
    
            raw_report = {}
            # raw_report = {'trigger name': {'dtime': [downtime-in-seconds, ...]}, ...}
            report = {}
            icmp_events_copy = icmp_events.copy()
            for event_id in icmp_events:
                trigger_name = icmp_events[event_id]['name']
                if not trigger_name in raw_report:
                    raw_report[trigger_name] = {'dtime': []}
                # ['r_eventid'] == '0' means this event is the end of the event or it's in progress now
                if icmp_events[event_id]['r_eventid'] == '0':
                    continue
                if icmp_events[event_id]['r_eventid'] in icmp_events:
                    # r_eventid is the id of the event's ending 
                    r_eventid = icmp_events[event_id]['r_eventid']
                    # из таймштампа окончания вычитаем таймштамп начала
                    dtime = int(icmp_events[r_eventid]['clock'])-int(icmp_events[event_id]['clock'])
                    raw_report[trigger_name]['dtime'].append(dtime)
                    icmp_events_copy.pop(r_eventid)
                # event ended after 'end time'
                else:
                    raw_report[trigger_name]['dtime'].append(tilld-int(icmp_events[event_id]['clock']))
                icmp_events_copy.pop(event_id)
            # event started before 'start time' or in progress now
            for event_id in icmp_events_copy:
                trigger_name = icmp_events_copy[event_id]['name']
                if not trigger_name in raw_report:
                    raw_report[trigger_name] = {'dtime': []}
                tstamp = int(icmp_events_copy[event_id]['clock'])
                # end of the event
                if icmp_events_copy[event_id]['value'] == '0':
                    raw_report[trigger_name]['dtime'].append(tstamp-fromd)
                # start of the event
                else:
                    raw_report[trigger_name]['dtime'].append(tilld-tstamp)
            
            for name in raw_report:
                clean_name = name.replace(' Unavailable by ICMP ping', '').replace(' не доступен по ICMP', '')
                # игнорируем удаленных из заббикса
                if not clean_name in host_id_dict:
                    continue
                report[clean_name] = {}
                report[clean_name]['events'] = str(len(raw_report[name]['dtime']))
                report[clean_name]['dtime'] = '{:d}'.format(int(sum(raw_report[name]['dtime'])/60))
                report[clean_name]['id'] = host_id_dict[clean_name]['hostid']
                icmp_graph = [x['graphid'] 
                              for x in host_id_dict[clean_name]['graphs'] 
                              if x['graphid'] in graphs_arr]
                if not icmp_graph: 
                    report[clean_name]['graph'] = ''
                else:
                    report[clean_name]['graph'] = icmp_graph[0]
        
            # Группы из списка диктов в дикт с ключами в виде id группы. Срезаем Авантел из названия.
            groups_id_dict = {x['groupid']: {'name': x['name'].replace('Avantel ', '')} for x in groups}
            # Добавляем ключ hosts в дикты групп, в него сгружаем дикты хостов из отчета.
            [groups_id_dict[group['groupid']].setdefault('hosts', {}).update({host_id_dict[dev]['name']: report[dev]})
             for dev in report 
             for group in host_id_dict[dev]['groups'] 
             if group['groupid'] in groups_id_dict]
            # дропаем лишние группы
            [groups_id_dict.pop(x) for x in groups_id_dict.copy() if 'hosts' not in groups_id_dict[x]]
            # сокращаем лишние данные. На выходе 
            # {Имя группы: {Имя хоста: {'events': '6', 'dtime': '60', 'id': 'hostid'}}}
            report_grouped = {groups_id_dict[g]['name']: groups_id_dict[g]['hosts'] for g in groups_id_dict}
            
            return (report, report_grouped)
            
        except Exception as err_message:
            logger.error('Ошибка в функции avalibility.get_report {}'.format(str(err_message)))
        
    def js_generator(report_grouped, logger):
        try:
            # делаем дикт для функции создания кнопок
            names_dict = {x: x for x in report_grouped.keys()}
            names_dict.update({'full_report': 'Все'})

            buttons_script, buttons = avalibility.js_buttons_generator(names_dict, 'AvalibilityButton', logger)
            table_sorter_script = avalibility.js_table_sorter_generator(names_dict, logger)
            
            return(buttons_script, buttons, table_sorter_script)
            
        except Exception as err_message:
            logger.error('Ошибка в функции avalibility.js_generator {}'.format(str(err_message)))
            
            
    def js_buttons_generator(names_dict, bclass, logger):
        '''Функция генерит скрипт который сделает нам кнопки для переключения между таблицами.
        Чтобы оно работало, таблицам надо будет раздать id из names_dict
        names_dict = {'short_eng_name': 'Большое название', ...}
        '''
        try:
            if not names_dict:
                return None
            jscript = ''
            block = '''
    function {button}() {{
      {elems}
      if ({button}.style.display === "none") {{
        {vars_block}
      }} else {{
        {vars_block}
      }}
    }}'''
            elem = 'var {} = document.getElementById("{}");'
            disp = '{}.style.display = "none";'
            button_template = '''
    <input id="{eid}" class="RadioButtons" name="{bname}Button" type="radio" value="0">
    <label for="{eid}" class="{bclass}" onclick="{func}()">{blabel}</label>\n'''
            
            buttons = ''.join([button_template.format(eid = x+str(i),
                                                      bclass = bclass,
                                                      func = x,
                                                      bname = bclass,
                                                      blabel = names_dict[x])
                                   for i, x in enumerate(names_dict)])
            for button in names_dict:
                elems = '\n  '.join([elem.format(x, x) for x in names_dict])
                vars_block = '{}.style.display = "block";\n'.format(button)
                vars_block = vars_block+'\n    '.join([disp.format(x) 
                                                    for x in names_dict 
                                                    if x != button])
                jscript = jscript+block.format(button=button, 
                                            elems=elems, 
                                            vars_block=vars_block)
            return jscript, buttons
        except Exception as err_message:
            er = 'Ошибка в функции js_buttons_generator {}'
            logger.error(er.format(str(err_message)))
            
    def js_table_sorter_generator(names_dict, logger):
        try:
            body = '''
    function init()
    {{
    {}
    }}
    window.onload = init;'''
            var_template = '''
        var {sorter} = tsorter.create('{table_id}', null, {{
                'image-number': function(row){{  
                    console.log( this );
                    return parseFloat( this.getCell(row).childNodes[1].nodeValue, 10 );
                }}
            }});'''
            sorters = '\n'.join([var_template.format(sorter = tid+str(i), 
                                                     table_id = tid) 
                                 for i, tid in enumerate(names_dict)])
            return(body.format(sorters))
            
        except Exception as err_message:
            er = 'Ошибка в функции js_table_sorter_generator {}'
            logger.error(er.format(str(err_message)))
        