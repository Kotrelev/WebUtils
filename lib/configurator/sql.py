from lib.common import common_mysql

class nodes_sql_tables:
    def get_nodes(logger):
        #CREATE TABLE configurator_nodes (
        #id MEDIUMINT NOT NULL AUTO_INCREMENT,
        #node VARCHAR(30),
        #vendor VARCHAR(30),
        #mpls BOOL,
        #vpls BOOL,
        #ip_unnumbered BOOL,
        #ip_common BOOL,
        #loopback_iface VARCHAR(30),
        #primary key (id)
        #);
        try:
            connection = common_mysql.local_sql_conn(logger)
            req = ("select * from configurator_nodes")
            with connection.cursor() as cursor:
                cursor.execute(req)
                nodes_arr = cursor.fetchall()
            connection.close()
            if not nodes_arr:
                logger.error('Failed to get configurator_nodes table')
                return []
            return nodes_arr
        except Exception as err_message:
            logger.error('Ошибка в функции nodes_sql_tables.get_nodes {}'.format(str(err_message)))
            
    def get_vlan_ranges(logger):
        #CREATE TABLE configurator_vlan_ranges (
        #id MEDIUMINT NOT NULL AUTO_INCREMENT,
        #node VARCHAR(30), 
        #range_start SMALLINT,
        #range_end SMALLINT,
        #primary key (id)
        #);
        try:
            connection = common_mysql.local_sql_conn(logger)
            req = ("select * from configurator_vlan_ranges")
            with connection.cursor() as cursor:
                cursor.execute(req)
                vlans_arr = cursor.fetchall()
            connection.close()
            if not vlans_arr:
                logger.error('Failed to get configurator_vlan_ranges table')
                return []
            return vlans_arr
        except Exception as err_message:
            logger.error('Ошибка в функции nodes_sql_tables.get_vlan_ranges {}'.format(str(err_message)))
            
    def get_ip_ranges(logger):
        #CREATE TABLE configurator_ip_ranges (
        #id MEDIUMINT NOT NULL AUTO_INCREMENT,
        #node VARCHAR(30),
        #range_start VARCHAR(15),
        #range_end VARCHAR(15),
        #subnet VARCHAR(15),
        #gateway VARCHAR(15),
        #primary key (id)
        #);
        try:
            connection = common_mysql.local_sql_conn(logger)
            req = ("select * from configurator_ip_ranges")
            with connection.cursor() as cursor:
                cursor.execute(req)
                ips_arr = cursor.fetchall()
            connection.close()
            if not ips_arr:
                logger.error('Failed to get configurator_ip_ranges table')
                return []
            return ips_arr
        except Exception as err_message:
            logger.error('Ошибка в функции nodes_sql_tables.get_ip_ranges {}'.format(str(err_message)))
            
    def set_node(node, vendor, mpls, vpls, ip_unnumbered, ip_common, loopback_iface, logger):
        try:
            connection = common_mysql.local_sql_conn(logger)
            req = ("insert into configurator_nodes(node,vendor,mpls,vpls,ip_unnumbered,ip_common,loopback_iface)"
                   " values ('{}', '{}', {}, {}, {}, {}, '{}');".format(
                       node,vendor,mpls,vpls,ip_unnumbered,ip_common,loopback_iface))
            with connection.cursor() as cursor:
                cursor.execute(req)
            connection.commit()
            connection.close()
        except Exception as err_message:
            logger.error('Ошибка в функции nodes_sql_tables.set_node {}'.format(str(err_message)))
            
    def set_ip_range(node, range_start, range_end, subnet, gateway, logger):
        try:
            connection = common_mysql.local_sql_conn(logger)
            req = ("insert into configurator_ip_ranges(node,range_start,range_end,subnet,gateway)"
                   " values ('{}', '{}', '{}', '{}', '{}');".format(
                       node,range_start,range_end,subnet,gateway))
            with connection.cursor() as cursor:
                cursor.execute(req)
            connection.commit()
            connection.close()
        except Exception as err_message:
            logger.error('Ошибка в функции nodes_sql_tables.set_ip_range {}'.format(str(err_message)))
            
    def set_vlan_range(node, range_start, range_end, logger):
        try:
            connection = common_mysql.local_sql_conn(logger)
            req = ("insert into configurator_vlan_ranges(node,range_start,range_end)"
                   " values ('{}', '{}', '{}');".format(
                       node,range_start,range_end))
            with connection.cursor() as cursor:
                cursor.execute(req)
            connection.commit()
            connection.close()
        except Exception as err_message:
            logger.error('Ошибка в функции nodes_sql_tables.set_vlan_range {}'.format(str(err_message)))
            
    def edit_node(logger):
        try:
            pass
        except Exception as err_message:
            logger.error('Ошибка в функции nodes_sql_tables.edit_node {}'.format(str(err_message)))
            
    def del_node(node_id, logger):
        try:
            connection = common_mysql.local_sql_conn(logger)
            req = ("delete from configurator_nodes where id = '{}'".format(node_id))
            logger.info('executing {}'.format(req))
            with connection.cursor() as cursor:
                cursor.execute(req)
            connection.commit()
            connection.close()
        except Exception as err_message:
            logger.error('Ошибка в функции nodes_sql_tables.del_node {}'.format(str(err_message)))
            
    def del_ip_range(ipr_id, logger):
        try:
            connection = common_mysql.local_sql_conn(logger)
            req = ("delete from configurator_ip_ranges where id = '{}'".format(ipr_id))
            logger.info('executing {}'.format(req))
            with connection.cursor() as cursor:
                cursor.execute(req)
            connection.commit()
            connection.close()
        except Exception as err_message:
            logger.error('Ошибка в функции nodes_sql_tables.del_ip_range {}'.format(str(err_message)))
            
    def del_vlan_range(vlr_id, logger):
        try:
            connection = common_mysql.local_sql_conn(logger)
            req = ("delete from configurator_vlan_ranges where id = '{}'".format(vlr_id))
            logger.info('executing {}'.format(req))
            with connection.cursor() as cursor:
                cursor.execute(req)
            connection.commit()
            connection.close()
        except Exception as err_message:
            logger.error('Ошибка в функции nodes_sql_tables.del_vlan_range {}'.format(str(err_message)))
