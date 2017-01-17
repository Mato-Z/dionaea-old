#*************************************************************************
#*                               Dionaea
#*                           - catches bugs -
#*
#*
#*
#* Copyright (C) 2009  Paul Baecher & Markus Koetter
#*
#* This program is free software; you can redistribute it and/or
#* modify it under the terms of the GNU General Public License
#* as published by the Free Software Foundation; either version 2
#* of the License, or (at your option) any later version.
#*
#* This program is distributed in the hope that it will be useful,
#* but WITHOUT ANY WARRANTY; without even the implied warranty of
#* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#* GNU General Public License for more details.
#*
#* You should have received a copy of the GNU General Public License
#* along with this program; if not, write to the Free Software
#* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#*
#*
#*             contact nepenthesdev@gmail.com
#*
#*******************************************************************************/

from dionaea import IHandlerLoader
from dionaea.core import ihandler, g_dionaea

import logging
import json
import time
import mysql.connector
import subprocess
import re

logger = logging.getLogger('logsql')
logger.setLevel(logging.DEBUG)


class LogSQLHandlerLoader(IHandlerLoader):
    name = "logsql"

    @classmethod
    def start(cls):
        return logsqlhandler("*")

#Tento zaciatok mi je nejasny...
class logsqlhandler(ihandler):
    def __init__(self, path):
        logger.debug("%s ready!" % (self.__class__.__name__))
        self.path = path
    
    def mysql_init(self): 
        cfg_database = g_dionaea.config()['modules']['python']['logsql']['mysql']['database']
        cfg_user = g_dionaea.config()['modules']['python']['logsql']['mysql']['user']
        cfg_password = g_dionaea.config()['modules']['python']['logsql']['mysql']['password']
        cfg_host = g_dionaea.config()['modules']['python']['logsql']['mysql']['host']
        cfg_port = g_dionaea.config()['modules']['python']['logsql']['mysql']['port']

        try:
            self.dbh = mysql.connector.connect(user=cfg_user, password=cfg_password, database=cfg_database, host=cfg_host, port=cfg_port)
        except:
            print("I am unable to connect to the database")
        self.cursor = self.dbh.cursor(buffered=True)#(buffered=True) #self.dbh.cursor()
        update = False

#        from uuid import UUID
#        from dionaea.smb import rpcservices
#        import inspect
#        services = inspect.getmembers(rpcservices, inspect.isclass)
#        for name, servicecls in services:
#            if not name == 'RPCService' and issubclass(servicecls, rpcservices.RPCService):
#                try:
#                    self.cursor.execute("INSERT INTO dcerpcservices (dcerpcservice_name, dcerpcservice_uuid) VALUES (?,?)",
#                                        (name, str(UUID(hex=servicecls.uuid))) )
#                except Exception as e:
#                    #                    print("dcerpcservice %s existed %s " % (servicecls.uuid, e) )
#                    pass


#        logger.info("Getting RPC Services")
#        r = self.cursor.execute("SELECT * FROM dcerpcservices")
#        print(r)
#        names = [r.description[x][0] for x in range(len(r.description))]
#        r = [ dict(zip(names, i)) for i in r]
#        print(r)
#        r = dict([(UUID(i['dcerpcservice_uuid']).hex,i['dcerpcservice'])
#                  for i in r])
#        print(r)

#        logger.info("Setting RPC ServiceOps")
#        for name, servicecls in services:
#            if not name == 'RPCService' and issubclass(servicecls, rpcservices.RPCService):
#                for opnum in servicecls.ops:
#                    op = servicecls.ops[opnum]
#                    uuid = servicecls.uuid
#                    vuln = ''
#                    dcerpcservice = r[uuid]
#                    if opnum in servicecls.vulns:
#                        vuln = servicecls.vulns[opnum]
#                    try:
#                        self.cursor.execute("INSERT INTO dcerpcserviceops (dcerpcservice, dcerpcserviceop_opnum, dcerpcserviceop_name, dcerpcserviceop_vuln) VALUES (?,?,?,?)",
#                                            (dcerpcservice, opnum, op, vuln))
#                    except:
#                       #                        print("%s %s %s %s %s existed" % (dcerpcservice, uuid, name, op, vuln))
#                        pass

#       from dionaea.mysql.include.packets import MySQL_Commands
#        logger.info("Setting MySQL Command Ops")
#        for num,name in MySQL_Commands.items():
#            try:
#                self.cursor.execute("INSERT INTO mysql_command_ops (mysql_command_cmd, mysql_command_op_name) VALUES (?,?)",
#                                    (num, name))
#            except:
#                pass


#        self.dbh.commit()

#odtialto zacina asi INSERTovanie jednotlivych udalosti?
    def start(self):
        ihandler.__init__(self, self.path)
        # mapping socket -> attackid
        self.attacks = {}

        self.pending = {}
        self.log_mode = g_dionaea.config()['modules']['python']['logsql']['mode']
        self.mysql_init()

    def __del__(self):
        logger.info("Closing %s handle" % (self.log_mode))
        self.cursor.close()
        self.cursor = None
        self.dbh.close()
        self.dbh = None

    def createASNForIP(self, icd, peerIP, connection_type):
        def addslashes(s):
            l = ["\\", '"', "'", "\0", ]
            for i in l:
                if i in s:
                    s = s.replace(i, '\\'+i)
            return s

        def reverseIP(address):
            temp = re.split("\.", address)
            convertedAddress = str(temp[3]) +'.' + str(temp[2]) + '.' + str(temp[1]) +'.' + str(temp[0])
            return convertedAddress

        def createTheSession(icd, connection_type, asnid):
            con = icd.con
            try:
                r = self.cursor.execute("""INSERT INTO connections (`connection_timestamp`, `connection_type`, `connection_transport`, `connection_protocol`, `local_host`, `local_port`, `remote_host`, `remote_hostname`, `remote_port`, `asnid`) VALUES (NOW(),%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                                    (connection_type, con.transport, con.protocol, con.local.host, con.local.port, con.remote.host, con.remote.hostname, con.remote.port, asnid) )
            except Exception as e:
                print(e)

            return self.cursor.lastrowid

        querycmd1 = reverseIP(peerIP) + '.origin.asn.cymru.com'
        response1 = subprocess.Popen(['dig', '-t', 'TXT', querycmd1, '+short'], stdout=subprocess.PIPE).communicate()[0]
        response1List = re.split('\|', str(response1, 'utf8'))
        ASN = response1List[0].strip('" ')
        querycmd2 = 'AS' + ASN + '.asn.cymru.com'
        response2 = subprocess.Popen(['dig', '-t', 'TXT', querycmd2, '+short'], stdout=subprocess.PIPE).communicate()[0]
        response2List = re.split('\|', str(response2, 'utf8'))
        logger.info("RESPONSE1: %s " % (str(response1, 'utf8')))
        logger.info("RESPONSE2: %s " % (str(response2, 'utf8')))
        if len(response2List) < 4:
            attackid = createTheSession(icd, connection_type, 1)
            logger.info("Invalid AS response, attackid = %i" % (attackid))
        else:
            isp = addslashes(response2List[4].replace('"', ''))
            network = addslashes(response1List[1].strip())
            country = addslashes(response1List[2].strip())
            registry = addslashes(response1List[3].strip())
            isp = network + "-" + isp
            self.cursor.execute("""SELECT `asnid` FROM `asinfo` WHERE `asn` = %s AND `rir` = %s AND `country` = %s AND `asname` = %s """, (ASN, registry, country, isp))
            r = self.cursor.fetchone()
            if r:
                attackid = createTheSession(icd, connection_type, int(r[0]))
                logger.info("Existing AS response (%s,%s,%s,%s), attackid = %i" % (isp, network, country, registry, attackid))
            else:
                r = self.cursor.execute("""INSERT INTO `asinfo` (`asn`, `rir`, `country`, `asname`) VALUES (%s, %s, %s, %s) """, (ASN, registry, country, isp))
                asnid = self.cursor.lastrowid
                attackid = createTheSession(icd, connection_type, asnid)
                logger.info("New AS response (%s,%s,%s,%s), attackid = %i" % (isp, network, country, registry, attackid))
      
        return attackid

    def handle_incident(self, icd):
        #        print("unknown")
        pass

    def connection_insert(self, icd, connection_type):
        con = icd.con
        attackid = self.createASNForIP(icd, con.remote.host, connection_type)
        self.attacks[con] = (attackid, attackid)
        self.dbh.commit()

        # maybe this was a early connection?
        if con in self.pending:
            # the connection was linked before we knew it
            # that means we have to
            # - update the connection_root and connection_parent for all connections which had the pending
            # - update the connection_root for all connections which had the 'childid' as connection_root
            for i in self.pending[con]:
                print("%s %s %s" % (attackid, attackid, i))
                try:
                    self.cursor.execute("UPDATE connections SET connection_root = %s, connection_parent = %s WHERE connection = %s",
                                            (attackid, attackid, i ) )
                    self.cursor.execute("UPDATE connections SET connection_root = %s WHERE connection_root = %s",
                                            (attackid, i ) )
                except Exception as e:
                    print(e)
            self.dbh.commit()

        return attackid


    def handle_incident_dionaea_connection_tcp_listen(self, icd):
        attackid = self.connection_insert( icd, 'listen')
        con=icd.con
        logger.info("listen connection on %s:%i (id=%i)" %
                    (con.remote.host, con.remote.port, attackid))

    def handle_incident_dionaea_connection_tls_listen(self, icd):
        attackid = self.connection_insert( icd, 'listen')
        con=icd.con
        logger.info("listen connection on %s:%i (id=%i)" %
                    (con.remote.host, con.remote.port, attackid))

    def handle_incident_dionaea_connection_tcp_connect(self, icd):
        attackid = self.connection_insert( icd, 'connect')
        con=icd.con
        logger.info("connect connection to %s/%s:%i from %s:%i (id=%i)" %
                    (con.remote.host, con.remote.hostname, con.remote.port, con.local.host, con.local.port, attackid))

    def handle_incident_dionaea_connection_tls_connect(self, icd):
        attackid = self.connection_insert( icd, 'connect')
        con=icd.con
        logger.info("connect connection to %s/%s:%i from %s:%i (id=%i)" %
                    (con.remote.host, con.remote.hostname, con.remote.port, con.local.host, con.local.port, attackid))

    def handle_incident_dionaea_connection_udp_connect(self, icd):
        attackid = self.connection_insert( icd, 'connect')
        con=icd.con
        logger.info("connect connection to %s/%s:%i from %s:%i (id=%i)" %
                    (con.remote.host, con.remote.hostname, con.remote.port, con.local.host, con.local.port, attackid))

    def handle_incident_dionaea_connection_tcp_accept(self, icd):
        attackid = self.connection_insert( icd, 'accept')
        con=icd.con
        logger.info("accepted connection from %s:%i to %s:%i (id=%i)" %
                    (con.remote.host, con.remote.port, con.local.host, con.local.port, attackid))

    def handle_incident_dionaea_connection_tls_accept(self, icd):
        attackid = self.connection_insert( icd, 'accept')
        con=icd.con
        logger.info("accepted connection from %s:%i to %s:%i (id=%i)" %
                    (con.remote.host, con.remote.port, con.local.host, con.local.port, attackid))


    def handle_incident_dionaea_connection_tcp_reject(self, icd):
        attackid = self.connection_insert(icd, 'reject')
        con=icd.con
        logger.info("reject connection from %s:%i to %s:%i (id=%i)" %
                    (con.remote.host, con.remote.port, con.local.host, con.local.port, attackid))

    def handle_incident_dionaea_connection_tcp_pending(self, icd):
        attackid = self.connection_insert(icd, 'pending')
        con=icd.con
        logger.info("pending connection from %s:%i to %s:%i (id=%i)" %
                    (con.remote.host, con.remote.port, con.local.host, con.local.port, attackid))

    def handle_incident_dionaea_connection_link_early(self, icd):
        # if we have to link a connection with a connection we do not know yet,
        # we store the unknown connection in self.pending and associate the
        # childs id with it
        if icd.parent not in self.attacks:
            if icd.parent not in self.pending:
                self.pending[icd.parent] = {self.attacks[icd.child][1]: True}
            else:
                if icd.child not in self.pending[icd.parent]:
                    self.pending[icd.parent][self.attacks[icd.child][1]] = True

    def handle_incident_dionaea_connection_link(self, icd):
        if icd.parent in self.attacks:
            logger.info("parent ids %s" % str(self.attacks[icd.parent]))
            parentroot, parentid = self.attacks[icd.parent]
            if icd.child in self.attacks:
                logger.info("child had ids %s" % str(self.attacks[icd.child]))
                childroot, childid = self.attacks[icd.child]
            else:
                childid = parentid
            self.attacks[icd.child] = (parentroot, childid)
            logger.info("child has ids %s" % str(self.attacks[icd.child]))
            logger.info("child %i parent %i root %i" % (childid, parentid, parentroot) )
            try:
                r = self.cursor.execute("UPDATE connections SET connection_root = %s, connection_parent = %s WHERE connection = %s",
                        (parentroot, parentid, childid) )
            except Exception as e:
                print(e)
            self.dbh.commit()

        if icd.child in self.pending:
            # if the new accepted connection was pending
            # assign the connection_root to all connections which have been
            # waiting for this connection
            parentroot, parentid = self.attacks[icd.parent]
            if icd.child in self.attacks:
                childroot, childid = self.attacks[icd.child]
            else:
                childid = parentid

            try:
                self.cursor.execute("UPDATE connections SET connection_root = %s WHERE connection_root = %s",
                        (parentroot, childid) )
            except Exception as e:
                print(e)
            self.dbh.commit()

    def handle_incident_dionaea_connection_free(self, icd):
        con=icd.con
        if con in self.attacks:
            attackid = self.attacks[con][1]
            del self.attacks[con]
            logger.info("attackid %i is done" % attackid)
        else:
            logger.warn("no attackid for %s:%s" %
                        (con.local.host, con.local.port) )
        if con in self.pending:
            del self.pending[con]


    def handle_incident_dionaea_module_emu_profile(self, icd):
        con = icd.con
        if con not in self.attacks:
            return
        attackid = self.attacks[con][1]
        logger.info("emu profile for attackid %i" % attackid)
        try:
            self.cursor.execute("INSERT INTO emu_profiles (connection, emu_profile_json) VALUES (%s,%s)",
                    (attackid, icd.profile) )
        except Exception as e:
            print(e)
        self.dbh.commit()


    def handle_incident_dionaea_download_offer(self, icd):
        con=icd.con
        if con not in self.attacks:
            return
        attackid = self.attacks[con][1]
        logger.info("offer for attackid %i" % attackid):
        try:
            self.cursor.execute("INSERT INTO offers (connection, offer_url) VALUES (%s,%s)",
                    (attackid, icd.url) )
        except Exception as e:
            print(e)
        self.dbh.commit()

    def handle_incident_dionaea_download_complete_hash(self, icd):
        con=icd.con
        if con not in self.attacks:
            return
        attackid = self.attacks[con][1]
        logger.info("complete for attackid %i" % attackid)
        try:
            self.cursor.execute("INSERT INTO downloads (connection, download_url, download_md5_hash) VALUES (%s,%s,%s)",
                (attackid, icd.url, icd.md5hash) )
        except Exception as e:
            print(e)
        self.dbh.commit()


    def handle_incident_dionaea_service_shell_listen(self, icd):
        con=icd.con
        if con not in self.attacks:
            return
        attackid = self.attacks[con][1]
        logger.info("listen shell for attackid %i" % attackid)
        try:
            self.cursor.execute("INSERT INTO emu_services (connection, emu_service_url) VALUES (%s,%s)",
                (attackid, "bindshell://"+str(icd.port)) )
        except Exception as e:
            print(e)
        self.dbh.commit()

    def handle_incident_dionaea_service_shell_connect(self, icd):
        con=icd.con
        if con not in self.attacks:
            return
        attackid = self.attacks[con][1]
        logger.info("connect shell for attackid %i" % attackid)
        try:
            self.cursor.execute("INSERT INTO emu_services (connection, emu_service_url) VALUES (%s,%s)",
                    (attackid, "connectbackshell://"+str(icd.host)+":"+str(icd.port)) )
        except Exception as e:
            print(e)
        self.dbh.commit()

    def handle_incident_dionaea_modules_python_p0f(self, icd):
        con=icd.con
        if con in self.attacks:
            attackid = self.attacks[con][1]
            try:
                self.cursor.execute("INSERT INTO p0fs (connection, p0f_genre, p0f_link, p0f_detail, p0f_uptime, p0f_tos, p0f_dist, p0f_nat, p0f_fw) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                        ( attackid, icd.genre, icd.link, icd.detail, icd.uptime, icd.tos, icd.dist, icd.nat, icd.fw))
            except Exception as e:
                print(e)
            self.dbh.commit()

    def handle_incident_dionaea_modules_python_smb_dcerpc_request(self, icd):
        con=icd.con
        if con in self.attacks:
            attackid = self.attacks[con][1]
            try:
                self.cursor.execute("INSERT INTO dcerpcrequests (connection, dcerpcrequest_uuid, dcerpcrequest_opnum) VALUES (%s,%s,%s)",
                        (attackid, icd.uuid, icd.opnum))
            except Exception as e:
                print(e)
            self.dbh.commit()

    def handle_incident_dionaea_modules_python_smb_dcerpc_bind(self, icd):
        con=icd.con
        if con in self.attacks:
            attackid = self.attacks[con][1]
            try:
                self.cursor.execute("INSERT INTO dcerpcbinds (connection, dcerpcbind_uuid, dcerpcbind_transfersyntax) VALUES (%s,%s,%s)",
                        (attackid, icd.uuid, icd.transfersyntax))
            except Exception as e:
                print(e)
            self.dbh.commit()

    def handle_incident_dionaea_modules_python_mssql_login(self, icd):
        con = icd.con
        if con in self.attacks:
            attackid = self.attacks[con][1]
            try:
                self.cursor.execute("INSERT INTO logins (connection, login_username, login_password) VALUES (%s,%s,%s)",
                    (attackid, icd.username, icd.password))
                self.cursor.execute("INSERT INTO mssql_fingerprints (connection, mssql_fingerprint_hostname, mssql_fingerprint_appname, mssql_fingerprint_cltintname) VALUES (%s,%s,%s,%s)", 
                    (attackid, icd.hostname, icd.appname, icd.cltintname))
            except Exception as e:
                print(e)
            self.dbh.commit()

    def handle_incident_dionaea_modules_python_mssql_cmd(self, icd):
        con = icd.con
        if con in self.attacks:
            attackid = self.attacks[con][1]
            try:
                self.cursor.execute("INSERT INTO mssql_commands (connection, mssql_command_status, mssql_command_cmd) VALUES (%s,%s,%s)", 
                    (attackid, icd.status, icd.cmd))
            except Exception as e:
                print(e)
            self.dbh.commit()

    def handle_incident_dionaea_modules_python_virustotal_report(self, icd):
        md5 = icd.md5hash
        f = open(icd.path, mode='r')
        j = json.load(f)

        if j['response_code'] == 1: # file was known to virustotal
            permalink = j['permalink']
            date = j['scan_date']
            try:
                self.cursor.execute("INSERT INTO virustotals (virustotal_md5_hash, virustotal_permalink, virustotal_timestamp) VALUES (%s,%s,extract(epoch from %s))", 
                    (md5, permalink, date))
            except Exception as e:
                print(e)
            self.dbh.commit()

            virustotal = self.cursor.lastrowid

            scans = j['scans']
            for av, val in scans.items():
                res = val['result']
                # not detected = '' -> NULL
                if res == '':
                    res = None

                try:
                    self.cursor.execute("""INSERT INTO virustotalscans (virustotal, virustotalscan_scanner, virustotalscan_result) VALUES (%s,%s,%s)""",
                            (virustotal, av, res))
                except Exception as e:
                    print(e)
#                logger.debug("scanner {} result {}".format(av,scans[av]))
            self.dbh.commit()

    def handle_incident_dionaea_modules_python_mysql_login(self, icd):
        con = icd.con
        if con in self.attacks:
            attackid = self.attacks[con][1]
            try:
                self.cursor.execute("INSERT INTO logins (connection, login_username, login_password) VALUES (%s,%s,%s)",
                    (attackid, icd.username, icd.password))
            except Exception as e:
                print(e)
            self.dbh.commit()


    def handle_incident_dionaea_modules_python_mysql_command(self, icd):
        con = icd.con
        if con in self.attacks:
            attackid = self.attacks[con][1]
            try:
                self.cursor.execute("INSERT INTO mysql_commands (connection, mysql_command_cmd) VALUES (%s,%s)",
                    (attackid, icd.command))
            except Exception as e:
                print(e)
            cmdid = self.cursor.lastrowid

            if hasattr(icd, 'args'):
                args = icd.args
                for i in range(len(args)):
                    arg = args[i]
                    try:
                        self.cursor.execute("INSERT INTO mysql_command_args (mysql_command, mysql_command_arg_index, mysql_command_arg_data) VALUES (%s,%s,%s)",
                            (cmdid, i, arg))
                    except Exception as e:
                        print(e)
            self.dbh.commit()

    def handle_incident_dionaea_modules_python_sip_command(self, icd):
        con = icd.con
        if con not in self.attacks:
            return

        def calc_allow(a):
            b={ b'UNKNOWN'  :(1<<0),
                'ACK'       :(1<<1),
                'BYE'       :(1<<2),
                'CANCEL'    :(1<<3),
                'INFO'      :(1<<4),
                'INVITE'    :(1<<5),
                'MESSAGE'   :(1<<6),
                'NOTIFY'    :(1<<7),
                'OPTIONS'   :(1<<8),
                'PRACK'     :(1<<9),
                'PUBLISH'   :(1<<10),
                'REFER'     :(1<<11),
                'REGISTER'  :(1<<12),
                'SUBSCRIBE' :(1<<13),
                'UPDATE'    :(1<<14)
                }
            allow=0
            for i in a:
                if i in b:
                    allow |= b[i]
                else:
                    allow |= b[b'UNKNOWN']
            return allow

        attackid = self.attacks[con][1]
        try:
            self.cursor.execute("""INSERT INTO sip_commands
                (connection, sip_command_method, sip_command_call_id,
                sip_command_user_agent, sip_command_allow) VALUES (%s,%s,%s,%s,%s)""",
                (attackid, icd.method, icd.call_id, icd.user_agent, calc_allow(icd.allow)))
        except Exception as e:
            print(e)
        cmdid = self.cursor.lastrowid

        def add_addr(cmd, _type, addr):
            try:
                self.cursor.execute("""INSERT INTO sip_addrs
                    (sip_command, sip_addr_type, sip_addr_display_name,
                    sip_addr_uri_scheme, sip_addr_uri_user, sip_addr_uri_password,
                    sip_addr_uri_host, sip_addr_uri_port) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (
                        cmd, _type, addr['display_name'],
                        addr['uri']['scheme'], addr['uri']['user'], addr['uri']['password'],
                        addr['uri']['host'], addr['uri']['port']
                    ))
            except Exception as e:
                print(e)

        add_addr(cmdid,'addr',icd.get('addr'))
        add_addr(cmdid,'to',icd.get('to'))
        add_addr(cmdid,'contact',icd.get('contact'))
        for i in icd.get('from'):
            add_addr(cmdid,'from',i)

        def add_via(cmd, via):
            try:
                self.cursor.execute("""INSERT INTO sip_vias
                    (sip_command, sip_via_protocol, sip_via_address, sip_via_port)
                    VALUES (%s,%s,%s,%s)""",
                    (
                        cmd, via['protocol'],
                        via['address'], via['port']
                     ))
            except Exception as e:
                print(e)

        for i in icd.get('via'):
            add_via(cmdid, i)

        def add_sdp(cmd, sdp):
            def add_origin(cmd, o):
                try:
                    self.cursor.execute("""INSERT INTO sip_sdp_origins
                            (sip_command, sip_sdp_origin_username,
                            sip_sdp_origin_sess_id, sip_sdp_origin_sess_version,
                            sip_sdp_origin_nettype, sip_sdp_origin_addrtype,
                            sip_sdp_origin_unicast_address)
                            VALUES (%s,%s,%s,%s,%s,%s,%s)""",
                            (
                                cmd, o['username'],
                                o['sess_id'], o['sess_version'],
                                o['nettype'], o['addrtype'],
                                o['unicast_address']
                            ))
                except Exception as e:
                    print(e)
            def add_condata(cmd, c):
                try:
                    self.cursor.execute("""INSERT INTO sip_sdp_connectiondatas
                            (sip_command, sip_sdp_connectiondata_nettype,
                            sip_sdp_connectiondata_addrtype, sip_sdp_connectiondata_connection_address,
                            sip_sdp_connectiondata_ttl, sip_sdp_connectiondata_number_of_addresses)
                            VALUES (%s,%s,%s,%s,%s,%s)""",
                            (
                                cmd, c['nettype'],
                                c['addrtype'], c['connection_address'],
                                c['ttl'], c['number_of_addresses']
                            ))
                except Exception as e:
                    print(e)
            def add_media(cmd, c):
                try:
                    self.cursor.execute("""INSERT INTO sip_sdp_medias
                            (sip_command, sip_sdp_media_media,
                            sip_sdp_media_port, sip_sdp_media_number_of_ports,
                            sip_sdp_media_proto)
                            VALUES (%s,%s,%s,%s,%s)""",
                            (
                                cmd, c['media'],
                                c['port'], c['number_of_ports'],
                                c['proto']
                            ))
                except Exception as e:
                    print(e)
            if 'o' in sdp:
                add_origin(cmd, sdp['o'])
            if 'c' in sdp:
                add_condata(cmd, sdp['c'])
            if 'm' in sdp:
                for i in sdp['m']:
                    add_media(cmd, i)

        if hasattr(icd,'sdp') and icd.sdp is not None:
            add_sdp(cmdid,icd.sdp)

        self.dbh.commit()

    def handle_incident_dionaea_modules_python_mqtt_connect(self, icd):
        con = icd.con
        if con in self.attacks:
            attackid = self.attacks[con][1]
            #self.cursor.execute("INSERT INTO logins (connection, login_username, login_password) VALUES (?,?,?)",
            #    (attackid, icd.username, icd.password))
            self.cursor.execute("INSERT INTO mqtt_fingerprints (connection, mqtt_fingerprint_clientid, mqtt_fingerprint_willtopic, mqtt_fingerprint_willmessage,mqtt_fingerprint_username,mqtt_fingerprint_password) VALUES (?,?,?,?,?,?)",
                (attackid, icd.clientid, icd.willtopic, icd.willmessage, icd.username, icd.password))
            self.dbh.commit()

    def handle_incident_dionaea_modules_python_mqtt_publish(self, icd):
        con = icd.con
        if con in self.attacks:
            attackid = self.attacks[con][1]
            self.cursor.execute("INSERT INTO mqtt_publish_commands (connection, mqtt_publish_command_topic, mqtt_publish_command_message) VALUES (?,?,?)",
                (attackid, icd.publishtopic, icd.publishmessage))
            self.dbh.commit()

    def handle_incident_dionaea_modules_python_mqtt_subscribe(self, icd):
        con = icd.con
        if con in self.attacks:
            attackid = self.attacks[con][1]
            self.cursor.execute("INSERT INTO mqtt_subscribe_commands (connection, mqtt_subscribe_command_messageid, mqtt_subscribe_command_topic) VALUES (?,?,?)",
                (attackid, icd.subscribemessageid, icd.subscribetopic))
            self.dbh.commit()

