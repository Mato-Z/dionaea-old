#################################################################################
#                                Dionaea
#                            - catches bugs -
#
#  Copyright (c) 2009 Markus Koetter
#  Copyright (c) 2016 PhiBo
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License
#  as published by the Free Software Foundation; either version 2
#  of the License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
#
################################################################################

# ftp client
import re
import random
import urllib.parse
import tempfile
import logging

from dionaea import IHandlerLoader
from dionaea.core import connection, ihandler, g_dionaea, incident

logger = logging.getLogger("ftp_download")
logger.setLevel(logging.DEBUG)

_linesep_regexp = re.compile(b"\r?\n")


class FTPIhandlerLoader(IHandlerLoader):
    name = "ftpdownload"

    @classmethod
    def start(cls):
        return FTPDownloadHandler("dionaea.download.offer")


class FTPCtrl(connection):
    def __init__(self, ftp):
        connection.__init__(self, "tcp")
        self.ftp = ftp
        self.state = "NONE"
        self.timeouts.sustain = 60

    def handle_established(self):
        logger.debug("FTP CTRL connection established")

    def handle_io_in(self, data):
        dlen = len(data)
        lines = _linesep_regexp.split(data)  # .decode("UTF-8"))

        remain = lines.pop()
        dlen = dlen - len(remain)

        for line in lines:
            logger.debug("FTP LINE: " + str(line))
            c = int(line[:3])
            s = line[3:4]
            if self.state == "NONE":
                if c == 220 and s != b"-":
                    self.cmd("USER " + self.ftp.user)
                    self.state = "USER"
            elif self.state == "USER" or self.state == "PASS":
                if self.state == "USER" and c == 331 and s != b"-":
                    self.cmd("PASS " + self.ftp.passwd)
                    self.state = "PASS"
                if c == 230 and s != b"-":
                    if self.ftp.mode == "binary":
                        self.cmd("TYPE I")
                        self.state = "TYPE"
                    else:
                        port = self.ftp.makeport()
                        self.cmd("PORT " + port)
                        self.state = "PORT"
            elif self.state == "TYPE":
                if (c >= 200 and c < 300) and s != b"-":
                    port = self.ftp.makeport()
                    self.cmd("PORT " + port)
                    self.state = "PORT"
            elif self.state == "PORT":
                if c == 200 and s != b"-":
                    self.cmd("RETR " + self.ftp.file)
                    self.state = "RETR"
                else:
                    logger.warn("PORT command failed")
            elif self.state == "RETR":
                if (c > 200 and c < 300)  and s != b"-":
                    self.cmd("QUIT")
                    self.state = "QUIT"
                    self.ftp.ctrldone()

        return dlen

    def cmd(self, cmd):
        logger.debug("FTP CMD: '%s'", + cmd)
        self.send(cmd + "\r\n")

    def handle_error(self, err):
        self.ftp.fail()
        return False

    def handle_disconnect(self):
        if self.state != "QUIT":
            self.ftp.fail()
        return False

    def handle_timeout_idle(self):
        return False

    def handle_timeout_sustain(self):
        return False


class FTPData(connection):
    def __init__(self, ftp=None):
        connection.__init__(self, "tcp")
        self.ftp = ftp
        self.fileobj = None
        self.timeouts.listen = 10

    def handle_established(self):
        logger.debug("FTP DATA established")
        self.timeouts.idle = 30
        self.fileobj = tempfile.NamedTemporaryFile(
            delete=False,
            prefix="ftp-",
            suffix=g_dionaea.config()["downloads"]["tmp-suffix"],
            dir=g_dionaea.config()["downloads"]["dir"]
        )

    def handle_origin(self, parent):
        self.ftp = parent.ftp
        self.ftp.dataconn = self
        self.ftp.datalistener.close()
        self.ftp.datalistener = None

    def handle_io_in(self, data):
        self.fileobj.write(data)
        return len(data)

    def handle_timeout_idle(self):
        self.fileobj.unlink(self.fileobj.name)
        self.fileobj = None
        self.ftp.fail()
        return False

    def handle_disconnect(self):
        logger.debug("received %i bytes", self._in.accounting.bytes)
        if hasattr(self, "fileobj")and self.fileobj is not None:
            # print(type(self.file))
            # print(self.file)
            self.fileobj.close()
            icd = incident("dionaea.download.complete")
            icd.path = self.fileobj.name
            icd.con = self.ftp.con
            icd.url = self.ftp.url
            icd.report()
            self.fileobj.unlink(self.fileobj.name)
            self.ftp.dataconn = None
            self.ftp.datadone()
        return False

    def handle_timeout_listen(self):
        self.ftp.fail()
        return False


class FTPClient:
    def __init__(self):
        self.ctrl = FTPCtrl(self)

    def download(self, con, user, passwd, host, port, file, mode, url):
        self.user = user
        self.passwd = passwd
        self.host = host
        self.port = port
        self.file = file
        self.mode = mode
        self.con = con
        self.url = url

        if con:
            self.local = con.local.host
            self.ctrl.bind(self.local, 0)
            self.con.ref()

        self.ctrl.connect(host, port)
        self.dataconn = None
        self.datalistener = None

        if con:
            i = incident("dionaea.connection.link")
            i.parent = con
            i.child = self.ctrl
            i.report()

    def makeport(self):
        self.datalistener = FTPData(ftp=self)
        try:
            portrange = g_dionaea.config()["modules"]["python"]["ftp"]["active-ports"]
            (minport, maxport) = portrange.split("-")
            minport = int(minport)
            maxport = int(maxport)
        except:
            minport = 62001
            maxport = 63000

        try:
            # for NAT setups
            host = g_dionaea.config()["modules"]["python"]["ftp"]["active-host"]
            if host == "0.0.0.0":
                host = self.ctrl.local.host
                logger.info("datalisten host %s", host)
            else:
                import socket
                host = socket.gethostbyname(host)
                logger.info("resolved host %s", host)
        except:
            host = self.ctrl.local.host
            logger.info("except datalisten host %s", self.ctrl.local.host)

        # NAT, use a port range which is forwarded to your honeypot
        ports = list(
            filter(
                lambda port: ((port >> 4) & 0xf) != 0,
                range(minport, maxport)
            )
        )
        random.shuffle(ports)
        port = None
        for port in ports:
            self.datalistener.bind(self.ctrl.local.host, port)
            if self.datalistener.listen() == True:
                port = self.datalistener.local.port
                i = incident("dionaea.connection.link")
                i.parent = self.ctrl
                i.child = self.datalistener
                i.report()
                break
        hbytes = host.split(".")
        pbytes = [repr(port // 256), repr(port % 256)]
        bytes = hbytes + pbytes
        port = ",".join(bytes)
        logger.debug("PORT CMD %s", port)
        return port

    def ctrldone(self):
        logger.info("SUCCESS DOWNLOADING FILE")
        self.done()

    def datadone(self):
        logger.info("FILE received")
        self.done()

    def done(self):
        if self.ctrl and self.ctrl.state == "QUIT" and self.dataconn is None:
            logger.info("proceed processing file!")
            self.ctrl = None
            self.finish()

    def fail(self):
        self.finish()

    def finish(self):
        if self.con:
            self.con.unref()
            self.con = None
        if self.ctrl is not None:
            self.ctrl.close()
            self.ctrl = None
        if self.datalistener and self.datalistener is not None:
            self.datalistener.close()
            self.datalistener = None
        if self.dataconn and self.dataconn != None:
            self.dataconn.close()
            self.dataconn = None


class FTPDownloadHandler(ihandler):
    def __init__(self, path):
        logger.debug("%s ready!", self.__class__.__name__)
        ihandler.__init__(self, path)

    def handle_incident(self, icd):
        url = icd.url
        p = urllib.parse.urlsplit(url)
        logger.debug("Parsed url: %s", repr(p))
        if p.scheme == "ftp":
            logger.info("do download")
            try:
                con = icd.con
            except AttributeError:
                con = None

            if hasattr(icd, "ftpmode"):
                ftpmode = icd.ftpmode
            else:
                ftpmode = "binary"

            f = FTPClient()
            f.download(con, p.username, p.password, p.hostname, p.port, p.path, ftpmode, url)
