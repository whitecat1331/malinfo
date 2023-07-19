import socketserver
import socket
import tempfile
import ddnsserver
import psutil
import ssl
import pop3_server
import os
import smbserver
import ICMPack.server
import nullsmtpd.nullsmtpd
import netifaces as ni
from http.server import BaseHTTPRequestHandler
from multiprocessing import Process
from abc import ABC, abstractmethod
from pyftpdlib.servers import FTPServer as FTPS
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.authorizers import DummyAuthorizer
from fake_ssh import Server as SSH
from generate_cert import generate_cert


class Server(ABC):

    ALL_INTERFACES = '0.0.0.0'
    HOME_DIRECTORY = os.path.expanduser("~")

    def __init__(self, name, lport, lhost, username="anonymous", password="anonymous"):
        self.lport = lport
        self.lhost = lhost
        self.address = (self.lhost, self.lport)
        self.username = username
        self.password = password

    @staticmethod
    def serve_until_interrupt(daemon):
        try:
            print("Starting Server")
            daemon.serve_forever()
        except KeyboardInterrupt:
            print("KeyboardInterrupt: Shutting Server Down")

    @abstractmethod
    def serve(self):
        pass

    @staticmethod
    def get_ip_address(interface):
        return ni.ifaddresses(interface)[ni.AF_INET][0]['addr']

    @staticmethod
    def get_interfaces():
        return list(psutil.net_if_stats().keys())


class HTTPServer(Server):
    NAME = "http"
    PORT = 80
    interrupt_read, interrupt_write = socket.socketpair()

    class RequestHandler(BaseHTTPRequestHandler):

        def do_GET(self):
            request_path = self.path

            print("\n----- Request Start ----->\n")
            print("request_path :", request_path)
            print("self.headers :", self.headers)
            print("<----- Request End -----\n")

            self.send_response(200, b"Welcome")
            self.send_header("Set-Cookie", "foo=bar")
            self.end_headers()
            self.wfile.write(b"<h1>Default GET malinfo HTTP Response</h1>")

            # close connection

        def do_POST(self):
            request_path = self.path

            # print("\n----- Request Start ----->\n")
            print("request_path : %s", request_path)

            request_headers = self.headers
            content_length = request_headers.getheaders('content-length')
            length = int(content_length[0]) if content_length else 0

            # print("length :", length)

            print("request_headers : %s" % request_headers)
            print("content : %s" % self.rfile.read(length))
            # print("<----- Request End -----\n")

            self.send_response(200)
            self.send_header("Set-Cookie", "foo=bar")
            self.end_headers()
            self.wfile.write(b"<h1>Default POST malinfo HTTP Response</h1>")

        do_PUT = do_POST
        do_DELETE = do_GET

    def __init__(self, lport=PORT, lhost=Server.ALL_INTERFACES):
        Server.__init__(self, HTTPServer.NAME, lport, lhost)

    def serve(self):
        handler = HTTPServer.RequestHandler
        httpd = socketserver.TCPServer((self.lhost, self.lport), handler)
        # httpd.handle_request()
        Server.serve_until_interrupt(httpd)


class HTTPSServer(Server):
    NAME = "https"
    PORT = 443
    KEY = "key.pem"
    CERT = "cert.pem"

    def __init__(self, lport=PORT, lhost=Server.ALL_INTERFACES):
        Server.__init__(self, HTTPSServer.NAME, lport, lhost)

    def serve(self):
        generate_cert()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(
            certfile=HTTPSServer.CERT, keyfile=HTTPSServer.KEY)
        server_address = (self.lhost, self.lport)  # CHANGE THIS IP & PORT
        handler = HTTPServer.RequestHandler
        httpd = socketserver.TCPServer(server_address, handler)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        Server.serve_until_interrupt(httpd)


# Get FTPServer running
# start all servers in Server static method and kill all servers using ctrl+c


class FTPServer(Server):
    NAME = "ftp"
    PORT = 21

    def __init__(self, lport=PORT, lhost=Server.ALL_INTERFACES):
        Server.__init__(self, FTPServer.NAME, lport, lhost)

    def serve(self):
        authorizer = DummyAuthorizer()
        with tempfile.TemporaryDirectory() as ftptemp:

            authorizer.add_user(self.username, self.password,
                                ftptemp, perm='elradfmw')
            handler = FTPHandler
            handler.authorizer = authorizer
            handler.banner = "pyftplibd based ftpd ready"
            server = FTPS(self.address, handler)
            server.max_cons = 256
            server.max_cons_per_ip = 5
            Server.serve_until_interrupt(server)


class DNSServer(Server):
    NAME = "dns"
    PORT = 53

    def __init__(self, lport=PORT, lhost=Server.ALL_INTERFACES):
        Server.__init__(self, DNSServer.NAME, lport, lhost)

    def serve(self):
        ddnsserver.start_dns(self.lport)


class ICMPServer():
    NAME = "dns"
    LOOPBACK = Server.get_interfaces()[0]

    def __init__(self, interface=LOOPBACK):
        self.interface = interface
        self.lhost = Server.get_ip_address(self.interface)

    # add feature to work on all interfaces
    def serve(self):
        ICMPack.server.start_icmp_server(self.interface)


class SSHServer(Server):
    NAME = "ssh"
    PORT = 22

    def __init__(self, lport=PORT, lhost=Server.ALL_INTERFACES):
        Server.__init__(self, SSHServer.NAME, lport, lhost)
        self.handle = SSH(self.handler, self.lhost, self.lport)

    def handler(self, command):
        if command.startswith("ls"):
            return "file1\nfile2\n"
        elif command.startswith("echo"):
            return command[4:].strip() + "\n"

    def serve(self):
        self.handle.run_blocking()


class SMTPServer(Server):
    NAME = "smtp"
    PORT = 25

    def __init__(self, lport=PORT, lhost=Server.ALL_INTERFACES):
        Server.__init__(self, SMTPServer.NAME, lport, lhost)

    def serve(self):
        nullsmtpd.nullsmtpd.start_server(self.address)


class POP3Server(Server):
    NAME = "pop3"
    PORT = 110
    SAMPLE_MESAGE = "sample_message.eml"

    def __init__(self, lport=PORT, lhost=Server.ALL_INTERFACES):
        Server.__init__(self, POP3Server.NAME, lport, lhost)

    def serve(self):
        pop3_server.serve(self.lhost, self.lport, POP3Server.SAMPLE_MESAGE)


class SMBServer(Server):
    NAME = "smb"
    PORT = 445
    SHAREPATH = os.path.expanduser("~")
    SHARENAME = "malinfo"

    def __init__(self, lport=PORT, lhost=Server.ALL_INTERFACES):
        Server.__init__(self, SMBServer.NAME, lport, lhost)

    def serve(self):
        smbserver.main(shareName=SMBServer.SHARENAME, sharePath=SMBServer.SHAREPATH,
                       ip=self.lhost, port=self.lport)


"""
ldap, kerberos, nfs
"""


def start_http_server(port=HTTPServer.PORT):
    HTTPServer(port).serve()


def start_https_server():
    HTTPSServer().serve()


def start_ftp_server(port=FTPServer.PORT):
    FTPServer(port).serve()


def start_dns_server(port=DNSServer.PORT):
    DNSServer(port).serve()


def start_icmp_server():
    ICMPServer().serve()


def start_ssh_server():
    SSHServer().serve()


def start_smtp_server():
    SMTPServer().serve()


def start_pop3_server():
    POP3Server().serve()


def start_smb_server():
    SMBServer().serve()


def start_servers():
    start_servers = [start_http_server, start_ftp_server,
                     start_dns_server, start_icmp_server,
                     start_ssh_server, start_https_server,
                     start_smtp_server, start_pop3_server,
                     start_smb_server]
    processes = []
    for server_starter in start_servers:
        processes.append(Process(target=server_starter))

    for process in processes:
        process.start()

    input("Press enter to continue")

    for process in processes:
        process.terminate()


if __name__ == "__main__":
    start_servers()
