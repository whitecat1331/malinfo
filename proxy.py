import click
from http.server import BaseHTTPRequestHandler
import socketserver
from multiprocessing import Process
import socket
import os
from abc import ABC, abstractmethod
from pyftpdlib.handlers import FTPHandler, ThrottledDTPHandler
from pyftpdlib.servers import FTPServer as FTPS
from pyftpdlib.authorizers import DummyAuthorizer
import tempfile
import shutil


class Server(ABC):

    ALL_INTERFACES = '0.0.0.0'

    def __init__(self, name, lport, lhost, username="anonymous", password="anonymous"):
        self.lport = lport
        self.lhost = lhost
        self.username = username
        self.password = password

    def log_start(self):
        click.echo(
            f"Starting {self.__class__.__name__} on {self.lhost}:{self.lport}")

    def log_exit(self):
        click.echo(
            f"Closing {self.__class__.__name__} on {self.lhost}:{self.lport}")

    def log_traffic(self):
        pass

    @staticmethod
    def serve_until_interrupt(daemon):
        try:
            print("Starting Server")
            daemon.serve_forever()
        except KeyboardInterrupt:
            click.echo("KeyboardInterrupt: Shutting Server Down")

    @abstractmethod
    def serve(self):
        pass


class HTTPServer(Server, BaseHTTPRequestHandler):
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
            address = (self.lhost, self.lport)
            server = FTPS(address, handler)
            server.max_cons = 256
            server.max_cons_per_ip = 5
            Server.serve_until_interrupt(server)


"""
class DNSServer(Server):
    pass


class NFSServer(Server):
    pass


class SMBServer(Server):
    pass

"""


def start_http_server(port=HTTPServer.PORT):
    HTTPServer(port).serve()


def start_ftp_server(port=FTPServer.PORT):
    FTPServer(port).serve()


def main():
    p = Process(target=start_http_server)
    j = Process(target=start_ftp_server)
    print("Start")
    j.start(), p.start()
    print("stop")
    input()
    j.terminate(), p.terminate()
    print("end")


if __name__ == "__main__":
    main()
