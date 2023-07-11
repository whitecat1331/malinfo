import click
from http.server import BaseHTTPRequestHandler
import socketserver
import json
from selectors import DefaultSelector, EVENT_READ
import socket
from abc import ABC, abstractmethod


class Server(ABC):

    ALL_INTERFACES = '0.0.0.0'

    def __init__(self, name, lport, lhost=ALL_INTERFACES, username="anonymous", password="anonymous"):
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
            print("Starting Servers: Use ctrl+c to stop servers.")
            daemon.serve_forever()
        except KeyboardInterrupt:
            click.echo("KeyboardInterrupt: Shutting Servers Down")

    @abstractmethod
    def serve(self):
        pass

    @abstractmethod
    def handle(self):
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
            self.wfile.write(b"Hello World")

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
            self.wfile.write(json.dumps({'hello': 'world', 'received': 'ok'}))

        do_PUT = do_POST
        do_DELETE = do_GET

    def __init__(self, port=PORT):
        Server.__init__(self, HTTPServer.NAME, port)

    def serve(self):
        handler = HTTPServer.RequestHandler
        httpd = socketserver.TCPServer((self.lhost, self.lport), handler)
        # httpd.handle_request()
        Server.serve_until_interrupt(httpd)

    def handle(self):
        pass


"""
class FTPServer(Server):
    SERVER_NAME = "ftp"

    def __init__(self, lport, lhost=''):
        Server.__init__(self, lport, lhost)

    def __enter__(self):
        Server.start_server(self)
        authorizer = DummyAuthorizer()
        authorizer.add_user(self.username, self.password,
                            os.getcwd(), perm='elradfmw')
        handler = FTPHandler
        handler.authorizer = authorizer
        handler.banner = "pyftplibd based ftpd ready"
        address = (self.lhost, self.lport)
        server = FTPS(address, handler)
        server.max_cons = 256
        server.max_cons_per_ip = 5
        Server.serve_until_interrupt(self, server)


class NFSServer(Server):
    pass


class SMBServer(Server):
    pass

"""


def main():
    HTTPServer().serve()


if __name__ == "__main__":
    main()