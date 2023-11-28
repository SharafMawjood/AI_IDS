import socket
import os


HOST = socket.gethostbyname(socket.gethostname())
proxy = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
