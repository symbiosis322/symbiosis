# coding: utf-8

'''
Created on 2015. 1. 21.

@summary: Symbiosis Library
'''

# Import
import socket
import select

from Crypto.Hash import SHA256



# Debug Mode
DEBUG = True




# Timeout
TIMEOUT = 0.01




# Symbiosis

# Symbiosis Port
SYMBIOSIS_PORT = 27000

SYMBIOSIS_BEE_PORT          = SYMBIOSIS_PORT + 1
SYMBIOSIS_FLOWER_PORT       = SYMBIOSIS_PORT + 2
SYMBIOSIS_SERVER_PORT       = SYMBIOSIS_PORT + 3
SYMBIOSIS_DEFLECTOR_PORT    = SYMBIOSIS_PORT + 4
SYMBIOSIS_BYPASS_PORT       = SYMBIOSIS_PORT + 5

# Symbiosis Cell Type
SYMBIOSIS_CELL_TYPE_REQUEST         = 0
SYMBIOSIS_CELL_TYPE_RESPONSE        = 1
SYMBIOSIS_CELL_TYPE_KEY_REQUEST     = 2
SYMBIOSIS_CELL_TYPE_KEY_RESPONSE    = 3

# Symbiosis Mode
SYMBIOSIS_MODE = ('Bee', 'Flower', 'Server', 'Master')




# Stream
class Stream:
    
    def __init__(self):
        DEBUG_POSITION = 'Symbiosis:Stream:Init:'
        
        self.streams = {}
        
        
    def connect(self, host, port, streamID):
        DEBUG_POSITION = 'Symbiosis:Stream:Connect:'

        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            conn.connect((host, port))
        except socket.error as e:
            if DEBUG: print(DEBUG_POSITION, 'Host와의 연결에 실패하였습니다:')
            if DEBUG: print(e)
            return False
        
        self.streams[streamID] = conn
        
        return True
        
        
    def send(self, streamID, data):
        DEBUG_POSITION = 'Symbiosis:Stream:Send:'
        
        if not streamID in self.streams.keys(): return False
        
        # Exception 처리 : stream이 닫혀있으면 보낼 수 없음
        self.streams[streamID].send(data)
        
        return True
    
    
    def add(self, conn, index=-1):
        DEBUG_POSITION = 'Symbiosis:Stream:Add:'
        
        try:
            if index < 0:
                index = 0
                while self.streams[index]: index += 1
            else:
                if self.streams[index]:
                    self.streams[index].close()
        except KeyError:
            pass
        self.streams[index] = conn
        
    
    def select(self, dest, cell_type, aes, hash_key):
        DEBUG_POSITION = 'Symbiosis:Stream:Select:'
        
        if len(self.streams) == 0: return
        
        timeout = TIMEOUT
        
        (read, _, exception) = select.select(list(self.streams.values()), [], list(self.streams.values()), timeout)
        
        if exception:
            if DEBUG: print(DEBUG_POSITION, 'select exception이 발생했습니다:')
            if DEBUG: print(exception)
            return
        elif read:
            for i in read:
                data = b''
                try:
                    data = i.recv(976)
                except socket.error as e:
                    if DEBUG: print(DEBUG_POSITION, '소켓이 닫혀있습니다.')
                    self.streams[self.getID(i)].close()
                    del self.streams[self.getID(i)]
                    continue
                
                if len(data) == 0: continue
                
                try:
                    print('BROWSER REQ > FLOWER > BEE:', len(data))

                    # Digest
                    digest = SHA256.new(data + hash_key).digest()

                    # Encrypt
                    encrypted = b''
                    while len(data) >= 16:
                        len(data[:16])
                        encrypted = encrypted + aes.encrypt(data[:16])
                        data = data[16:]
                    encrypted = encrypted + data

                    # Send Cell
                    dest.send(encodeCell(cell_type, len(encrypted), self.getID(i), digest, encrypted))
                except socket.error as e:
                    if DEBUG: print(DEBUG_POSITION, '예기치 못한 에러:', e)
                    continue    
        
    def getID(self, conn):
        DEBUG_POSITION = 'Symbiosis:Stream:GetID:'

        for k in self.streams.keys():
            if self.streams[k] == conn:
                return k
        return None
    
    
    def clear(self):
        DEBUG_POSITION = 'Symbiosis:Stream:Clear:'
        
        for k in self.streams.keys():
            self.streams[k].close()
        self.streams.clear()
        



# Cell

# Cell Format
# ( Type:1, Length:2, StreamID:2, Digest:32, Data:987 )

# Encode Cell
def encodeCell(cell_type, length, streamID, digest, data):
    pad = b''
    if len(data) < 987: pad = bytes(987 - len(data))
    return bytes([cell_type, int(length / 256), length % 256, int(streamID / 256), streamID % 256]) + digest + data + pad

# Decode Cell
def decodeCell(data):
    cell = {}
    cell['type'] = data[0]
    cell['length'] = int.from_bytes(data[1:3], 'big')
    cell['streamID'] = int.from_bytes(data[3:5], 'big')
    cell['digest'] = data[5:37]
    cell['data'] = data[37:37 + cell['length']]
    return cell

# Print Cell
def printCell(cell):
    print('-' * 20)
    print('type:', cell['type'], end='\t\t')
    print('length:', cell['length'], end='\t')
    print('streamID:', cell['streamID'])
    print('digest:', cell['digest'])
    print('data:', cell['data'])
    print('-' * 20)