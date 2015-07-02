# coding: utf-8

'''
Created on 2015. 1. 25.

@summary: Symbiosis Server
'''

# Import
import _thread
import select
import socket
import hashlib

from symbiosis import SYMBIOSIS_MODE, decodeCell, Stream, SYMBIOSIS_SERVER_PORT,\
    TIMEOUT, printCell, SYMBIOSIS_CELL_TYPE_RESPONSE,\
    SYMBIOSIS_CELL_TYPE_REQUEST, SYMBIOSIS_CELL_TYPE_KEY_REQUEST, encodeCell,\
    SYMBIOSIS_CELL_TYPE_KEY_RESPONSE

from diffie_hellman import DiffieHellman




# Debug Mode
DEBUG = True




# Server
class Server:
    
    def __init__(self):
        DEBUG_POSITION = 'Symbiosis_Server:Server:Init:'
        
        self.running = True
        
        # Flower Listener Socket
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Diffie Hellman
        self.exchange = False

        # Stream
        self.stream = Stream()
    
    
    def run(self):
        DEBUG_POSITION = 'Symbiosis_Server:Server:Run:'
    
        try:
            # Listen to Flower
            self.listener.bind(('', SYMBIOSIS_SERVER_PORT))
            self.listener.listen(5)
            
            if DEBUG: print('Flower를 기다리는 중...')
            while self.running:
                # Accept Flower
                flower, _ = self.listener.accept()
                
                if DEBUG: print('Flower와 연결되었습니다.')
                
                # Handle Flower
                _thread.start_new_thread(self.handle, (flower,))
                
        except socket.error as e:
            if self.listener:
                self.listener.close()
                self.listener = None
            if DEBUG: print('Flower를 기다리던 도중 오류가 발생했습니다:')
            if DEBUG: print(e)
    
    
    def handle(self, flower):
        DEBUG_POSITION = 'Symbiosis_Server:Server:Handle:'
        
        dh = DiffieHellman()
        
        data_proxy = b''

        timeout = TIMEOUT
        while self.running:
            (read, _, exception) = select.select([flower], [], [flower], timeout)
            if exception:
                if DEBUG: print(DEBUG_POSITION, 'select exception이 발생했습니다:')
                if DEBUG: print(exception)
                return
            elif read:
                for i in read:
                    try:
                        # Receive Data
                        data_proxy = data_proxy + i.recv(1024)

                        if len(data_proxy) >= 1024:
                            # Raw Cell
                            raw_cell, data_proxy = data_proxy[0:1024], data_proxy[1024:]

                            # Decode Cell
                            cell = decodeCell(raw_cell)

                            if cell['type'] == SYMBIOSIS_CELL_TYPE_REQUEST:
                                # Connect to Squid with streamID
                                if not cell['streamID'] in self.stream.streams.keys():
                                    if self.stream.connect('localhost', 3128, cell['streamID']) == False:
                                        if DEBUG: print(DEBUG_POSITION, 'Squid에 연결할 수 없습니다.')
                                        continue
                                    
                                # Send Data
                                self.stream.send(cell['streamID'], cell['data'])
                            elif cell['type'] == SYMBIOSIS_CELL_TYPE_KEY_REQUEST:
                                print("KEY REQUEST!!!!")
                                g_x = cell['data']
                                
                                # g_y
                                g_y = dh.publicKey
                                
                                # H(K)
                                dh.genKey(int.from_bytes(g_x, byteorder='big'))
                                
                                aes = AES.new(dh.getKey(), AES.MODE_ECB)
                                self.exchange = True

                                h = hashlib.sha256()
                                h.update(str(dh.getKey()).encode(encoding='utf_8', errors='strict'))
                                h_k = h.digest()
                                
                                data = dh.publicKey.to_bytes((dh.publicKey.bit_length() + 7) // 8, 'big') + h_k
                                flower.send(encodeCell(SYMBIOSIS_CELL_TYPE_KEY_RESPONSE, len(data), 0, bytes(32), data))

                    except socket.error as e:
                            if DEBUG: print(DEBUG_POSITION, '알 수 없는 오류가 발생했습니다:')
                            if DEBUG: print(e)
                            return
            
            if self.exchange == True:
                self.stream.select(flower, SYMBIOSIS_CELL_TYPE_RESPONSE, aes)




# Main
if __name__ == '__main__':
    # Symbiosis : Server
    if DEBUG: print('Start of Symbiosis:', SYMBIOSIS_MODE[2])
    if DEBUG: print()
    
    
    # Server
    server = Server()
    server.run()
    
    
    if DEBUG: print()
    if DEBUG: print('End of Symbiosis')