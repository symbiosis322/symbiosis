# coding: utf-8

'''
Created on 2015. 1. 21.

@summary: Symbiosis Bee
'''

# Import
import _thread
import select
import socket
import hashlib

from Crypto.Cipher import AES

from diffie_hellman import DiffieHellman

from symbiosis import SYMBIOSIS_MODE, decodeCell, SYMBIOSIS_FLOWER_PORT, \
    Stream, SYMBIOSIS_BEE_PORT, TIMEOUT, SYMBIOSIS_DEFLECTOR_PORT, \
    SYMBIOSIS_CELL_TYPE_REQUEST, SYMBIOSIS_CELL_TYPE_RESPONSE, \
    SYMBIOSIS_SERVER_PORT, printCell, SYMBIOSIS_CELL_TYPE_KEY_REQUEST,\
    encodeCell, SYMBIOSIS_CELL_TYPE_KEY_RESPONSE



# Debug Mode
DEBUG = True




# Bee
class Bee:
    
    def __init__(self):
        DEBUG_POSITION = 'Symbiosis_Bee:Bee:Init:'
        self.alive = True
        
        # Flower Socket
        self.flower = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Deflector Socket
        self.deflector = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Diffie Hellman
        self.dh = DiffieHellman()
        self.exchange = False
        
        # Stream
        self.stream = Stream()
        
    
    def fly(self, flower_host, flower_port, deflector_host, deflector_port):
        DEBUG_POSITION = 'Symbiosis_Bee:Bee:Fly:'
        
        # Connect to Deflector
        try:
            self.deflector.connect((deflector_host, deflector_port))
        except socket.error as e:
            if DEBUG: print(DEBUG_POSITION, 'Deflector와의 연결에 실패하였습니다:')
            if DEBUG: print(e)
            return
        
        # Connect to Flower
        try:
            self.flower.connect((flower_host, flower_port))
        except socket.error as e:
            if DEBUG: print(DEBUG_POSITION, 'Flower와의 연결에 실패하였습니다:')
            if DEBUG: print(e)
            return
        
        

        if DEBUG: print('Key Exchange: Start')
        self.exchange = False
        
        # Key Exchange
        data = self.dh.publicKey.to_bytes((self.dh.publicKey.bit_length() + 7) // 8, 'big')
        self.flower.send(encodeCell(SYMBIOSIS_CELL_TYPE_KEY_REQUEST, len(data), 0, bytes(32), data))
       
        
        
        # Catch : Select
        _thread.start_new_thread(self.catch, (self.flower, self.deflector))
        
        # Feel : Browsing
        self.feel()
        
        # Die
        self.die()
        
    
    def feel(self):
        DEBUG_POSITION = 'Symbiosis_Bee:Bee:Feel:'
        
        try:
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(('', SYMBIOSIS_BEE_PORT))
            listener.listen(5)
            
            while self.alive:
                if self.exchange == False: continue
                
                # Accept
                conn, _ = listener.accept()
                
                # Stream
                self.stream.add(conn)
                
        except socket.error as e:
            if listener:
                listener.close()
            if DEBUG: print(DEBUG_POSITION, 'Browser의 요청을 기다리던 도중 오류가 발생했습니다:')
            if DEBUG: print(e)
        
    
    def catch(self, flower, deflector):
        DEBUG_POSITION = 'Symbiosis_Bee:Bee:Catch:'
        
        data_flower = b''
        data_deflector = b''
        
        timeout = TIMEOUT
        while self.alive:
            (read, _, exception) = select.select([flower, deflector], [], [flower, deflector], timeout)
            if exception:
                if DEBUG: print(DEBUG_POSITION, 'select exception이 발생했습니다:')
                if DEBUG: print(exception)
                return
            elif read:
                for i in read:
                    if i == flower:
                        try:
                            # Receive Data
                            data_flower = data_flower + i.recv(1024)
                            
                            if len(data_flower) >= 1024:
                                # Raw Cell
                                raw_cell, data_flower = data_flower[0:1024], data_flower[1024:]
                                
                                # Decode Cell
                                cell = decodeCell(raw_cell)
                                #printCell(cell)
                                
                                if cell['type'] == SYMBIOSIS_CELL_TYPE_RESPONSE:
                                    # Flower Response
                                    h = hashlib.sha256()
                                    h.update(cell['data'])
                                    if cell['digest'] == h.digest():
                                        self.stream.send(cell['streamID'], aes.decrypt(cell['data']))
                                elif cell['type'] == SYMBIOSIS_CELL_TYPE_REQUEST:
                                    # Flower Request
                                    print('FLOWER REQ > BEE > DEFLECTOR:')
                                    #printCell(cell)
                                    deflector.send(raw_cell)
                                    pass
                                elif cell['type'] == SYMBIOSIS_CELL_TYPE_KEY_REQUEST:
                                    # Flower Key Request
                                    deflector.send(raw_cell)
                                elif cell['type'] == SYMBIOSIS_CELL_TYPE_KEY_RESPONSE:
                                    g_y = cell['data'][:512]
                                    h_k = cell['data'][512:576]
                                    c = cell['data'][576:]
                                    
                                    # Check Certificate : c
                                    # Check H(g_y) : g_y
                                    
                                    self.dh.genKey(int.from_bytes(g_y, byteorder='big'))
                                    
                                    h = hashlib.sha256()
                                    h.update(str(self.dh.getKey()).encode(encoding='utf_8', errors='strict'))
                                    if h_k == h.digest():
                                        print("Key Exchange: Complete")
                                        aes = AES.new(self.dh.getKey(), AES.MODE_ECB)
                                        self.exchange = True
                                    else:
                                        data = self.dh.publicKey.to_bytes((self.dh.publicKey.bit_length() + 7) // 8, 'big')
                                        self.flower.send(encodeCell(SYMBIOSIS_CELL_TYPE_KEY_REQUEST, len(data), 0, bytes(32), data))
                                    pass
                        except socket.error as e:
                            if DEBUG: print(DEBUG_POSITION, '알 수 없는 오류가 발생했습니다:flower')
                            if DEBUG: print(e)
                            return
                    elif i == deflector:
                        try:
                            # Receive Data
                            data_deflector = data_deflector + i.recv(1024)
                            
                            if len(data_deflector) >= 1024:
                                # Raw Cell
                                raw_cell, data_deflector = data_deflector[0:1024], data_deflector[1024:]
                                
                                # Deflector Response
                                print('DEFLECTOR RES > BEE > FLOWER')
                                flower.send(raw_cell)
                        except socket.error as e:
                            if DEBUG: print(DEBUG_POSITION, '알 수 없는 오류가 발생했습니다:deflector')
                            if DEBUG: print(e)
                            return
            if self.exchange == True:
                self.stream.select(flower, SYMBIOSIS_CELL_TYPE_REQUEST, aes)
                        
        
    
    def die(self):
        DEBUG_POSITION = 'Symbiosis_Bee:Bee:Die:'
        
        self.alive = False
        self.stream.clear()
        self.stream = None
        self.deflector.close()
        self.deflector = None
        self.flower.close()
        self.flower = None
        



# Main
if __name__ == '__main__':
    # Symbiosis : Bee
    if DEBUG: print('Start of Symbiosis:', SYMBIOSIS_MODE[0])
    if DEBUG: print()
    

    # Bee
    bee = Bee()
    # bee.fly('flower.Symbiosis.CAT.emulab.net', SYMBIOSIS_FLOWER_PORT, 'deflector.Symbiosis.CAT.emulab.net', SYMBIOSIS_DEFLECTOR_PORT)

    # usage: bee.fly( <SYMBIOSIS_FLOWER_IP>, SYMBIOSIS_FLOWER_PORT, <SYMBIOSIS_DEFLECTOR_IP>, SYMBIOSIS_DEFLECTOR_PORT)

    
    if DEBUG: print()
    if DEBUG: print('End of Symbiosis')