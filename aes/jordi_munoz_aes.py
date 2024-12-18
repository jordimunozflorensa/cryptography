from cuerpo_finito import G_F
import os

class AES:
    def __init__(self, key, Polinomio_Irreducible):
        '''
        Entrada:
            key: bytearray de 16 24 o 32 bytes
            Polinomio_Irreducible: Entero que representa el polinomio para construir
            el cuerpo
        SBox: equivalente a la tabla 4, pag. 14
        InvSBOX: equivalente a la tabla 6, pag. 23
        Rcon: equivalente a la tabla 5, pag. 17
        InvMixMatrix : equivalente a la matriz usada en 5.3.3, pag. 24
        '''
        self.Polinomio_Irreducible = Polinomio_Irreducible
        self.key = key
        self.SBox = []
        self.InvSBOX = []
        self.Rcon = []
        self.InvMixMatrix = [
            [0x0e, 0x0b, 0x0d, 0x09],
            [0x09, 0x0e, 0x0b, 0x0d],
            [0x0d, 0x09, 0x0e, 0x0b],
            [0x0b, 0x0d, 0x09, 0x0e]
        ]
        self.gf = G_F(Polinomio_Irreducible)
        self.intializeSBoxInvSBOX()
        self.intializeRcon()
    
    def intializeRcon(self):
        '''
        Calcula la tabla Rcon de acuerdo con la especificación FIPS 197.
        '''
        self.Rcon = [[1, 0, 0, 0]]
        for i in range(1, 20):
            self.Rcon.append([self.gf.xTimes(self.Rcon[i-1][0]), 0, 0, 0])
        
    def intializeSBoxInvSBOX(self):
        '''
        Calcula la SBox y la InvSBox usando el inverso multiplicativo y la transformación afín
        de acuerdo con la especificación FIPS 197.
        '''
        self.SBox = [0] * 256
        self.InvSBOX = [0] * 256

        affine_matrix = [
            [1, 0, 0, 0, 1, 1, 1, 1],
            [1, 1, 0, 0, 0, 1, 1, 1],
            [1, 1, 1, 0, 0, 0, 1, 1],
            [1, 1, 1, 1, 0, 0, 0, 1],
            [1, 1, 1, 1, 1, 0, 0, 0],
            [0, 1, 1, 1, 1, 1, 0, 0],
            [0, 0, 1, 1, 1, 1, 1, 0],
            [0, 0, 0, 1, 1, 1, 1, 1]
        ]
        
        A = 0x63 

        def byte_to_bit_array(byte):
            return [(byte >> i) & 1 for i in range(8)]

        def bit_array_to_byte(bit_array):
            return sum([bit_array[i] << i for i in range(8)])

        def affine_transformation(byte):
            bit_array = byte_to_bit_array(byte)
            result = [0] * 8
            for i in range(8):
                result[i] = A >> i & 1  # Inicia con la constante A
                for j in range(8):
                    result[i] ^= affine_matrix[i][j] * bit_array[j]
            return bit_array_to_byte(result)

        for x in range(256):
            # Paso 1: Inverso multiplicativo en GF(2^8)
            inv = self.gf.inverso(x)

            # Paso 2: Aplicar la transformación afín
            self.SBox[x] = affine_transformation(inv)
            
            # Construir la tabla inversa InvSBox
            self.InvSBOX[self.SBox[x]] = x

    def print_tables(self):
        '''
        Imprime las tablas SBox e InvSBox en formato hexadecimal.
        '''
        print("SBox:")
        for i in range(0, 256, 16):
            print(" ".join(f"{x:02x}" for x in self.SBox[i:i+16]))

        print("\nInvSBOX:")
        for i in range(0, 256, 16):
            print(" ".join(f"{x:02x}" for x in self.InvSBOX[i:i+16]))
    
    def SubBytes(self, State):
        '''
        5.1.1 SUBBYTES()
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        for i in range(4):
            for j in range(4):
                State[i][j] = self.SBox[State[i][j]]
        
    def InvSubBytes(self, State):
        '''
        5.3.2 INVSUBBYTES()
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        for i in range(4):
            for j in range(4):
                State[i][j] = self.InvSBOX[State[i][j]]
        
    def ShiftRows(self, State):
        '''
        5.1.2 SHIFTROWS()
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        State[1] = State[1][1:] + State[1][:1]
        State[2] = State[2][2:] + State[2][:2]
        State[3] = State[3][3:] + State[3][:3]
        
    def InvShiftRows(self, State):
        '''
        5.3.1 INVSHIFTROWS()
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        State[1] = State[1][-1:] + State[1][:-1]
        State[2] = State[2][-2:] + State[2][:-2]
        State[3] = State[3][-3:] + State[3][:-3]
        
    def MixColumns(self, State):
        '''
        5.1.3 MIXCOLUMNS()
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        for i in range(4):
            col = State[i]
            State[i][0] = self.gf.producto(0x02, col[0]) ^ self.gf.producto(0x03, col[1]) ^ col[2] ^ col[3]
            State[i][1] = col[0] ^ self.gf.producto(0x02, col[1]) ^ self.gf.producto(0x03, col[2]) ^ col[3]
            State[i][2] = col[0] ^ col[1] ^ self.gf.producto(0x02, col[2]) ^ self.gf.producto(0x03, col[3])
            State[i][3] = self.gf.producto(0x03, col[0]) ^ col[1] ^ col[2] ^ self.gf.producto(0x02, col[3])
        
    def InvMixColumns(self, State):
        '''
        5.3.3 INVMIXCOLUMNS()
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        for i in range(4):
            col = State[i]
            State[i][0] = self.gf.producto(self.InvMixMatrix[0][0], col[0]) ^ self.gf.producto(self.InvMixMatrix[0][1], col[1]) ^ self.gf.producto(self.InvMixMatrix[0][2], col[2]) ^ self.gf.producto(self.InvMixMatrix[0][3], col[3])
            State[i][1] = self.gf.producto(self.InvMixMatrix[1][0], col[0]) ^ self.gf.producto(self.InvMixMatrix[1][1], col[1]) ^ self.gf.producto(self.InvMixMatrix[1][2], col[2]) ^ self.gf.producto(self.InvMixMatrix[1][3], col[3])
            State[i][2] = self.gf.producto(self.InvMixMatrix[2][0], col[0]) ^ self.gf.producto(self.InvMixMatrix[2][1], col[1]) ^ self.gf.producto(self.InvMixMatrix[2][2], col[2]) ^ self.gf.producto(self.InvMixMatrix[2][3], col[3])
            State[i][3] = self.gf.producto(self.InvMixMatrix[3][0], col[0]) ^ self.gf.producto(self.InvMixMatrix[3][1], col[1]) ^ self.gf.producto(self.InvMixMatrix[3][2], col[2]) ^ self.gf.producto(self.InvMixMatrix[3][3], col[3])
        
    def AddRoundKey(self, State, roundKey):
        '''
        5.1.4 ADDROUNDKEY()
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        for c in range(4):
            for r in range(4):
                State[r][c] ^= roundKey[c][r]
        
    def SubWord(self, word):
        '''
        5.2.1 SUBWORD()
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        for i in range(4):
            word[i] = self.SBox[word[i]]
            
    def RotWord(self, word):
        '''
        5.2.2 ROTWORD()
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        word.append(word.pop(0))
    
    def KeyExpansion(self, key):
        '''
        5.2 KEYEXPANSION()
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        Nk = len(key) // 4
        Nr = Nk + 6
        w = [[0, 0, 0, 0] for _ in range(4 * (Nr + 1))]

        for i in range(Nk):
            w[i] = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]

        for i in range(Nk, 4 * (Nr + 1)):
            temp = w[i - 1].copy()
            if i % Nk == 0:
                self.RotWord(temp)
                self.SubWord(temp)
                temp[0] ^= self.Rcon[i // Nk][0]
            elif Nk > 6 and i % Nk == 4:
                self.SubWord(temp)
            w[i] = [w[i - Nk][j] ^ temp[j] for j in range(4)]

        return w

        
    def Cipher(self, State, Nr, Expanded_KEY):
        '''
        5.1 Cipher(), Algorithm 1 p ́ag. 12
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        self.AddRoundKey(State, Expanded_KEY[0:4])
        for round in range(1, Nr):
            self.SubBytes(State)
            self.ShiftRows(State)
            self.MixColumns(State)
            self.AddRoundKey(State, Expanded_KEY[round*4:(round+1)*4]) #### Revisar
        
        self.SubBytes(State)
        self.ShiftRows(State)
        self.AddRoundKey(State, Expanded_KEY[Nr*4:(Nr+1)*4])
        return State
        
    def InvCipher(self, State, Nr, Expanded_KEY):
        '''
        5. InvCipher()
        Algorithm 3 p ́ag. 20 o Algorithm 4 p ́ag. 25. Son equivalentes
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        self.AddRoundKey(State, Expanded_KEY[Nr*4:(Nr+1)*4]) #### Revisar
        for round in range(Nr-1, 0, -1):
            self.InvShiftRows(State)
            self.InvSubBytes(State)
            self.AddRoundKey(State, Expanded_KEY[round*4:(round+1)*4])
            self.InvMixColumns(State)
        
        self.InvShiftRows(State)
        self.InvSubBytes(State)
        self.AddRoundKey(State, Expanded_KEY[0:4])
        return State
    
    def padding(self, data, block_size):
        '''
        Añade padding PKCS7 al data para que su longitud sea un múltiplo de block_size.
        
        Entrada:
        - data: bytearray con los datos a los que añadir padding.
        - block_size: tamaño del bloque en bytes.
        
        Salida:
        - bytearray con los datos de data más el padding añadido.
        '''
        padding = block_size - len(data) % block_size
        return data + bytearray([padding] * padding)
        
    def encrypt_file(self, fichero):
        '''
        Entrada: Nombre del fichero a cifrar
        Salida: Fichero cifrado usando la clave utilizada en el constructor de la clase.
                Para cifrar se usar ́a el modo CBC, con IV generado aleatoriamente
                y guardado en los 16 primeros bytes del fichero cifrado.
                El padding usado ser ́a PKCS7.
                El nombre de fichero cifrado ser ́a el obtenido al a~nadir el sufijo .enc
                al nombre del fichero a cifrar: NombreFichero --> NombreFichero.enc
        '''
        with open(fichero, 'rb') as f:
            plaintext = f.read()

        iv = os.urandom(16)

        padded_plaintext = self.padding(plaintext, 16)

        expanded_key = self.KeyExpansion(self.key)
        Nr = len(expanded_key) // 4 - 1

        state = [list(iv[i:i+4]) for i in range(0, 16, 4)]

        ciphertext = bytearray(iv)
        for i in range(0, len(padded_plaintext), 16):
            block = padded_plaintext[i:i+16]
            block_state = [list(block[j:j+4]) for j in range(0, 16, 4)]
            
            for row in range(4):
                for col in range(4):
                    block_state[row][col] ^= state[row][col]
            
            encrypted_block = self.Cipher(block_state, Nr, expanded_key)
            state = encrypted_block
            
            for row in encrypted_block:
                ciphertext.extend(row)
        
        with open(f"{fichero}.enc", 'wb') as f:
            f.write(ciphertext)
        
        
    def decrypt_file(self, fichero):
        '''
        Entrada: Nombre del fichero a descifrar
        Salida: Fichero descifrado usando la clave utilizada en el constructor
                de la clase.
                Para descifrar se usar ́a el modo CBC, con el IV guardado en los 16
                primeros bytes del fichero cifrado, y se eliminar ́a el padding
                PKCS7 a~nadido al cifrar el fichero.
                El nombre de fichero descifrado ser ́a el obtenido al a~nadir el sufijo .dec
                al nombre del fichero a descifrar: NombreFichero --> NombreFichero.dec
        '''
        with open(fichero, 'rb') as file:
            ciphertext = file.read()

        iv = ciphertext[:16]
        ciphertext = ciphertext[16:]
        
        expanded_key = self.KeyExpansion(self.key)
        
        Nr = len(expanded_key) // 4 - 1
        state = [list(iv[i:i+4]) for i in range(0, 16, 4)]
        
        plaintext = bytearray()
        
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            block_state = [list(block[j:j+4]) for j in range(0, 16, 4)] 
            decrypted_block = self.InvCipher(block_state, Nr, expanded_key)
            
            for row in range(4):
                for col in range(4):
                    decrypted_block[row][col] ^= state[row][col]

            state = block_state

            for row in decrypted_block:
                plaintext.extend(row)
        
        print("Last 16 bytes: ", plaintext[-16:])
        padding_length = plaintext[-1]
        print(padding_length)
        plaintext = plaintext[:-padding_length]
        print("Last 16 bytes: ", plaintext[-16:])

        fichero = fichero[:-4] # elimino la extensión .enc
        with open(f"{fichero}.dec", 'wb') as file:
            file.write(plaintext)
        
def main():
    return    
    ################################## Desencriptación 1 ##################################
    
    # # mandril.png_0x11b_184d0214afe945d315339b6d92b01c0f.enc
    # key = bytearray([0x18, 0x4d, 0x02, 0x14, 0xaf, 0xe9, 0x45, 0xd3, 0x15, 0x33, 0x9b, 0x6d, 0x92, 0xb0, 0x1c, 0x0f])
    # Polinomio_Irreducible = 0x11b

    # aes = AES(key, Polinomio_Irreducible)
    # aes.decrypt_file('mandril.png_0x11b_184d0214afe945d315339b6d92b01c0f.enc')

    ################################## Desencriptación 2 ##################################
    
    # # mandril.png_0x11d_a26d65fdd2fea302638290cdd2cbf626.enc
    # key = bytearray([0xa2, 0x6d, 0x65, 0xfd, 0xd2, 0xfe, 0xa3, 0x02, 0x63, 0x82, 0x90, 0xcd, 0xd2, 0xcb, 0xf6, 0x26])
    # Polinomio_Irreducible = 0x11d
    
    # aes = AES(key, Polinomio_Irreducible)
    # aes.decrypt_file('mandril.png_0x11d_a26d65fdd2fea302638290cdd2cbf626.enc')
    
    ################################## Encriptación 1 ##################################
    
    # # mandril png
    # key = bytearray([0x18, 0x4d, 0x02, 0x14, 0xaf, 0xe9, 0x45, 0xd3, 0x15, 0x33, 0x9b, 0x6d, 0x92, 0xb0, 0x1c, 0x0f])
    # Polinomio_Irreducible = 0x11b
    
    # aes = AES(key, Polinomio_Irreducible)
    # aes.encrypt_file('mandril.png')
        
if __name__ == "__main__":
    main()