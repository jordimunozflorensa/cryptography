from cuerpo_finito import G_F
import random

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
        tmp = ""
        for i in self.key:
            hexa = f"{i:02x}"
            tmp+= hexa[:2]
        self.key = tmp
        
        self.Nb = 0
        self.Nk = 0
        self.Nr = 0

        if len(self.key) == 32:
            self.Nb = 4 
            self.Nk = 4 
            self.Nr = 10
        elif len(self.key) == 48:
            self.Nb = 4; self.Nk = 6; self.Nr = 12
        elif len(self.key) == 64:
            self.Nb = 4; self.Nk = 8; self.Nr = 14
        
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
                result[i] = A >> i & 1
                for j in range(8):
                    result[i] ^= affine_matrix[i][j] * bit_array[j]
            return bit_array_to_byte(result)

        for x in range(256):
            inv = self.gf.inverso(x)
            self.SBox[x] = affine_transformation(inv)
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
        for c in range(4):
            s0 = State[0][c]
            s1 = State[1][c]
            s2 = State[2][c]
            s3 = State[3][c]

            new_s0 = self.gf.producto(s0, 0x02) ^ self.gf.producto(s1, 0x03) ^ s2 ^ s3
            new_s1 = s0 ^ self.gf.producto(s1, 0x02) ^ self.gf.producto(s2, 0x03) ^ s3
            new_s2 = s0 ^ s1 ^ self.gf.producto(s2, 0x02) ^ self.gf.producto(s3, 0x03)
            new_s3 = self.gf.producto(s0, 0x03) ^ s1 ^ s2 ^ self.gf.producto(s3, 0x02)

            State[0][c] = new_s0
            State[1][c] = new_s1
            State[2][c] = new_s2
            State[3][c] = new_s3
        
    def InvMixColumns(self, State):
        '''
        5.3.3 INVMIXCOLUMNS()
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        for c in range(4):
            s0 = State[0][c]
            s1 = State[1][c]
            s2 = State[2][c]
            s3 = State[3][c]

            new_s0 = self.gf.producto(s0, self.InvMixMatrix[0][0]) ^ self.gf.producto(s1, self.InvMixMatrix[0][1]) ^ self.gf.producto(s2, self.InvMixMatrix[0][2]) ^ self.gf.producto(s3, self.InvMixMatrix[0][3])
            new_s1 = self.gf.producto(s0, self.InvMixMatrix[1][0]) ^ self.gf.producto(s1, self.InvMixMatrix[1][1]) ^ self.gf.producto(s2, self.InvMixMatrix[1][2]) ^ self.gf.producto(s3, self.InvMixMatrix[1][3])
            new_s2 = self.gf.producto(s0, self.InvMixMatrix[2][0]) ^ self.gf.producto(s1, self.InvMixMatrix[2][1]) ^ self.gf.producto(s2, self.InvMixMatrix[2][2]) ^ self.gf.producto(s3, self.InvMixMatrix[2][3])
            new_s3 = self.gf.producto(s0, self.InvMixMatrix[3][0]) ^ self.gf.producto(s1, self.InvMixMatrix[3][1]) ^ self.gf.producto(s2, self.InvMixMatrix[3][2]) ^ self.gf.producto(s3, self.InvMixMatrix[3][3])

            State[0][c] = new_s0
            State[1][c] = new_s1
            State[2][c] = new_s2
            State[3][c] = new_s3
        
    def AddRoundKey(self, State, roundKey):
        '''
        5.1.4 ADDROUNDKEY()
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        for r in range(4):
            for c in range(4):
                State[r][c] ^= roundKey[r][c]
        
    def SubWord(self, word):
        '''
        5.2.1 SUBWORD()
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        return [self.SBox[b] for b in word]
            
    def RotWord(self, word):
        '''
        5.2.2 ROTWORD()
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        return word[1:] + word[:1]    

    def KeyExpansion(self, key):
        '''
        5.2 KEYEXPANSION()
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        key_symbols = [int(key[i:i+2], 16) for i in range(0, len(key), 2)]
        expanded_key = [[0 for _ in range(4 * (self.Nr+1))] for _ in range(4)]
        
        for i in range(self.Nk):
            for j in range(4):
                expanded_key[j][i] = key_symbols[i * 4 + j]

        i = self.Nk
        while i < 4 * (self.Nr + 1):
            temp = [expanded_key[row][i-1] for row in range(4)]
            if i % self.Nk == 0:
                temp = self.SubWord(self.RotWord(temp))
                for j in range(4):
                    temp[j] ^= self.Rcon[i // self.Nk - 1][j]
            elif self.Nk > 6 and i % self.Nk == 4:
                temp = self.SubWord(temp)

            for row in range(4):
                expanded_key[row][i] = expanded_key[row][i - self.Nk] ^ temp[row]
            i += 1

        return expanded_key

        
    def Cipher(self, State, Nr, Expanded_KEY):
        '''
        5.1 Cipher(), Algorithm 1 p ́ag. 12
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        size = len(State[0])
        self.AddRoundKey(State, Expanded_KEY[0:4])
        
        for round in range(1, Nr):
            self.SubBytes(State)
            self.ShiftRows(State)
            self.MixColumns(State)
            self.AddRoundKey(State, [fila[size*round:size*(round+1)] for fila in Expanded_KEY])
        
        self.SubBytes(State)
        self.ShiftRows(State)    
        self.AddRoundKey(State, [fila[size*(Nr):size*(Nr+1)] for fila in Expanded_KEY])
        return State
        
    def InvCipher(self, State, Nr, Expanded_KEY):
        '''
        5. InvCipher()
        Algorithm 3 p ́ag. 20 o Algorithm 4 p ́ag. 25. Son equivalentes
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        size = len(State[0])
        self.AddRoundKey(State, [fila[size*(Nr):size*(Nr+1)] for fila in Expanded_KEY])
        for round in range(Nr-1, 0, -1):
            self.InvShiftRows(State)
            self.InvSubBytes(State)
            self.AddRoundKey(State, [fila[size*round:size*(round+1)] for fila in Expanded_KEY])
            self.InvMixColumns(State)
        
        self.InvShiftRows(State)
        self.InvSubBytes(State)
        self.AddRoundKey(State, Expanded_KEY[0:size])
        
        return State
    
    def	convertFileToBytes(self, file):		 							
        matriu = []
        fila_actual = []
        for element in file:
            fila_actual.append(element)
            if len(fila_actual) == self.Nb:
                matriu.append(fila_actual)
                fila_actual = []
        if fila_actual:
            matriu.append(fila_actual)
        return matriu
    
    def addPadding(self, data, block_size):
        padding_size = block_size - (len(data) % block_size)
        padding = bytes([padding_size] * padding_size)
        return bytes(data) + padding
    
    def encrypt_file(self, file):
        '''
        Entrada: Nombre del fichero a cifrar
        Salida: Fichero cifrado usando la clave utilizada en el constructor
        de la clase.
        Para cifrar se usara el modo CBC, con IV generado aleatoriamente
        y guardado en los 16 primeros bytes del fichero cifrado.
        El padding usado sera PKCS7.
        El nombre de fichero cifrado sera el obtenido al a~nadir el sufijo .enc
        al nombre del fichero a cifrar: NombreFichero --> NombreFichero.enc
        '''
        with open(file, "rb") as f:
            file_data = f.read()

        expanded_key = self.KeyExpansion(self.key)
        padded_data = self.addPadding(file_data, self.Nb * 4)
        states = self.convertFileToBytes(padded_data)

        iv = [[random.randint(0, 255) for _ in range(4)] for _ in range(4)]
        resultat = bytearray(iv[i][j] for j in range(4) for i in range(4))

        for i in range(0, len(states), self.Nb):
            state = [list(row) for row in zip(*states[i:i+4])]

            for row in range(4):
                for col in range(4):
                    state[row][col] ^= iv[row][col]
            
            state = self.Cipher(state, self.Nr, expanded_key)
            iv = state

            resultat.extend(state[i][j] for j in range(4) for i in range(4))

        with open(file + ".enc", "wb") as f:
            f.write(resultat)


    def decrypt_file(self, file):
        '''
        Entrada: Nombre del fichero a descifrar
        Salida: Fichero descifrado usando la clave utilizada en el constructor
        de la clase.
        Para descifrar se usara el modo CBC, con el IV guardado en los 16
        primeros bytes del fichero cifrado, y se eliminara el padding
        PKCS7 a~nadido al cifrar el fichero.
        El nombre de fichero descifrado sera el obtenido al a~nadir el sufijo .dec
        al nombre del fichero a descifrar: NombreFichero --> NombreFichero.dec
        '''
        with open(file, "rb") as f:
            file_data = f.read()

        expanded_key = self.KeyExpansion(self.key)
        iv = file_data[:16]
        ciphertext = file_data[16:]

        decrypted_data = bytearray()
        previous_block = iv

        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            state = [[block[j*4 + i] for j in range(4)] for i in range(4)]
            state = self.InvCipher(state, self.Nr, expanded_key)
            
            for row in range(4):
                for col in range(4):
                    state[row][col] ^= previous_block[row + col * 4]
            
            previous_block = block

            for j in range(4):
                for k in range(4):
                    decrypted_data.append(state[k][j])

        pad = decrypted_data[-1]
        decrypted_data = decrypted_data[:-pad]

        with open(file + ".dec", "wb") as f:
            f.write(decrypted_data)