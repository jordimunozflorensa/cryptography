from cuerpo_finito import G_F

class AES:
    def __init__(self, key, Polinomio_Irreducible=0x11B):
        '''
        Inicializa el AES con la clave y genera las tablas SBox e InvSBox.
        '''
        self.Polinomio_Irreducible = Polinomio_Irreducible
        self.SBox = []
        self.InvSBOX = []
        self.gf = G_F(Polinomio_Irreducible)
        self.calculateSBoxInvSBOX()

    def calculateSBoxInvSBOX(self):
        '''
        Calcula la SBox y la InvSBox usando el inverso multiplicativo y la transformación afín
        de acuerdo con la especificación FIPS 197.
        '''
        self.SBox = [0] * 256
        self.InvSBOX = [0] * 256

        # Matriz de transformación afín, tal como se muestra en la ecuación 5.4
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
        
        # Constante binaria (0b01100011 == 0x63) que se suma en la transformación afín
        A = 0x63

        def byte_to_bit_array(byte):
            '''Convierte un byte en un arreglo de bits.'''
            return [(byte >> i) & 1 for i in range(8)]

        def bit_array_to_byte(bit_array):
            '''Convierte un arreglo de bits en un byte.'''
            return sum([bit_array[i] << i for i in range(8)])

        def affine_transformation(byte):
            '''Aplica la transformación afín al byte dado.'''
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


def main():
    key = bytearray([0x00] * 16)  # Clave de ejemplo de 16 bytes (se puede cambiar)
    aes = AES(key)
    aes.print_tables()

if __name__ == "__main__":
    main()

