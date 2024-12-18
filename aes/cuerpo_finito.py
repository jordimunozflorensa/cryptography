class G_F:
    def __init__(self, Polinomio_Irreducible=0x100000000000000000000000000000087):
        '''
        Inicializa el cuerpo finito usando un polinomio irreducible dado y un generador g = 3.
        
        Entrada:
        - Polinomio_Irreducible: entero que representa el polinomio irreducible para generar el cuerpo.
        
        Crea las tablas Tabla_EXP y Tabla_LOG que permiten realizar operaciones de multiplicación e inversos 
        de manera eficiente con g = 3 como generador del cuerpo.
        '''
        self.Polinomio_Irreducible = Polinomio_Irreducible
        self.Tabla_EXP = [0] * 256
        self.Tabla_LOG = [0] * 256 

        self.Tabla_EXP[0] = 1
        self.Tabla_LOG[1] = 0
        self.Tabla_LOG[0] = 255
        
        found = False
        g = 2
        while not found:
            i = 1
            res = g
            while i < 255 and res != 1:
                self.Tabla_EXP[i] = res
                self.Tabla_LOG[self.Tabla_EXP[i]] = i
                res = self.producto_polinomios(res, g)
                i += 1
                
            if i == 255: 
                found = True
            else:
                g += 1
                
        self.Tabla_EXP[255] = self.Tabla_EXP[0]
        print(f"Generador del cuerpo finito: {g}")
        
    def print_tables(self):
        '''
        Funcion auxiliar que muestra el resultado de las tablas EXP y LOG
        '''
        print("Tabla_EXP:")
        for i in range(0, 256, 16):
            print(" ".join(f"{x:02x}" for x in self.Tabla_EXP[i:i+16]))

        print("\nTabla_LOG:")
        for i in range(0, 256, 16):
            print(" ".join(f"{x:02x}" for x in self.Tabla_LOG[i:i+16]))
        
    def producto_polinomios(self, a, b):
        '''
        Multiplica dos polinomios en GF(2^8) y los reduce usando el polinomio irreducible.
        
        Entrada:
        - a: entero que representa el primer polinomio.
        - b: entero que representa el segundo polinomio.
        
        Salida:
        - El producto de a y b reducido por el polinomio irreducible.
        '''
        result = 0
        while b > 0:
            if b & 1:
                result ^= a
            a <<= 1
            if a & 0x100:
                a ^= self.Polinomio_Irreducible
            b >>= 1
        return result & 0xFF
        
    def division(self, a, b):
        '''
        Calcula la división de dos elementos en el cuerpo finito GF(2^8) usando las tablas EXP y LOG.
        
        Entrada:
        - a: entero entre 0 y 255.
        - b: entero entre 0 y 255.
        
        Salida:
        - El cociente de a y b en GF(2^8).
        '''
        if a == 0:
            return 0
        if b == 0:
            raise ZeroDivisionError("No se puede dividir por 0.")
        # Usamos las tablas log y exp para calcular el cociente eficientemente
        log_a = self.Tabla_LOG[a]
        log_b = self.Tabla_LOG[b]
        log_result = (log_a - log_b) % 255
        return self.Tabla_EXP[log_result]

    def xTimes(self, n):
        '''
        Multiplica el elemento n por 0x02 en el cuerpo finito GF(2^8).
        
        Entrada:
        - n: entero entre 0 y 255 que representa un elemento del cuerpo.
        
        Salida:
        - Un entero entre 0 y 255 que es el producto de n por 0x02 en el cuerpo.
        '''
        result = n << 1
        if result & 0x100:
            result ^= self.Polinomio_Irreducible
        return result & 0xFF

    def producto(self, a, b):
        '''
        Calcula el producto de dos elementos en el cuerpo finito GF(2^8) usando las tablas EXP y LOG.
        
        Entrada:
        - a: entero entre 0 y 255.
        - b: entero entre 0 y 255.
        
        Salida:
        - El producto de a y b en GF(2^8).
        '''
        if a == 0 or b == 0:
            return 0
        
        return self.Tabla_EXP[(self.Tabla_LOG[a] + self.Tabla_LOG[b]) % 255]

    def inverso(self, n):
        '''
        Calcula el inverso multiplicativo de un elemento en el cuerpo finito GF(2^8).
        
        Entrada:
        - n: entero entre 0 y 255 que representa un elemento del cuerpo.
        
        Salida:
        - 0 si n es 0.
        - El inverso multiplicativo de n si n es diferente de 0.
        '''
        if n == 0:
            return 0
        
        return self.Tabla_EXP[255 - self.Tabla_LOG[n]]
    
    def producto_polinomios_128(self, a, b):
        '''
        Multiplica dos polinomios en GF(2^128) y los reduce usando el polinomio irreducible.

        Entrada:
        - a: entero de 128 bits que representa el primer polinomio.
        - b: entero de 128 bits que representa el segundo polinomio.

        Salida:
        - El producto de a y b reducido por el polinomio irreducible (128 bits).
        '''
        result = 0
        for i in range(128):
            if b & 1:
                result ^= a
            b >>= 1
            a <<= 1
            # Si el bit 128 está encendido, realizamos la reducción con el polinomio irreducible
            if a & (1 << 128):
                a ^= self.Polinomio_Irreducible
        return result & ((1 << 128) - 1)  # Aseguramos que el resultado esté en 128 bits

    def gmac(self, H, m):
        '''
        Calcula el código de autenticación GMAC para un mensaje en GF(2^128) usando una clave H.

        Entrada:
        - H: clave de autenticación en GF(2^128), un entero de 128 bits.
        - m: mensaje en GF(2^128), un entero de 128 bits.

        Salida:
        - El código de autenticación GMAC (128 bits).
        '''
        # Inicializamos el valor del autenticador en 0 (128 bits)
        y = 0
        # Aplicamos GHASH: y = m * H en GF(2^128)
        y = self.producto_polinomios_128(m, H)
        return y

def juegos_de_prueba(cuerpo):

    # n = 0x57  # (87 en decimal)
    # resultado_xTimes = cuerpo.xTimes(n)
    # print(f"Multiplicación de {n:#04x} por 0x02 en el cuerpo GF(2^8): HEX: {resultado_xTimes:#04x}, DEC: {resultado_xTimes}")

    a = 0x71
    b = 0x06
    resultado_producto = cuerpo.producto(a, b)
    print(f"Producto de {a:#04x} y {b:#04x} en el cuerpo GF(2^8): HEX: {resultado_producto:#04x}, DEC: {resultado_producto}")
    
    # n = 0x7a  # 87 en decimal
    # resultado_inverso = cuerpo.inverso(n)
    # print(f"Inverso de {n:#04x} en el cuerpo GF(2^8): HEX: {resultado_inverso:#04x}, DEC: {resultado_inverso}")

    # a = 42
    # b = 22
    # resultado_producto_polinomios = cuerpo.producto_polinomios(a, b)
    # print(f"Producto de {a:#04x} y {b:#04x} en el cuerpo GF(2^8): HEX: {resultado_producto_polinomios:#04x}, DEC: {resultado_producto_polinomios}")
    
    # a = 0x57  # 87 en decimal
    # b = 0x83  # 131 en decimal
    # resultado_division = cuerpo.division(a, b)
    # print(f"División de {a:#04x} entre {b:#04x} en el cuerpo GF(2^8): HEX: {resultado_division:#04x} DEC: {resultado_division}")
    
    print("\n")

# if __name__ == "__main__":
#     cuerpo_finito = G_F()
#     juegos_de_prueba(cuerpo_finito)
#     # cuerpo_finito.print_tables()


# Prueba del cálculo de GMAC en GF(2^128)
if __name__ == "__main__":
    # Inicializamos el cuerpo finito GF(2^128)
    cuerpo_finito = G_F()

    # Definimos el mensaje y la clave de autenticación
    mensaje = 0x80000000000000000000000000000000  # m en GF(2^128)
    clave_H = 0x00000000000000000000000000000002  # H en GF(2^128)

    # Calculamos el código de autenticación GMAC
    codigo_autenticacion = cuerpo_finito.gmac(clave_H, mensaje)
    print(f"Código de autenticación GMAC: {codigo_autenticacion:032x}") 