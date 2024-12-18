class AES:
    '''
    Genera un cuerpo finito usando como polinomio irreducible el dado
    representado como un entero. Por defecto toma el polinomio del AES.
    Los elementos del cuerpo los representaremos por enteros 0 <= n <= 255.
    '''
    def __init__(self, Polinomio_irreductible = 0x11B):
        '''
        Entrada: un entero que representa el polinomio para construir el cuerpo
        Tabla_EXP y Tabla_LOG dos tablas, la primera tal que en la posicion
        i-esima tenga valor a=g**i y la segunda tal que en la posicion a-esima
        tenga el valor i tal que a=g**i. (g generador del cuerpo finito
        representado por el menor entero entre 0 y 255.)
        '''
        self.Polinomio_irreductible = Polinomio_irreductible
        
        self.Tabla_EXP = [0] * 512
        self.Tabla_LOG = [0] * 256
        a = 1
        for i in range(0, 255):
            self.Tabla_EXP[i] = a
            self.Tabla_LOG[a] = i
            a = self.xTimes(a)
        
        for i in range(255, 512):
            self.Tabla_EXP[i] = self.Tabla_EXP[i - 255]
            
    def xTimes(self, n):
        '''
        Entrada: un elemento del cuerpo representado por un entero entre 0 y 255
        Salida: un elemento del cuerpo representado por un entero entre 0 y 255
                que es el producto en el cuerpo de n y 0x02 (el polinomio X).
        '''        
        n = n << 1
        if n >= 128:
            n = n ^ self.Polinomio_irreductible
        return n
    
    def producto(self, a, b):
        '''
        Entrada: dos elementos del cuerpo representados por enteros entre 0 y 255
        Salida: un elemento del cuerpo representado por un entero entre 0 y 255
        que es el producto en el cuerpo de la entrada.
        
        Atencion: Se valorara la eficiencia. No es lo mismo calcularlo
        usando la definicion en terminos de polinomios o calcular
        usando las tablas Tabla_EXP y Tabla_LOG.
        '''
        if a == 0 or b == 0:
            return 0
        return self.Tabla_EXP[(self.Tabla_LOG[a] + self.Tabla_LOG[b]) % 255]
    
    def inverso(self, a):
        '''
        Entrada: un elemento del cuerpo representado por un entero entre 0 y 255
        Salida: un elemento del cuerpo representado por un entero entre 0 y 255
        que es el inverso en el cuerpo de la entrada.
        '''
        return self.Tabla_EXP[255 - self.Tabla_LOG[a]]
    

if __name__ == '__main__':
    aes = AES()
    print(aes.xTimes(0x57)) # deberia dar 0xAE
    print(aes.producto(0x57, 0x13)) # deberia dar 0xFE en hexadecimal y en decimal 254
    print(aes.inverso(0x57)) # deberia dar 0x83