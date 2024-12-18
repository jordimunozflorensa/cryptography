import hashlib
import random
from sympy import randprime
from sympy import mod_inverse

D = 16 # para el exponente publico

class rsa_key:
    def __init__(self, bits_modulo=2048, e=2**16+1):
        '''
        genera una clave RSA (de 2048 bits y exponente público 2**16+1 por defecto)
        '''
        self.publicExponent = e
        self.primeP = randprime(2**(bits_modulo//2 - 1), 2**(bits_modulo//2))
        self.primeQ = randprime(2**(bits_modulo//2 - 1), 2**(bits_modulo//2))
        self.modulus = self.primeP * self.primeQ
        
        phi = (self.primeP - 1) * (self.primeQ - 1)
        self.privateExponent = mod_inverse(self.publicExponent, phi)
        
        self.inverseQModulusP = mod_inverse(self.primeQ, self.primeP)
        self.privateExponentModulusPhiP = mod_inverse(self.privateExponent, self.primeP - 1)
        self.privateExponentModulusPhiQ = mod_inverse(self.privateExponent, self.primeQ - 1)


    def __repr__(self):
        return str(self.__dict__)

    def sign(self, message):
        '''
        Salida: un entero que es la firma de "message" hecha con la clave RSA usando el TCR
        
        m ===  mP mod p
        m ===  mQ mod q
        
        h = (mP - mQ)*q_inv mod p
        
        m = mQ + h*q mod n
        '''
        
        mP = pow(message, self.privateExponentModulusPhiP, self.primeP)
        mQ = pow(message, self.privateExponentModulusPhiQ, self.primeQ)
        h = ((mP-mQ) * self.inverseQModulusP) % self.primeP
        m = (mQ + h * self.primeQ) % self.modulus
        return m


    def sign_slow(self, message):
        '''
        Salida: un entero que es la firma de "message" hecha con la clave RSA sin usar el TCR
        
        mess = m^d mod n
        '''
    
        m = pow(message, self.privateExponent, self.modulus)
        return m


class rsa_public_key:
    def __init__(self, publicExponent=1, modulus=1):
        '''
        genera la clave pública RSA asociada a la clave RSA "rsa_key"
        '''
        self.publicExponent = publicExponent
        self.modulus = modulus

    def __repr__(self):
        return str(self.__dict__)

    def verify(self, message, signature):
        '''
        Salida: el booleano True si "signature" se corresponde con la
        firma de "message" hecha con la clave RSA asociada a la clave
        pública RSA;
        el booleano False en cualquier otro caso.
        
        mess = sign^e mod n
        '''
        
        return pow(signature, self.publicExponent, self.modulus) == message


class transaction:
    def __init__(self, message, RSAkey=rsa_key()):
        '''
        genera una transaccion firmando "message" con la clave "RSAkey"
        '''
        self.message = message
        self.public_key = rsa_public_key(RSAkey.publicExponent, RSAkey.modulus)
        self.signature = RSAkey.sign(message)

    def __repr__(self):
        return str(self.__dict__)

    def verify(self):
        '''
        Salida: el booleano True si "signature" se corresponde con la
        firma de "message" hecha con la clave RSA asociada a la clave
        pública RSA;
        el booleano False en cualquier otro caso.
        '''
        return self.public_key.verify(self.message, self.signature)
        

class block:
    def __init__(self):
        '''
        crea un bloque (no necesariamente válido)
        '''
        self.block_hash = None
        self.previous_block_hash = None
        self.transaction = None
        self.seed = None

    def __repr__(self):
        return str(self.__dict__)
    
    def generateBlockHash(block):
        while True:
            block.seed = random.randint(0, 2**256)
            
            entrada = str(block.previous_block_hash)
            entrada = entrada+str(block.transaction.public_key.publicExponent)
            entrada = entrada+str(block.transaction.public_key.modulus)   
            entrada = entrada+str(block.transaction.message)
            entrada = entrada+str(block.transaction.signature)
            entrada = entrada+str(block.seed)
            entrada = int(hashlib.sha256(entrada.encode()).hexdigest(),16)
            
            if entrada < 2 ** (256 - D):
                break
            
        block.block_hash = entrada

    def genesis(self, transaction):
        '''
        genera el primer bloque de una cadena con la transacción "transaction"
        que se caracteriza por:
        - previous_block_hash=0
        - ser válido
        '''
        self.previous_block_hash = 0
        self.transaction = transaction
        self.generateBlockHash(self)
        return self

    def next_block(self, transaction):
        '''
        genera un bloque válido siguiente al actual con la transacción "transaction"
        '''
        next_block = block()
        next_block.previous_block_hash = self.block_hash
        next_block.transaction = transaction
        next_block.generateBlockHash(next_block)
        return next_block

    def verify_block(self):
        '''
        Verifica si un bloque es válido:
        -Comprueba que el hash del bloque anterior cumple las condiciones exigidas
        -Comprueba que la transacción del bloque es válida
        -Comprueba que el hash del bloque cumple las condiciones exigidas
        Salida: el booleano True si todas las comprobaciones son correctas;
        el booleano False en cualquier otro caso.
        '''
        check_previous_block_hash = self.previous_block_hash < 2 ** (256 - D)
        check_transaction = self.transaction.verify()
        check_block_hash = self.block_hash < 2 ** (256 - D)
        
        return check_previous_block_hash and check_transaction and check_block_hash


class block_chain:
    def __init__(self, transaction):
        '''
        genera una cadena de bloques que es una lista de bloques,
        el primer bloque es un bloque "genesis" generado con la transacción "transaction"
        '''
        primerBloque = block()
        self.list_of_blocks = [primerBloque.genesis(transaction)]

    def __repr__(self):
        return str(self.__dict__)

    def add_block(self, transaction):
        '''
        añade a la cadena un nuevo bloque válido generado con la transacción "transaction"
        '''
        new_block = self.list_of_blocks[-1].next_block(transaction)
        self.list_of_blocks.append(new_block)

    def verify(self):
        '''
        verifica si la cadena de bloques es válida:
        - Comprueba que todos los bloques son válidos
        - Comprueba que el primer bloque es un bloque "genesis"
        - Comprueba que para cada bloque de la cadena el siguiente es correcto
        Salida: el booleano True si todas las comprobaciones son correctas;
        en cualquier otro caso, el booleano False y un entero
        correspondiente al último bloque válido
        '''
        check_genesis = self.list_of_blocks[0].previous_block_hash == 0
        check_blocks = [block.verify_block() for block in self.list_of_blocks]
        check_next_block = [self.list_of_blocks[i].block_hash == self.list_of_blocks[i+1].previous_block_hash for i in range(len(self.list_of_blocks)-1)]
        
        if check_genesis and all(check_blocks) and all(check_next_block):
            return True
        else:
            for i in range(len(self.list_of_blocks)-1, 0, -1):
                if self.list_of_blocks[i].verify_block():
                    return False, i
            return False, 0