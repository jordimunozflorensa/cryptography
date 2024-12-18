import hashlib
import random
from sympy import isprime
from sympy import mod_inverse
import time
import matplotlib.pyplot as plt
import json
import math
from Crypto.Util import number


D = 16 # para el exponente publico

class rsa_key:
    def obtener_primos(self, bits_modulo):
        p_es_primo = False
        q_es_primo = False
        p_q_igual = True
        p_q_coprimos = False
        primeP = 0
        primeQ = 0

        while ((not p_q_coprimos) or (p_q_igual)):
            while (not p_es_primo):
                primeP = random.randint(0, 2**(bits_modulo >> 1))
                p_es_primo = isprime(primeP)
            while (not q_es_primo):
                primeQ = random.randint(0, 2**(bits_modulo >> 1))
                q_es_primo = isprime(primeQ)
            p_q_igual = (primeQ == primeP)
            p_q_coprimos = (math.gcd(self.publicExponent, ((primeP - 1) * (primeQ - 1))) == 1)

        return primeP, primeQ

    def __init__(self, bits_modulo=2048, e=2**16 + 1):
        """
        Genera una clave RSA (de 2048 bits y exponente público 2**16+1 por defecto).
        """
        self.publicExponent = e
        self.primeP, self.primeQ = self.obtener_primos(bits_modulo)
        # self.primeP = provided_values['primeP']
        # self.primeQ = provided_values['primeQ']
        self.modulus = self.primeP * self.primeQ
        
        phi = (self.primeP - 1) * (self.primeQ - 1)
        self.privateExponent = int(mod_inverse(self.publicExponent, phi))
        
        self.inverseQModulusP = int(mod_inverse(self.primeQ, self.primeP))
        self.privateExponentModulusPhiP = int(self.privateExponent % (self.primeP - 1))
        self.privateExponentModulusPhiQ = int(self.privateExponent % (self.primeQ - 1))

    def __repr__(self):
        return str(self.__dict__)

    def sign(self, message):
        """
        Realiza una firma utilizando la clave privada con el Teorema Chino del Resto (TCR).
        """
        mP = pow(message, self.privateExponentModulusPhiP, self.primeP)
        mQ = pow(message, self.privateExponentModulusPhiQ, self.primeQ)
        h = ((mP - mQ) * self.inverseQModulusP) % self.primeP
        m = (mQ + h * self.primeQ) % self.modulus
        return m

    def sign_slow(self, message):
        """
        Realiza una firma utilizando la clave privada directamente (sin TCR).
        """
        m = pow(message, self.privateExponent, self.modulus)
        return m
    
    def from_dictionary(self, clave):
        self.publicExponent = clave['publicExponent']
        self.primeP = clave['primeP']
        self.primeQ = clave['primeQ']
        self.modulus = clave['modulus']
        self.privateExponent = clave['privateExponent']
        self.inverseQModulusP = clave['inverseQModulusP']
        self.privateExponentModulusPhiP = clave['privateExponentModulusPhiP']
        self.privateExponentModulusPhiQ = clave['privateExponentModulusPhiQ']
        
    def to_dict(self):
        """
        Convierte el objeto rsa_key a un diccionario.
        """
        return {
            'publicExponent': self.publicExponent,
            'primeP': self.primeP,
            'primeQ': self.primeQ,
            'modulus': self.modulus,
            'privateExponent': self.privateExponent,
            'inverseQModulusP': self.inverseQModulusP,
            'privateExponentModulusPhiP': self.privateExponentModulusPhiP,
            'privateExponentModulusPhiQ': self.privateExponentModulusPhiQ
        }

class rsa_public_key:
    def __init__(self, publicExponent=1, modulus=1):
        """
        Genera la clave pública RSA asociada a la clave RSA privada.
        """
        self.publicExponent = publicExponent
        self.modulus = modulus

    def __repr__(self):
        return str(self.__dict__)

    def verify(self, message, signature):
        """
        Verifica que la firma corresponde al mensaje con la clave pública.
        """
        return pow(signature, self.publicExponent, self.modulus) == message

    def to_dict(self):
        """
        Convierte el objeto rsa_public_key a un diccionario.
        """
        return {
            'publicExponent': self.publicExponent,
            'modulus': self.modulus
        }


class transaction:
    def __init__(self, message = 0, RSAkey = 0):
        """
        Crea una transacción firmando 'message' con la clave privada RSAkey.
        """
        if isinstance(RSAkey, int):
            return
        self.message = message
        self.public_key = rsa_public_key(RSAkey.publicExponent, RSAkey.modulus)
        self.signature = RSAkey.sign(message)

    def __repr__(self):
        return str(self.__dict__)

    def verify(self):
        """
        Verifica que la firma sea válida con la clave pública.
        """
        return self.public_key.verify(self.message, self.signature)
    
    def from_dictionary(self, transaccion):
        self.public_key = rsa_public_key(
            publicExponent=transaccion['public_key']['publicExponent'],
            modulus=transaccion['public_key']['modulus']
        )
        self.message = transaccion['message']
        self.signature = transaccion['signature']
        
    def to_dict(self):
        """
        Convierte el objeto transaction a un diccionario.
        """
        return {
            'public_key': self.public_key.to_dict(),
            'message': self.message,
            'signature': self.signature
        }

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
        self.generateBlockHash()
        return self

    def next_block(self, transaction):
        '''
        genera un bloque válido siguiente al actual con la transacción "transaction"
        '''
        next_block = block()
        next_block.previous_block_hash = self.block_hash
        next_block.transaction = transaction
        next_block.generateBlockHash()
        return next_block

    def verify_block(self):
        '''
        Verifica si un bloque es válido:
        - Comprueba que el hash del bloque anterior cumple las condiciones exigidas
        - Comprueba que la transacción del bloque es válida
        - Comprueba que el hash del bloque cumple las condiciones exigidas
        - Comprobar que la seed sea correcta
        Salida: el booleano True si todas las comprobaciones son correctas;
        el booleano False en cualquier otro caso.
        '''
        check_previous_block_hash = self.previous_block_hash < 2 ** (256 - D)
        check_transaction = self.transaction.verify()
        check_block_hash = self.block_hash < 2 ** (256 - D)
        
        # Verificar que la seed es correcta
        entrada = str(self.previous_block_hash)
        entrada = entrada + str(self.transaction.public_key.publicExponent)
        entrada = entrada + str(self.transaction.public_key.modulus)
        entrada = entrada + str(self.transaction.message)
        entrada = entrada + str(self.transaction.signature)
        entrada = entrada + str(self.seed)
        entrada = int(hashlib.sha256(entrada.encode()).hexdigest(), 16)
        check_seed = entrada == self.block_hash
        
        return check_previous_block_hash and check_transaction and check_block_hash and check_seed
    
    def from_dictionary(self, bloque):
        self.block_hash = bloque['block_hash']
        self.previous_block_hash = bloque['previous_block_hash']
        transaccion_aux = transaction()
        transaccion_aux.from_dictionary(bloque['transaction'])
        self.transaction = transaccion_aux
        self.seed = bloque['seed']
        
    def to_dict(self):
        return {
            'block_hash': self.block_hash,
            'previous_block_hash': self.previous_block_hash,
            'transaction': self.transaction.to_dict(),
            'seed': self.seed
        }


class block_chain:
    def __init__(self, transaction=0):
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
        
    def add_invalid_block(self, transaction):
        '''
        añade a la cadena un nuevo bloque inválido
        generado con la transacción "transaction"
        '''
        new_block = self.list_of_blocks[-1].next_block(transaction)
        new_block.block_hash = 0  # Forzar un hash de bloque inválido
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
            ultimo_hash = 0
            for i, bloque in enumerate(self.list_of_blocks):
                if not bloque.verify_block() or ultimo_hash != bloque.previous_block_hash:
                    return False, i
                ultimo_hash = bloque.block_hash
            return False, 0
        
    def from_dictionary(self, lista_de_bloques):
        aux = []
        for i in lista_de_bloques['list_of_blocks']:
            bloque = block()
            bloque.from_dictionary(i)
            aux.append(bloque)
        self.list_of_blocks = aux
        
    def to_dict(self):
        return {
            'list_of_blocks': [bloque.to_dict() for bloque in self.list_of_blocks]
        }