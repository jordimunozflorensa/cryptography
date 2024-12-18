import os

with open('mandril.png_0x11b_184d0214afe945d315339b6d92b01c0f.enc', 'rb') as f:
    data = f.read()
    
print(data[:16])

with open('mandril.png.enc', 'rb') as f:
    data = f.read()

print(data[:16])

with open('mandril.png_0x11b_184d0214afe945d315339b6d92b01c0f.dec', 'rb') as f:
    data = f.read()
    
print(data[:16])

with open('mandril.png', 'rb') as f:
    data = f.read()
    
print(data[:16])