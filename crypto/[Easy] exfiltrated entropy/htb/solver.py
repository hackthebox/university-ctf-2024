from pwn import xor
from params import a, b, m
from base64 import b64decode
from sage.all import *

class LCG:
    def __init__(self, seed):
        self.state = seed
        self.a = a
        self.b = b
        self.m = m
    
    def _next(self):
        self.state = (self.a * self.state + self.b) % self.m
        return self.state
    
    def generate_key(self, l):
        return bytes([self._next() & 0xff for _ in range(l)])

    def generate_packet_uuid(self):
        return hex(self._next())

    def encrypt(self, msg):
        key = self.generate_key(len(msg))
        return xor(msg, key)
    
    def decrypt(self, msg):
        return self.encrypt(msg)

def pwn():
    R = PolynomialRing(Zmod(m), 's0')
    s0 = R.gen()

    for _ in range(14):
        s0 = a*s0 + b
    
    uuid = int('eba14c429a64b2251717da016e096091', 16)
    coeffs = list(s0)
    seed = int((uuid - coeffs[0]) / coeffs[1])
    
    lcg = LCG(seed)

    encs = ["ocXzAq8Q", "PZxLt34=", "kn4=", "Ve7i4H2jQpnQaq2QVgLqprnTCzzM8xLx3TzrV/17HYPvkpZOkcLiOWhXSybh+QMNAie+CTVC7lZ928epBo/yMoQ1KfAlfwBckLny2pSb86i8RcHlz/aG9kEjfNy8ek/VKciP0V+Duq1xT9c5cH/Cl5mzM0I1z3bP4B/CMJMf/2eJKzdt+jucTAz7OwONh3twYB/a/R0nzzBG5iKUZe/SE2wSA8lDHCbh8dOP5DIj2cLR+XiIrooI", "2ulbTirRTzn+EKa1bvu3", "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", "B3ljT4UTIVliEXzIoq8=", "UPLJRbJORAiYXGBp0ftEnICuCAgROdzp+RChCyGfWqwblSCYcOb0ryPnUvqdfKuHTV+z4eaZBC3Ur02rwSTrQKBycKPli4Nc35boAG5RDF/H5E5EXnb7CGYq7lZ61uQ=", "4FfTtXHCD3LuRRJzLIzwyeylqqGwyTiugfjOo+MbNhyKv1ZDgSL33Lwaysu+dlONfwJ8jaqbuTVnVqwFloEI4wGdC9FFkmJgLpV9y3AZyjM0wsV+DRVR1cpOBvQqT4F46j2JiDxvABDqHRw5yrmv+uByJMyX/cZM2azJMonAVwV95ncUg0uWs3bmpturCW9sWiVaQ2pqjgAuUDs3Yab1/jJa4tthhkJrBJl6cyX88ijWqoMBKUkjsZ/sNa8uGLpC9gGpafUQwfyaPfImxIx8taB8bain59NlaI2RaL3YFfRrkxQAw8rUshLbxqI/AhpOH9LRQ09GeORcBnHPC0HaqMFDgp0euCJzrnVhdDmPrPPGhq/MsfISmr3R94HfOE4hs/h4ceMywp+qHOLZ/1RlvVoSBrK5w7o4G16PJLC9Xf8UzC6rQO5PQBiOcpNgCPg7NvToEickQd7CTBWQOEy+Rv0ar8gnTAooy2cjMe2iqeuEMTOd5Pz8QKS721vcxU4AU4cLDbwhr4tKteb3v3oGcAEiPF9sSoMbBlhoE0m7+f8wLPHvXrgfShSKBD0L9vccz42AMCUZGu+Ctw2QASe5apAnvWz0c+u3rD3aG8aXZo+hF3K4u7rjRkulqm2B+mD9aeJiVb2zlah74L6iRW0MUR7PvXkXSnnaX2sW8E9Y3obSBo2gEqcQAqhLAlsu7Y3y9Jyc87LJEMSf/tmq/BBEFIjcXXWBBO3ys1rK3vFdb5pfND6ApIO/AEhRoguD/SDGCpkOqkjXYk8cgSWaTE3aMULyhCZwFlHsyVMS9CodoFvAbInIEjE+L8ptHDff6IbbkENz/83i7SOGitFn3epsL0fyQjWlA5CSdceb/opVJVUeVwdYbVO4DC9XTRtDivq3VkbI0WL3cHUqmXcmAKzcGMSV/xkMB2Th6vAq+xcYhhm8EoFxqXC14e00/0XlvXm0pkZngfmo0Gd0qqJYofA34HS/Miuy6deJd5u3mnMeUGsv6O9mZ3VlpAUTQtEJXJvbzXbB7j+VPhb3J2JRRs+a9N2Is8jyyRO3tI7kmskDPRyMx1pg4jH138wWyqOvfWXVcTE+qNa+gh4VUZkDsaNE9H2+E/dyx2tKH78htEtT0zkU5tIOCzFl19odAJUdGapWjjqZmEBYKzGIdRF53KLK9qdmPczHycB8uYqRdNbLZixO2lIshAmGh1yx8ZKVGD1/RgFdPiE9k1YxHGQXd5Lmvg=="]

    for i in range(0, len(encs), 2):
        cmd = lcg.decrypt(b64decode(encs[i].encode()))

        if i != 0:
            lcg.generate_packet_uuid()

        if i == len(encs) - 1:
            print("ENTER IN ANY *NIX TERMINAL :",cmd.decode())
            
        if i + 1 < len(encs):
            response = lcg.decrypt(b64decode(encs[i+1].encode()))
            # print(response)

if __name__ == '__main__':
    pwn()
