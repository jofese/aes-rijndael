#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
	Algoritmo de Cifrado/Descifrado AES
    Copyright (C) 2012 Darío López Padial y César Aguilera 
    @bukosabino
    @Cs4r
    ‏
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>
"""

################################################################################
#
#	Ejecución (cifrar) : ./genera_tablas.py
#	
#
#	Objetivo: Este programa generará 4 ficheros, cada uno representa una tabla:
#	log.txt: potencias del elemento primitivo 0x03 en el cuerpo AES.
#	alog.txt: logaritmo de cualquier elemento del cuerpo AES, en base 0x03.
#	sbox.txt: transformación inversa + transformación afín, para la operación SubBytes.
#	sbox_inv.txt: inversa de 'sbox.txt'
#
#
################################################################################

lista_alog = []
lista_log = []


##	Multiplicamos en cuerpo AES: hacemos el producto en notación polinomial, 
##	y posteriormente dividimos entre x^8+x^4+x^3+x+1.
def multiplicacion_aes(a, b):
	p = 0
	hiBitSet = 0
	for i in range(8):
		if b & 1 == 1:
			p ^= a
		hiBitSet = a & 0x80
		a <<= 1
		if hiBitSet == 0x80:
			a ^= 0x1b
		b >>= 1
	return p % 256


##	Cálculo del inverso en cuerpo AES: Xinverso = Alog(FF - Log(X))
def inverso_aes(inverso):
	if inverso == 0:
		return 0
	elif inverso == 1:
		return 1
	else:
		return lista_alog[(255 - lista_log[inverso])]


##	Transformación Subbytes: Inverso + Transformación Afín.
def sbox(inverso):
	s = x = inverso_aes(inverso)
	for c in range(4):
		s = (s << 1) | (s >> 7)
		x ^= s
	x ^= 99
	return x % 256
	

##	Genera las s-cajas del algoritmo AES.
def genera_tablas_sbox():
	lista_sbox = []
	lista_sbox_inv = []
	for j in range(256):
		lista_sbox_inv.append(0)
		
	for i in range(256):
		lista_sbox.append(sbox(i))
		lista_sbox_inv[lista_sbox[i]] = i
		
	fp_sbox = open("sbox.txt", "w")
	fp_sbox.write(unicode(lista_sbox)[1:-1])

	fp_sbox = open("sbox_inv.txt", "w")
	fp_sbox.write(unicode(lista_sbox_inv)[1:-1])	


##	Genera la tabla de logaritmos y antilogaritmos en el cuerpo AES.
def genera_tablas_aes():
	for i in range(256):
		if i == 0 or i == 1:
			lista_alog.append(multiplicacion_aes(3, i))
		else:
			lista_alog.append(multiplicacion_aes(3, lista_alog[i-1]))
		lista_log[lista_alog[i]] = i
	
	fp_alog = open("alog.txt", "w")
	fp_alog.write(unicode(lista_alog)[1:-1])

	fp_log = open("log.txt", "w")
	fp_log.write(unicode(lista_log)[1:-1])


def main():
	for i in range(256):
		lista_log.append(0)
	
	genera_tablas_aes()
	genera_tablas_sbox()


if __name__ == "__main__":
	main()
