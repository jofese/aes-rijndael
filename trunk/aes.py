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
#	Ejecución (cifrar con fichero de clave) :
#		$ ./aes.py -c <fichero> -k <fichero_clave> -s <fichero_cifrado>
#
#	Ejecución (descifrar con fichero de clave) :
#		$ ./aes.py -d <fichero_cifrado> -k <fichero_clave> -s <fichero_descifrado>
#
#	Ejecución (cifrar sin fichero de clave) :
#		$ ./aes.py -c <fichero> -s <fichero_cifrado>
#
#	Ejecución (descifrar sin fichero de clave) :
#		$ ./aes.py -d <fichero_cifrado> -s <fichero_descifrado>
#
#	Objetivo: Cifrar o Descifrar cualquier fichero, bajo el algoritmo AES.
#	Lo hace bajo el estándar, tamaño de bloques de datos de 128 bits y tamaño de 
#	claves de 128,192 y 256 bits.
#	Modo de operación: ECB.
#
################################################################################

import sys, hashlib, string, getpass
from copy import copy
from random import randint

"""
	TABLAS GLOBALES
"""
sbox = []
sbox_inv = []
log = []
alog = []

rcon = [
        0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
        0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
        0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
        0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
        0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
        0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
        0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
        0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
        0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
        0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
        0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
        0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
        0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
        0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
        0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
        0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb
        ]


"""
	TRANSFORMACIONES
"""
##	Aplicamos XOR entre los bytes del estado y los bytes de la "clave de ronda".
def add_round_key(estado, clave_ronda):
	for i in range(len(estado)):
		estado[i] = estado[i] ^ clave_ronda[i]
	return estado

##	Inverso + Transformación Afín para cada valor del estado entrante.
def sub_bytes(estado):
	for i in range(len(estado)):
		estado[i] = sbox[estado[i]]
	return estado

##	Transformación 'sub_bytes' invertida.
def sub_bytes_inv(estado):
	for i in range(len(estado)):
		estado[i] = sbox_inv[estado[i]]
	return estado

##	Gira n posiciones una columna del estado. Hacia arriba si n > 0, hacia abajo si n < 0.
def desplaza_columnas(columna, n):
	return columna[n:]+columna[0:n]
	
##	Desplaza las columnas del estado hacia arriba tantas posiciones como número de columna sea en la matriz 'estado'.
def shift_rows(estado):
	columna = [0,0,0,0]
	for j in range(4):
		for i in range(4):
			columna[i] = estado[(i*4)+j]
		columna = desplaza_columnas(columna, j)		
		for i in range(4):
			estado[(i*4)+j] = columna[i]
	return estado

##	Desplaza las columnas del estado hacia abajo tantas posiciones como número de columna sea en la matriz 'estado'.
def shift_rows_inv(estado):
	columna = [0,0,0,0]
	for j in range(4):
		for i in range(4):
			columna[i] = estado[(i*4)+j]
		columna = desplaza_columnas(columna, -j)		
		for i in range(4):
			estado[(i*4)+j] = columna[i]
	return estado

##	Multiplicamos en cuerpo AES, hacemos el producto en notación polinomial, y después dividimos entre x^8+x^4+x^3+x+1
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

##	Multiplicamos la columna recibida por la matriz:
##	(02 03 01 01)
##	(01 02 03 01)
##	(01 01 02 03)
##	(03 01 01 02)
def mix_column(columna):
	temp = copy(columna)
	columna[0] = multiplicacion_aes(temp[0],2) ^ multiplicacion_aes(temp[3],1) ^ \
				multiplicacion_aes(temp[2],1) ^ multiplicacion_aes(temp[1],3)
	columna[1] = multiplicacion_aes(temp[1],2) ^ multiplicacion_aes(temp[0],1) ^ \
				multiplicacion_aes(temp[3],1) ^ multiplicacion_aes(temp[2],3)
	columna[2] = multiplicacion_aes(temp[2],2) ^ multiplicacion_aes(temp[1],1) ^ \
				multiplicacion_aes(temp[0],1) ^ multiplicacion_aes(temp[3],3)
	columna[3] = multiplicacion_aes(temp[3],2) ^ multiplicacion_aes(temp[2],1) ^ \
				multiplicacion_aes(temp[1],1) ^ multiplicacion_aes(temp[0],3)

##	Multiplicamos la columna recibida por la matriz:
##	(0E 0B 0D 09)
##	(09 0E 0B 0D)
##	(0D 09 0E 0B)
##	(0B 0D 09 0E)
def mix_column_inv(columna):
    temp = copy(columna)
    columna[0] = multiplicacion_aes(temp[0],14) ^ multiplicacion_aes(temp[3],9) ^ \
                multiplicacion_aes(temp[2],13) ^ multiplicacion_aes(temp[1],11)
    columna[1] = multiplicacion_aes(temp[1],14) ^ multiplicacion_aes(temp[0],9) ^ \
                multiplicacion_aes(temp[3],13) ^ multiplicacion_aes(temp[2],11)
    columna[2] = multiplicacion_aes(temp[2],14) ^ multiplicacion_aes(temp[1],9) ^ \
                multiplicacion_aes(temp[0],13) ^ multiplicacion_aes(temp[3],11)
    columna[3] = multiplicacion_aes(temp[3],14) ^ multiplicacion_aes(temp[2],9) ^ \
                multiplicacion_aes(temp[1],13) ^ multiplicacion_aes(temp[0],11)

##	Transforma cada columna del estado multiplicandola con la siguiente matriz:
##	(02 03 01 01)
##	(01 02 03 01)
##	(01 01 02 03)
##	(03 01 01 02)
def mix_columns(estado):
	for i in range(4):
		columna = []
		# creamos una columna a partir del estado.
		# por ejemplo, los elementos 0, 4, 8, 12 formarán la primera columna.
		for j in range(4):
			columna.append(estado[j+i*4])
        # aplicamos mixColumn sobre la columna.
		mix_column(columna)
		# actualizamos el nuevo estado.
		for j in range(4):
			estado[j+i*4] = columna[j]
	return estado

##	Transformación mixColumns invertida.
def mix_columns_inv(estado):
	for i in range(4):
		columna = []
		for j in range(4):
			columna.append(estado[j+i*4])
		mix_column_inv(columna)
		for j in range(4):
			estado[j+i*4] = columna[j]
	return estado


"""
EXPANSIÓN DE CLAVE
"""
##	Transforma la columna recibida aplicando desplazamientos, sbox y rcon.
def key_schedule_core(columna, i):
	# desplaza la columna 1 posición hacia arriba.
	columna = desplaza_columnas(columna, 1)
	nueva_columna = []
	# sustituye cada byte de la columna por su sbox correspondiente.
	for c in columna:
		nueva_columna.append(sbox[c])
	# aplica XOR entre la columna y rcon[i].
	nueva_columna[0] = nueva_columna[0]^rcon[i]	
	return nueva_columna

##	Expande la clave a un tamaño de 176, 208, 240 bytes.
def expandir_clave(clave, num_rondas):
	tamanio_clave = len(clave)
	clave_expandida = []
	puntero_auxiliar = 0
	indice = 0
	rcon_indice = 1
	t = [0,0,0,0]
	# copia los primeros 16, 24 o 32 bytes de la clave en la clave_expandida.
	for i in range(tamanio_clave):
		clave_expandida.append(clave[i])
	indice += tamanio_clave
	# El tamaño del bloque será constante, 16 bytes.
	tamanio_expansion = 16 * (num_rondas+1)
	while indice < tamanio_expansion:		
		for i in range(4):
			t[i] = clave_expandida[(indice - 4) + i]
		# cada 32 bytes aplicamos el 'key_schedule_core' en la columna t.
		if indice % tamanio_clave == 0:
			t = key_schedule_core(t, rcon_indice)
			rcon_indice += 1
		# si usamos claves de 256 bits añadimos una transformación sbox extra.
		if num_rondas == 14:
			if indice % tamanio_clave == 16:
				for i in range(4):
					t[i] = sbox[t[i]]
		# aplica XOR entre la columna actual 'indice' y la auxiliar 't'.
		for i in range(4):
			clave_expandida.append(((clave_expandida[indice - tamanio_clave]) ^ (t[i])))
			indice += 1
	return clave_expandida

##	Devuelve una clave de ronda a partir de una clave expandida y el número de ronda.
def crea_clave_ronda(clave_expandida, n):
	return clave_expandida[(n*16):(n*16+16)] # +16 o +24 o +32 para indicar el tamaño de la clave..
	
	
"""
AES
"""	
##	Algoritmo de cifrado AES, usando el modo ECB.
def cifrar(bloque, clave, num_rondas):
	clave_expandida = expandir_clave(clave, num_rondas)
	clave_ronda = crea_clave_ronda(clave_expandida, 0)	
	estado = add_round_key(bloque, clave_ronda)
	
	for i in range(1, num_rondas):
		estado = sub_bytes(estado)
		estado = shift_rows(estado)
		estado = mix_columns(estado)
		clave_ronda = crea_clave_ronda(clave_expandida, i)
		estado = add_round_key(estado, clave_ronda)

	clave_ronda = crea_clave_ronda(clave_expandida, num_rondas)
	estado = sub_bytes(estado)
	estado = shift_rows(estado)
	bloque_cifrado = add_round_key(estado, clave_ronda)
	return bloque_cifrado

##	Algoritmo de descifrado AES, usando el modo ECB.
def descifrar(bloque, clave, num_rondas):
	clave_expandida = expandir_clave(clave, num_rondas)
	clave_ronda = crea_clave_ronda(clave_expandida, num_rondas)
	estado = add_round_key(bloque, clave_ronda)
	estado = shift_rows_inv(estado)
	estado = sub_bytes_inv(estado)

	for i in range(num_rondas-1,0,-1):
		clave_ronda = crea_clave_ronda(clave_expandida, i)
		estado = add_round_key(estado, clave_ronda)
		estado = mix_columns_inv(estado)
		estado = shift_rows_inv(estado)
		estado = sub_bytes_inv(estado)
		
	clave_ronda = crea_clave_ronda(clave_expandida, 0)
	bloque_cifrado = add_round_key(estado, clave_ronda)
	return bloque_cifrado


"""
UTILIDADES
"""
##	Creamos una clave de 256 bits a partir de una palabra.
def passwordToKey(password):
    sha256 = hashlib.sha256()
    sha256.update(password)
    key = []
    for c in list(sha256.digest()):
        key.append(ord(c))
    return key

##	Carga una tabla que se encuentre en un fichero.
def obtener_tabla(nombre_fichero):
	try:
		fp = open(nombre_fichero, "r")
		lista = fp.read().split(", ")
		lista2 = []
		for l in lista:
			lista2.append(int(l))
	except:
		print "error: No se han creado las tablas.\nEjecute ./genera_tablas.py para crearlas."
		sys.exit()
	return lista2

##	Mensaje de error ejecutando el programa.
def error_parametros():
	print "error: especificando los parámetros"
	print "./aes.py -c|-d <fichero entrada> [-k <fichero clave>] -s <salida>"
	sys.exit()	

##	Leemos un bloque del fichero entrante.
def lee_bloque(fp):
	bloque = fp.read(16)
	# si llegamos al final del fichero, devolvemos 0.
	if len(bloque) == 0:
		return 0
	# estado con la lista de bytes.
	estado = []
	for c in list(bloque):
		estado.append(ord(c))
	# si el bloque leído es inferior al tamaño de bloque, le memos "bytes de relleno".
	if len(estado) < 16:
		relleno = 16-len(estado)
		while len(estado) < 16:
			estado.append(relleno)
	return estado
	
##	Leemos una clave a través de fichero.
def lee_clave(fp):
	# Averiguamos el tamaño del fichero.
	fp.seek(0,2)
	tamanio_fichero = fp.tell()
	fp.seek(0)
	# Leemos parejas de caracteres hexadecimales.
	fin = True
	clave = []
	while(fin == True):
		bloque = fp.read(2)
		if len(bloque) == 0:
			fin = False
		else:
			clave.append(int(bloque, 16))
			if len(clave) == tamanio_fichero/2:
				fin = False
	return clave

##	Inicialización de las tablas globales.
sbox = obtener_tabla("sbox.txt")
sbox_inv = obtener_tabla("sbox_inv.txt")
log = obtener_tabla("log.txt")
alog = obtener_tabla("alog.txt")

def main():

	# Comprobación de argumentos y apertura de ficheros.
	if sys.argv[1] != "-c" and sys.argv[1] != "-d":
		error_parametros()
		
	if len(sys.argv) == 7: # Establece la clave a través de un fichero en hexadecimal.
		try:
			fp_entrada = open(sys.argv[2], "rb")
		except:
			print "error: abriendo el fichero", sys.argv[2]
			sys.exit()
		if sys.argv[3] == "-k":
			try:
				fp_clave = open(sys.argv[4], "r")
			except:
				print "error: abriendo el fichero", sys.argv[4]
				sys.exit()
		else:
			error_parametros()
		if sys.argv[5] == "-s":
			try:
				fp_salida = open(sys.argv[6], "w")
			except:
				print "error: abriendo el fichero", sys.argv[6]
				sys.exit()
		else:
			error_parametros()

		# leemos la clave y determinamos su tamaño.
		clave = lee_clave(fp_clave)
		if len(clave) == 16:
			num_rondas = 10
		elif len(clave) == 24:
			num_rondas = 12
		elif len(clave) == 32:
			num_rondas = 14
		else:
			print "error: tamaño de clave no estándar\n"
			sys.exit()
	elif len(sys.argv) == 5: # Establece una contraseña sin usar fichero. La transformaremos en una clave de 256 bits.
		try:
			fp_entrada = open(sys.argv[2], "rb")
		except:
			print "error: abriendo el fichero", sys.argv[2]
			sys.exit()
		if sys.argv[3] == "-s":
			try:
				fp_salida = open(sys.argv[4], "w")
			except:
				print "error: abriendo el fichero", sys.argv[4]
				sys.exit()
		else:
			error_parametros()			
		clave = getpass.getpass("Contraseña: ")
		clave = passwordToKey(clave)
		num_rondas = 14
	else:
		error_parametros()

	fp_entrada.seek(0,2)
	tamanio_fichero = fp_entrada.tell()
	fp_entrada.seek(0)
	
	# Leemos el archivo de entrada por bloques de 16 bytes.
	bloque = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
	bloque = lee_bloque(fp_entrada)

	if sys.argv[1] == "-c":	# Ciframos
		while bloque != 0:
			bloque_cifrado = cifrar(bloque, clave, num_rondas)
			for c in bloque_cifrado:
				fp_salida.write(chr(c))
			bloque = lee_bloque(fp_entrada)
			
	else: # Desciframos
		while bloque != 0: 
			bloque_cifrado = descifrar(bloque, clave, num_rondas)
			# si es el último bloque de texto despreciamos los bytes de relleno.
			if fp_entrada.tell() == tamanio_fichero:
				bloque_cifrado = bloque_cifrado[0:-(bloque_cifrado[-1])]
			for c in bloque_cifrado:
				fp_salida.write(chr(c))
			bloque = lee_bloque(fp_entrada)
			
if __name__ == "__main__":
	main()
