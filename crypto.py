#! /usr/bin/python
from __future__ import division
from math import log
import string
import itertools
import operator
import random

surprise = lambda p: sys.maxint if p==0 else log(1/p,2)

class Distribution:
	def __init__(self,probs):
		self.probs=probs
	def __iter__(self):
		for c in self.probs: yield c
	def __getitem__(self,index):
		try: return self.probs[index]
		except KeyError: return 0
	def __setitem__(self,index,value):
		self.probs[index] = value
	def __repr__(self):
		return str(self.probs)
	def entropy(self):
		return sum(map(lambda c: self[c]*surprise(self[c]),self))
	def surprise(self,evidence):
		return sum(map(lambda e: surprise(self[e]),evidence))
	def probOfList(self,evidence):
		result = 1
		for e in evidence: result *= self[e]
		return result
	def indexOfCoincidence(self):
		return sum([p**2 for p in self.probs.values()])
	def sample(self,length=1):
		def getOne():
			index = random.uniform(0,1)
			accumulator = 0
			for value in sorted(self.probs):
				accumulator += self.probs[value]
				if accumulator >= index: return value
		result = []
		for i in range(length): result.append(getOne())
		return result
	def mean(self):
		return sum([k*self.probs[k] for k in self.probs])
	def variance(self):
		mean = self.mean()
		return sum([self.probs[k]*(k-mean)**2 for k in self.probs]) 
	def stdev(self):
		return self.variance()**0.5

allCharacters = [chr(i) for i in range(256)]
uniform = lambda vlist: Distribution({v:1/len(vlist) for v in vlist})

RandomLowercase = uniform(string.lowercase)
RandomCharacters = uniform(allCharacters)
RandomPrintables = uniform(string.printable)
myDistribution = uniform(string.hexdigits+"\x00")

English1Grams = Distribution({
	'e':0.13000,
	't':0.09056,
	'a':0.08167,
	'o':0.07507,
	'i':0.06966,
	'n':0.06749,
	's':0.06327,
	'h':0.06094,
	'r':0.05987,
	'd':0.04253,
	'l':0.04025,
	'c':0.02782,
	'u':0.02758,
	'm':0.02406,
	'w':0.02360,
	'f':0.02228,
	'g':0.02015,
	'y':0.01974,
	'p':0.01929,
	'b':0.01492,
	'v':0.00978,
	'k':0.00772,
	'j':0.00153,
	'x':0.00150,
	'q':0.00095,
	'z':0.00074
})

English1GramsUpper = Distribution({string.upper(item):prob for item,prob in English1Grams.probs.items()})

def linComb(distWeights):
	result = {}
	for dist, factor in distWeights:
		for item, prob in dist.probs.items():
			result.setdefault(item,0)
			result[item] += prob*float(factor)
	return Distribution(result)

miscChars = "\x00\x0d\x0a\x20"

softDist = linComb((
	(English1Grams,0.25),
	(English1GramsUpper,0.25),
	(uniform(string.digits),0.2),
	(uniform(string.punctuation),0.2),
	(uniform(miscChars),0.1)
))


product = lambda iterable: reduce(operator.mul, iterable, 1)

def hexToBase64(string):
	return list("".join(string).decode("hex").encode("base64"))[:-1]

def base64Tohex(string):
	return list("".join(string).decode("base64").encode("hex"))

def project(dicts,vector):
	return [dicts[i][vector[i]] for i in range(len(vector))]

def collect(tuples):
	result = {}
	for t in tuples:
		if t[0] not in result: result[t[0]] = 0
		result[t[0]] += t[1]
	return result

def chrxor(chr1, chr2):
	return chr(ord(chr1)^ord(chr2))

def strxor(str1, str2):
	rlength = min(len(str1),len(str2))
	return [chrxor(str1[i],str2[i]) for i in range(rlength)]

def repKeyXor(string,key):
	return [chrxor(c,key[i%len(key)]) for i,c in enumerate(string)] 


def tryXorBreak(ciphertext,distribution=English1Grams):
	return min([
	{"Text":repKeyXor(ciphertext,char),"Key":char} 
	for char in allCharacters],
	key = lambda result: distribution.surprise(str(result["Text"]).lower())
) 

def indexOfCoincidence(buf):
	matches = 0
	for i in range(len(buf)):
		for j in range(len(buf)):
			if buf[i]==buf[j]: matches += 1
	return matches/(len(buf)**2)

def mutualIndexOfCoincidence(buf1,buf2):
	matches = 0
	for c1 in buf1:
		for c2 in buf2:
			if c1==c2: matches +=1
	return matches/(len(buf1)*len(buf2))

def pad(buf, modulus):
	padlength = (modulus-(len(buf)))%modulus
	if padlength==0: padlength=modulus #append at least 1 byte
	padchar = chr(padlength)
	return buf + padchar*padlength

def rmPad(buf,modulus):
	if len(buf)%modulus != 0: raise Exception("Wrong plaintext length") 
	padChar = buf[-1]
	padLength = ord(padChar)
	s = buf[-padLength:]
	if not all(map(lambda x: x==padChar,s)): raise Exception("Invalid padding")
	return buf[:len(buf)-padLength]
	

blocks = lambda buf, blocksize: [buf[blocksize*i:(blocksize*i+blocksize)] for i in range(len(buf)//blocksize + (1 if len(buf)%blocksize!=0 else 0))]

def distributionFromFunction(operands, function):
	getProb = lambda case: product(project(operands,case))
	resultDict = collect([(function(case), getProb(case)) for case in itertools.product(*operands)])
	return Distribution(resultDict)

def xorDecryptionTable(dist):
	result = {}
	for c in allCharacters:
		clist = [(c1,chrxor(c1,c)) for c1 in dist if chrxor(c1,c) in dist]
		if clist == []: continue
		result[c] = max(clist,key=lambda x: dist[x[0]]*dist[x[1]])
	return result

	
