#! /usr/bin/python

from __future__ import division
from math import log
import crypto
import random
import itertools
import numpy as np
import sys
import argparse

our_pale_attempt_to_represent_minus_infinity = -sys.maxint-1 #minimum integer we can represent

def diagonals(boardsize):
    """Yields a list of sublists of (x,y) coordinates on a 'boardsize'-sized nxn grid.
    Each sublist corresponds to a diagonal on the bottom-right triangular half of the grid.
    Diagonals are iterated bottom-up, and appear leftmost-first."""
    for i in range(boardsize):
        yield [(j+i,j) for j in range(boardsize-i)]

def evidenceLogOdds(char, dist):
    """Gives the log-odd-ratio, in bits, of:
    "character originates in given distribution" vs. 
    "character originates in random distribution"""
    pDist = dist.probOfList([char]) #probability of char in dist
    if pDist==0: 
        return our_pale_attempt_to_represent_minus_infinity
    pRandom = crypto.RandomCharacters.probOfList([char]) #probability of char in random distribution
    result = log(pDist,2)-log(pRandom,2)
    return result

def xtTable(buf,threshold):
    """Given a buffer, this returns an nxn grid where cell (i,j)
    corresponds to the log-odd-ratio of (buf[i] xor buf[j]) appearing in the 
    xorText distribution vs. in the random character distribution."""
    table_size = range(len(buf))
    return [[\
            evidenceLogOdds(crypto.chrxor(buf[i],buf[j]),xorText) 
        for i in table_size]\
    for j in table_size]

def ptVector(buf):
    """Given a buffer, this returns an n-size vector where the ith entry
    corresponds to the log-odd-ratio of buf[i] appearing in the plainText 
    distribution vs. in the random character distribution."""
    return [evidenceLogOdds(c,crypto.softDist) for c in buf]

def partition(nums,goal,breakThreshold):
    """Takes a vector of numbers as input and returns all delimiters of positive 
    number runs that sum up to more than the goal, as long as they are not 
    interrupted by runs of negative numbers that sum up to the breakThreshold"""
    result = [] #used to keep runs we have seen that qualify
    goodVibes = 0 #good vibes collected during current run
    badVibes = 0 #bad vibes collected during current run
    lastGoodVibes = 0 #most recent offset where we have encountered good vibes
    anchor = 0 #starting offset of current run
    for index,num in enumerate(nums):
        if num>0:
            badVibes = 0
            lastGoodVibes = index
        else:
            badVibes+= -num
        if badVibes>=breakThreshold or index==len(nums)-1:
            #too much bad vibes, or EOF -- end current run
            if badVibes<breakThreshold and index==len(nums)-1: 
                #cutoff by EOF edge case
                lastGoodVibes+=1
            if goodVibes>=goal:
                #enough good vibes - run that just finished qualifies
                result.append([anchor,lastGoodVibes])
            anchor = index+1
            goodVibes = 0
        else:
            goodVibes += num 
    return result
	

def findPtruns(buf):
    """Given an input buffer, detects areas likely to be plaintext"""
    return partition(ptVector(buf), threshold, threshold)

def findparallelciphers(buf):
    """Given an input buffer, finds index tuples that are likely to be 
    offsets of different strings that had been XORed with the same keystream"""
    matches = []
    threshold = (2*log(len(buf),2))-1 #bits
    table = xtTable(buf,threshold)
    for diagonal in diagonals(len(buf)):
        if (0,0) in diagonal: continue #trivial diagonal
        values = map(lambda (i,j): table[i][j], diagonal)
        foundRuns = partition(values,threshold,threshold)
        #format our found runs as (offset,length) instead of (start,end)
        newmatches = [(diagonal[start],end-start) for (start,end) in foundRuns]
        matches += newmatches
    #Remove duplicate results (a suffix of a valid match is also a valid match)
    for ((o1,o2),l) in matches:
        for i in range(1,l):
            cand = ((o1+i,o2+i),l-i) 
            if cand not in matches: 
                continue
            matches.remove(cand)
    return matches

def encryptedBySameKeyImplausibility(s1, s2, ptDist):
    s3 = crypto.strxor(s1,s2)
    xorText = crypto.distributionFromFunction(\
            [ptDist]*2, lambda (c1,c2): crypto.chrxor(c1,c2)\
    ) 
    surprise = xorText.surprise(s3)     
    return surprise / float(len(s3))
 



def dumpHeatMap(inputBuffer, outputFile):
    """Generates evidence 'heat map' of string based on its evidence gain table (see xtTable for details)"""
    import png
    table = xtTable(inputBuffer, (2*log(len(inputBuffer),2))-1)
    #collect all evidence values on table, with 'sanity cutoff' of -5, for statistics
    tvals = [\
            table[i][j] for (i,j) in itertools.product(range(len(inputBuffer)),repeat=2)\
    if table[i][j]>-5]
    evidenceMean = np.average(tvals)
    evidenceStdev = np.std(tvals)
    evidenceScore = lambda x : ((x-evidenceMean) / evidenceStdev) #z-score of evidence
    #Mean and stdev of discret uniform distribution
    rgbMean = np.average(range(256))
    rgbStdev = np.std(range(256))
    def cutoff(x):
        if x>255: 
            return 255
        if x<0: 
            return 0
        return x
    #Function to convert level of evidence to pixel color
    epixel = lambda x: (
        cutoff(rgbMean + evidenceScore(x)*rgbStdev),
        0,
        cutoff(rgbMean - evidenceScore(x)*rgbStdev)
    )
    pixels = [
        tuple(
            reduce(
                lambda x,y: x+y,
                [epixel(table[i][len(inputBuffer)-j-1]) for j in range(len(inputBuffer))]
            )
        )	 
    for i in range(len(inputBuffer))
    ]
    f = open(outputFile, 'wb')
    w = png.Writer(len(inputBuffer),len(inputBuffer))
    w.write(f,pixels)
    f.close()


if __name__ == "__main__":
    print encryptedBySameKeyImplausibility("approximation","approximation",crypto.softDist)
    exit(0)
    cli = argparse.ArgumentParser(description="Attempt to detect key reuse in a given file")
    cli.add_argument(
            "-d", 
            type=str, 
            metavar="image_dump_path", 
            help="Output evidence 'heat map' image to specified path"
    )
    cli.add_argument(
            "inputFilePath", 
            metavar="inputFilePath", 
            type=str, 
            help="Path to file containing input buffer"
    )
    args = cli.parse_args()
    
    with open(args.inputFilePath,'r') as fh:
        inputBuffer = fh.readlines()[0]
    
    ptDistribution = crypto.softDist
    threshold = (2*log(len(inputBuffer),2))-1
    xorText = crypto.distributionFromFunction(\
            [ptDistribution]*2, lambda (c1,c2): crypto.chrxor(c1,c2)\
    )
    
    ptxts =  partition(ptVector(inputBuffer), (threshold+1)/2, (threshold+1)/2)
    suspectedReuses = findparallelciphers(inputBuffer)
    
    if suspectedReuses == []: 
        print "No suspected key reuses found"
    else:
        print "Suspected key reuse instances:"
    for item in suspectedReuses:
        print "\tOffsets {} and {}, lenth {}".format(
            item[0][0],
            item[0][1],
            item[1]
        )  
    print "Suspected plaintext intervals found:"
    for item in ptxts:
            print "\tFrom offset {} to offset {}".format(item[0],item[1])
    if args.d is not None:
        dumpHeatMap(inputBuffer,args.d)
