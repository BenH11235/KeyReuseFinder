# KeyReuseFinder

KeyReuseFinder is a smallish command-line tool for finding instances of stream cipher key reuse.

Stream ciphers are ciphers that use the encryption key as a random seed, and from it generate a pseudorandom keystream which is then XORed with the plaintext to create the ciphertext. The most commonly used stream cipher is RC4, which is particularly common in malware since it is easy to implement.

A particular issue with stream ciphers is that using the same key *twice* to encrypt two *differen* plaintexts is a very bad idea. Suppose you call the two plaintexts *p1* and *p2*, and the key *k*; then the respective ciphertexts will be *c1=p1^k* and *c2=p2^k*. These two ciphertexts will be available to an eavesdropper, who can compute their XOR and obtain *p1^k^p2^k = p1^p2* (since the XOR operation is commutative, and two XORs with the same constant- in this case *k* - cancel each other out). This is a catastrophic data leak, and in many cases, it makes it possible for the attacker to recover large amounts of plaintext.

There are two stages to every attack. The second stage is the attack. The first, and perhaps less notorious, is finding out that there's something to attack in the first place. To employ an attack against a key-reuse vulnerability, one must first know that key-reuse occurred, and have access to the vulnerable ciphertexts. Often, one will have access to a buffer of apparent noise, with no prior information. This is the gap KeyReuseFinder attempts to help bridge.

What KeyReuseFinder does, basically, is iterate over all possible XORed pairs of bytes from the input buffer. Since plaintext has a different per-byte distribution from pseudorandom noise, so will bytes of the form *p1^p2*, where both *p1* and *p2* are plaintext bytes. But this is exactly what one gets by XORing two bytes of ciphertext that were encrypted by XORing with the same key byte. Therefore, two different plaintexts that were encrypted using the same keystream will appear as linear 'streaks' in the space of XORed input bytes.

KeyReuseFinder uses a Bayesian decision model to decide if and where key reuse has occurred. It sets a threshold for evidence (log-odds) equal to twice the binary logarithm of the input length, minus one. This is basically a 'normalizing factor': loosely speaking, since there are *n^2* characters, there is an order of magnitude of n^2 'opportunities' for mere coincidences to happen, so when we run across an event, we deem it significant if it is a one-in-*n^2* coincidence. The "-1" factor is because the space of XORed input bytes is symmetric, and so this 'opportunity space' is cut by half (and indeed, we only scan half of it, given that the other half is identical).

While the clasical application of this tool would be to scenarios involving a proper stream cipher, it applies to any situation where encryption is performed by XORing against a pseudorandom string, and this includes other methods of encryption - for example, block ciphers in CTR mode and One Time Pads.

More information can be found in [the whitepaper](https://www.dropbox.com/s/dkfyk5b0bnsy3dq/exploiting-stream-cipher-key-reuse-in-malware-traffic.pdf?dl=0) and in the recorded talk ['Finding the Weak Crypto Needle in a Byte Haystack'](https://www.youtube.com/watch?v=GQOam3XJdWg), given at 31C3 (31st Chaos Communication Congress in Hamburg).

## Installation

Clone the repository to your local directory of choice by running git from the command line:

`git clone https://github.com/BenH11235/KeyReuseFinder`

Alternately, download a zip of the source code via HTTP: click [here](https://github.com/BenH11235/KeyReuseFinder/archive/master.zip).

KeyReuseFinder requires Python 2.7.X with the [numpy](http://numpy.org) package installed. See [here](http://www.scipy.org/install.html) for instructions for how to get Numpy depending on your operating system. To check if you have numpy installed, run Python from the command line and try:

`import numpy`

If you have numpy installed, this will pass silently with no output. If you do not have numpy installed, Python will throw an ImportError.

## Usage

From the command line, execute:

`path-to-python KeyReuseFinder.py [-h] [-d image_dump_path] inputFilePath`

path-to-python should be replaced with the path to your python interpreter executable. On linux and OSX you can run "which python" to find out where this is. On Windows environments, the default location is C:\Python27\python.exe.

inputFilePath should be replaced with the path to a file containing the input buffer, and (optionally) image_dump_path is a location where KeyReuseFinder will dump a 'heat visualization' of the input bytes XOR space. Instances of key reuse should appear as red diagonals apart from the main diagonal.

## History

2015-05-13, v0.1: First upload of KeyReuseFinder

