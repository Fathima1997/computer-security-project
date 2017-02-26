# 480 Project 1 – CCA2 Encryption

## Synopsis

In this assignment you are asked to build a public key cryptosystem using a _key encapsulation mechanism_. The idea is that by using a hybrid encryption scheme (combining an asymmetric and symmetric system), we can produce a highly efficient public-key system, thus getting the best of both worlds.

### Goals for the student

*   Understand different security definitions for cryptosystems.
*   Hands on experience programming with a variety of crypto building blocks (symmetric encryption, asymmetric encryption, hashing, MACs…).

## The cryptosystem

### Step 1: CCA2 symmetric encryption

First, we build CCA2 symmetric encryption from the weaker assumption of CPA encryption. Let <span class="math inline">_f_<sub>_k_</sub></span> denote our symmetric encryption with key <span class="math inline">_k_</span>, and let <span class="math inline">_h_<sub>_k_′</sub></span> denote our MAC with key <span class="math inline">_k_′</span>. To encrypt a bit string <span class="math inline">_m_</span>, we set <span class="math inline">_c_ = _f_<sub>_k_</sub>(_m_)</span>, and set the ciphertext to the pair <span class="math inline">(_c_, _h_<sub>_k_′</sub>(_c_))</span>. Decryption of a pair <span class="math inline">(_x_, _y_)</span> first makes sure that <span class="math inline">_h_<sub>_k_′</sub>(_x_)=_y_</span>; if this fails, output <span class="math inline">⊥</span>, otherwise decrypt <span class="math inline">_x_</span> and output the result.

Given that <span class="math inline">_f_<sub>_k_</sub></span> is CPA secure and that <span class="math inline">_h_<sub>_k_′</sub></span> is pseudorandom, it is well known that this construction is CCA2 secure. The key idea is that the MAC makes the adversary’s decryption queries useless: for any ciphertext which was not the output of the encryption oracle, the output will invariably be <span class="math inline">⊥</span>: To find a valid ciphertext _is_ to forge the MAC. Formal proof is left as an exercise (use any CCA2 adversary to build a CPA adversary with almost the same advantage by emulating a CCA2 _challenger_).

### Step 2: KEM to make it public-key

The idea is very simple: create a random key for the above scheme, encrypt the message you want to send, and then send it, along with a _public-key encryption of the symmetric key_. The analysis is a little tricky though. To preserve the CCA2-ness, we can’t just send a public-key encryption of the key – we need a _key encapsulation mechanism_ which has some special properties. In particular, we need our KEM to have an analogous property to CCA2 for an encryption scheme: an adversary with access to a “decapsulation” oracle (a box that outputs the key from its encapsulation) cannot differentiate between valid encapsulations (where the key corresponds to the ciphertext), and random keys. Obviously the same CCA2 rule of “you can’t decrypt the challenge” applies, but other than that, anything goes.

How to build such a thing? It turns out that all you need is a public key encryption (plain, deterministic RSA works!), a key derivation function (HMAC will do fine), and a hash function (we could use HMAC again, but we must make sure it is with a different key). Letting <span class="math inline">_K__D__F_</span> denote the key derivation function, <span class="math inline">_E_<sub>_p__k_</sub></span> the encryption (with public key <span class="math inline">_p__k_</span>) and letting <span class="math inline">_H_</span> denote the hash, then the KEM construction is as follows: select a random message <span class="math inline">_x_</span> (needs at least as much entropy as your key!) and then let <span class="math inline">_C_ = (_E_<sub>_p__k_</sub>(_x_),_H_(_x_))</span> be the encapsulation, while <span class="math inline">_K__D__F_(_x_)</span> is the key. The “decapsulation” algorithm on input <span class="math inline">_C_ = (_C_<sub>0</sub>, _C_<sub>1</sub>)</span> simply computes <span class="math inline">_x_ = _D_<sub>_p__k_</sub>(_C_<sub>0</sub>)</span>, and outputs <span class="math inline">_K__D__F_(_x_)</span> if <span class="math inline">_H_(_x_)=_C_<sub>1</sub></span>; otherwise it outputs <span class="math inline">⊥</span>. It isn’t too hard to prove this has the property we need. <span class="citation">(See Dent 2003 for the details.)</span>

### Why is the composition CCA2 secure?

There is a nice hybrid-style argument in <span class="citation">(Cramer and Shoup 2003, chap. 7)</span>, but verifying all the details would take us a little off course. Here’s the gist though: how different could the CCA2 game be if we swapped out the encapsulated key with a totally random key for the symmetric encryption? Not very! Even if we gave the adversary the ability to run decapsulation queries, he can’t distinguish the cases (this is exactly our definition of CCA2 for a KEM). But now if the key is random, this is precisely the situation for which we’ve proved CCA2 security of the symmetric scheme. Voila.


### Regarding the C skeleton

To facilitate the development, you can use [GMP](http://gmplib.org/) for the long integer arithmetic needed for RSA, and [OpenSSL](http://www.openssl.org/) for various cryptographic primitives like hashing and symmetric encryption. (_NOTE:_ OpenSSL also contains implementations of RSA of course, but I want you to write this part yourself – it is more educational, and actually quite simple since “plain” RSA suffices for our application.)

I’ve given you a skeleton, as well as some examples that you can draw upon. The stubs that you are supposed to fill out are labeled “TODO”. Unless you have a super-compelling reason, I would recommend that you don’t change the interface.

Building blocks:

*   RSA for PKE. You will implement this yourself. Note that this is the naive, deterministic, un-semantically-secure version. But it will work fine for our KEM.
*   AES for symmetric encryption. You can get this from OpenSSL. We’ll use it in counter mode for optimal speed during encryption. (**Question:** why is cbc mode encryption usually slower than cbc decryption?)
*   HMAC for a MAC. Also available via OpenSSL.

Be sure to read `man 4 random` at some point.

### Hints / even more details

#### What to do when

I’d attack this in the following order:

1.  RSA
2.  SKE (only on buffers)
3.  SKE that works on files
4.  KEM (shouldn’t be too challenging once you have the other pieces)

There are some basic tests for RSA and the memory buffer version of SKE (`ske_encrypt` / `ske_decrypt`) in the `tests/` directory, so those are good to start with. Once you have that working, implement the versions which operate on files. _Hint:_ For this, I would recommend `mmap`. Then you can just hand off the pointers from `mmap` to the simple versions and let the kernel do all the buffering work for you. (Nice, right?) Or if you are lazy, you can also just read the entire file contents into a (potentially huge) buffer. But Zoidberg will be mad at you.

![zoidberg](https://github.com/LinfinityLab/computer-security-project/blob/master/bad-code.jpg)  

#### Extra notes on the KDF for symmetric encryption

_Note:_ for the KEM scheme, both the KDF and the hash function are public. To ensure “orthogonality” of the two, one is implemented via HMAC, but the key is public (it is hard-coded into `ske.c` – see `KDF_KEY`). Note that the KDF should be handled inside of this function:

<div class="sourceCode">

    int ske_keyGen(SKE_KEY* K, unsigned char* entropy, size_t entLen);

</div>

If the `entropy` buffer is supplied, the KDF should be applied to it to derive the key. Thus when implementing `kem_encrypt`, you can take the encapsulated key `x` and supply that as `entropy`. Maybe something like this:

<div class="sourceCode">

    unsigned char* x = malloc(len);
    /* ...fill x with random bytes (which fit in an RSA plaintext)... */
    SKE_KEY SK;
    ske_keyGen(&SK,x,len);
    /* ...now encrypt with SK... */

</div>

#### Basic usage (command line interface)

This is documented via the usage string (as well as by looking at the test script), but here are some examples.

Generate a 2048 bit key, and save to /tmp/testkey{,.pub}:

<div class="sourceCode">

    ./kem-enc -b 2048 -g /tmp/testkey

</div>

Encrypt `file` with the public key and write ciphertext to `ct`:

<div class="sourceCode">

    ./kem-enc -e -i file -o ct -k /tmp/testkey.pub

</div>

Decrypt `ct` with the private key and write plaintext to `file0`:

<div class="sourceCode">

    ./kem-enc -d -i ct -o file0 -k /tmp/testkey

</div>

### Compiling, testing, debugging

As mentioned, there are some test programs in `tests/` for the RSA and SKE components. (You can build these via `make tests`.) For the hybrid KEM scheme, there’s a `kem-test.sh` script. Fill the `tests/data/` directory with some files, and it will check if encrypt and decrypt at least compose to be the identity on those inputs.

### Other languages

If you want to do this in another language (or without the skeleton code), feel free to do so. Keep in mind that your code should speak the same language as the one described in the skeleton. That is,

*   The binary file formats (for keys and ciphertext) should be the same.
*   Your program should understand the same command line arguments.

Moreover, your code cannot assume additional cryptographic functionality beyond what is outlined above. In particular, **you must implement RSA from long integers**. You’re welcome to get your hash functions and AES from somewhere other than OpenSSL, but you can’t rely on things that trivialize any part of the project.

Lastly, you must provide a Makefile and a readme if you don’t use the skeleton, and the Makefile must work on Linux.

# References

<div id="refs" class="references">

<div id="ref-CS2003">

Cramer, Ronald, and Victor Shoup. 2003\. “Design and Analysis of Practical Public-Key Encryption Schemes Secure Against Adaptive Chosen Ciphertext Attack.” _SIAM Journal on Computing_ 33 (1). SIAM: 167–226.

</div>

<div id="ref-dent2003">

Dent, Alex. 2003\. “A Designer’s Guide to KEMs.” _Cryptography and Coding_. Springer, 133–51.

</div>

</div>
