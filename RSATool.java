import java.io.*;
import java.math.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/**
 * This class provides an implementation of 1024-bit RSA-OAEP.
 *
 * @author Mike Jacobson
 * @version 1.0, October 23, 2013
 */
public class RSATool {
    // OAEP constants
    private final static int K = 128;   // size of RSA modulus in bytes
    private final static int K0 = 16;  // K0 in bytes
    private final static int K1 = 16;  // K1 in bytes

    // RSA key data
    private BigInteger n;
    private BigInteger e, d, p, q;

    // Chinese remainder theorem speed up data
    private BigInteger dp, dq, px, qy;

    // SecureRandom for OAEP and key generation
    private SecureRandom rnd;

    private boolean debug = false;



    /**
     * Utility for printing protocol messages
     * @param s protocol message to be printed
     */
    private void debug(String s) {
	if(debug) 
	    System.out.println("Debug RSA: " + s);
    }
    
    /**
     * Generates sophie germain prime p such that
     * p = 2s+1 where s is a prime number
     *
     * @return prime p of the form p = 2s+1
     */
    private BigInteger generateStrongPrime() {
        BigInteger p, s;
        int bits = 8*K/2; // Half the number of bits as the modulus
        
        do {
            s = BigInteger.probablePrime(bits-1, rnd);
            p = s.multiply(BigInteger.valueOf(2)).add(BigInteger.ONE);
        } while(!p.isProbablePrime(CryptoUtilities.CERTAINTY));
        
        return p;
    }


    /**
     * G(M) = 1st K-K0 bytes of successive applications of SHA1 to M
     */
    private byte[] G(byte[] M) {
        MessageDigest sha1 = null;
	try {
	    sha1 = MessageDigest.getInstance("SHA1");
	}
	catch (NoSuchAlgorithmException e) {
	    System.out.println(e);
	    System.exit(1);
	}


	byte[] output = new byte[K-K0];
	byte[] input = M;

	int numBytes = 0;
	while (numBytes < K-K0) {
          byte[] hashval = sha1.digest(input);

	  if (numBytes + 20 < K-K0)
	      System.arraycopy(hashval,0,output,numBytes,K0);
	  else
	      System.arraycopy(hashval,0,output,numBytes,K-K0-numBytes);

	  numBytes += 20;
	  input = hashval;
	}

	return output;
    }



    /**
     * H(M) = the 1st K0 bytes of SHA1(M)
     */
    private byte[] H(byte[] M) {
        MessageDigest sha1 = null;
	try {
	    sha1 = MessageDigest.getInstance("SHA1");
	}
	catch (NoSuchAlgorithmException e) {
	    System.out.println(e);
	    System.exit(1);
	}

        byte[] hashval = sha1.digest(M);
 
	byte[] output = new byte[K0];
	System.arraycopy(hashval,0,output,0,K0);

	return output;
    }



    /**
     * Construct instance for decryption.  Generates both public and private key data.
     *
     */
    public RSATool(boolean setDebug) {
        debug("Initializing RSA...");
        
        // set the debug flag
        debug = setDebug;
        
        rnd = new SecureRandom();
        
        // Set e = 3 (must use secure padding)
        e = BigInteger.valueOf(3);
        debug("Using encryption key e = " + e);
        
        
        BigInteger pMinusOne;
        BigInteger qMinusOne;
        BigInteger phi;
        
        BigInteger diffMin = BigInteger.valueOf(2).pow(128);
        BigInteger dex4;
        
        boolean firstLoop = true;
        do {
            if(!firstLoop) {
                debug("d < n^0.25 re-generating parameters...\n");
            }
            
            // Find modulus that is compatible with e
            firstLoop = true;
            do {
                if(!firstLoop) {
                    debug("gcd(e, phi(n)) != 1 re-generating parameters...\n");
                }
                
                // Generate two strong primes p and q
                p = generateStrongPrime();
                debug("Generated prime p = " + p);
                
                // Ensure |p-q| > 2^128
                BigInteger diff;
                do {
                    q = generateStrongPrime();
                    diff = p.subtract(q).abs();
                } while(diff.compareTo(diffMin) < 0);
                debug("Generated prime q = " + q);
                
                // n = pq
                n = p.multiply(q);
                debug("RSA Modulus n = " + n);
                
                // Compute phi(n) = (p-1)(q-1)
                pMinusOne = p.subtract(BigInteger.ONE);
                qMinusOne = q.subtract(BigInteger.ONE);
                phi       = pMinusOne.multiply(qMinusOne);
                debug("Computed phi(n) = " + phi);
                
                firstLoop = false;
            } while(e.gcd(phi).compareTo(BigInteger.ONE) != 0);
            
            
            // Solve ed \equiv 1 mod phi(n) to find decryption key d
            // ensure d > n^0.25
            d = e.modInverse(phi);
            debug("Decryption key candidiate d = " + d);
            
            dex4 = d.pow(4);
            firstLoop = false;
        } while(dex4.compareTo(n) < 0);
        debug("Using decryption key d = " + d);
        
        // Store parameters for chinese remainder theorem
        // decryption speed up
        dp = d.mod(pMinusOne);
        dq = d.mod(qMinusOne);
        px = p.modInverse(q).multiply(p);
        qy = q.modInverse(p).multiply(q);
        
        debug("dp = " + dp);
        debug("dq = " + dq);
        debug("px = " + px);
        debug("qy = " + qy);
        debug("RSA setup complete.\n");
    }


    /**
     * Construct instance for encryption, with n and e supplied as parameters.  No
     * key generation is performed - assuming that only a public key is loaded
     * for encryption.
     */
    public RSATool(BigInteger new_n, BigInteger new_e, boolean setDebug) {
        // set the debug flag
        debug = setDebug;
        
        // initialize random number generator
        rnd = new SecureRandom();
        
        n = new_n;
        e = new_e;
        
        d = p = q = null;
        
        dp = dq = px = qy = null;
    }
    


    public BigInteger get_n() {
        return n;
    }

    public BigInteger get_e() {
        return e;
    }
    
    
    /**
     * Computes the xor of two byte array's, if the array's
     * are not the same size only up to the smaller one's
     * size bytes are used
     *
     * @return the result of xor'ing b1 and b2
     */
    private byte[] xorBytes(byte[] b1, byte[] b2) {
        int min = (b1.length < b2.length) ? b1.length : b2.length;
        byte[] result = new byte[min];
        
        for(int i=0; i < min; i++) {
            result[i] = (byte)(b1[i] ^ b2[i]);
        }
        
        return result;
    }



    /**
     * Encrypts the given byte array using RSA-OAEP.
     *
     *
     * @param plaintext  byte array representing the plaintext
     * @throw IllegalArgumentException if the plaintext is longer than K-K0-K1 bytes
     * @return resulting ciphertext
     */
    public byte[] encrypt(byte[] plaintext) {
        debug("In RSA encrypt");
        
        // make sure plaintext fits into one block
        if (plaintext.length > K-K0-K1) {
            throw new IllegalArgumentException("plaintext longer than one block");
        }
        
        debug("Padding...");
        
        // RSA encrypt with OAEP padding
        BigInteger oaepPlaintext;
        boolean firstLoop = true;
        
        do {
            if(!firstLoop) {
                debug("Padding failed. (s||t) was not smaller than the RSA modulus. retrying...\n");
            }
            
            // 1) Generate random k0-bit number r (here K0 is k0 in bytes)
            byte[] r = new byte[K0];
            rnd.nextBytes(r);
            debug("Generated r = " + new BigInteger(r));
            
            // 2) Compute s = (M||0^k1) xor G(r)
            byte[] s = new byte[K-K0];
            System.arraycopy(plaintext, 0, s, 0, plaintext.length);
            
            byte[] gofr = G(r);
            debug("G(r) = " + new BigInteger(gofr));
            
            s = xorBytes(s, gofr);
            debug("s = " + CryptoUtilities.toHexString(s));
            
            // 3) Compute t = r xor H(s) and appedn to s
            byte[] hofs = H(s);
            debug("H(s) = " + new BigInteger(hofs));
            
            byte[] t = xorBytes(r, hofs);
            debug("t = " + CryptoUtilities.toHexString(t));
            
            // Using K+1 here since by keeping st[0] all 0's
            // BigInteger won't misinterpret the LSB as a
            // sign bit
            byte[] st = new byte[K+1];
            System.arraycopy(s, 0, st, 1, K-K0);
            System.arraycopy(t, 0, st, K-K0+1, K0);
            
            oaepPlaintext = new BigInteger(st);
            debug("Computed (s||t) = " + oaepPlaintext);
            
            // Make sure s||t is smaller than RSA modulus
            // otherwise re-select r and try again
            firstLoop = false;
        } while(oaepPlaintext.compareTo(n) >= 0);
        
        debug("Padding complete. Encrypting (s||t)");
        BigInteger ciphertext = oaepPlaintext.modPow(e, n);
        debug("Ciphertext = " + ciphertext);
        
        return ciphertext.toByteArray();
    }


    /**
     * Decrypts the given byte array using RSA.
     *
     *
     * @param ciphertext  byte array representing the ciphertext
     * @throw IllegalArgumentException if the ciphertext is not valid
     * @throw IllegalStateException if the class is not initialized for decryption
     * @return resulting plaintexttext
     */
    public byte[] decrypt(byte[] ciphertext) {
        debug("In RSA decrypt");
        
        // make sure class is initialized for decryption
        if (d == null) {
            throw new IllegalStateException("RSA class not initialized for decryption");
        }
        
        BigInteger c = new BigInteger(ciphertext);
        if(c.compareTo(n) >= 0) {
            throw new IllegalArgumentException("plaintext does not fit into one block");
        }
        
        debug("Decrypting (s||t)^e = " + c);
        
        // OAEP decryption using chinese remainder theorem
        BigInteger mp = c.modPow(dp, p);
        BigInteger mq = c.modPow(dq, q);
        
        BigInteger oaepPlaintext = mq.multiply(px).add(mp.multiply(qy)).mod(n);
        
        // OAEP padding check
        //
        // 2) Compute u = t xor H(s) and v = s xor G(u)
        byte[] st = oaepPlaintext.toByteArray();
        byte[] s = new byte[K-K0];
        byte[] t = new byte[K0];
        
        System.arraycopy(st, 0, s, 0, K-K0);
        System.arraycopy(st, K-K0, t, 0, K0);
        
        debug("s = " + CryptoUtilities.toHexString(s));
        debug("t = " + CryptoUtilities.toHexString(t));
        
        byte[] hofs = H(s);
        debug("H(s) = " + new BigInteger(hofs));
        
        byte[] u = xorBytes(t, hofs);
        debug("u = " + new BigInteger(u));
        
        byte[] gofu = G(u);
        debug("G(u) = " + new BigInteger(gofu));
        
        byte[] v = xorBytes(s, gofu);
        debug("v = " + new BigInteger(v));
        
        // 3) Output M if v = (M||0^k1) (i.e. decrypted message has required
        //    redundancy), otherwise reject as invalid
        for(int i=v.length-1; i>=v.length-K1; i--) {
            if(v[i] != 0) {
                throw new IllegalArgumentException("Invalid ciphertext padding");
            }
        }
        
        BigInteger plaintext = new BigInteger(v);
        return plaintext.toByteArray();
    }
}
