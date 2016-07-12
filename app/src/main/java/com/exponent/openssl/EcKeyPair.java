/*
MIT License

Copyright (c) 2016 United States Government

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Written by Christopher Williams, Ph.D. (cwilliams@exponent.com) & John Koehring (jkoehring@exponent.com)
*/

package com.exponent.openssl;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * This class contains Elliptic Curve key pair functionality.
 *
 * The hard labor is done in the OpenSSL library accessed through JNI.
 * Although not used directly here or in the JNI C code, the corresponding
 * header (.h) file was created using the following command. This command
 * was run in the jni parent directory (app/src/main) and the CLASSPATH
 * environment variable included ..\..\build\intermediates\classes\arm7\debug.
 *
 * "%JAVA_HOME%\bin\javah" -d jni -verbose -stubs -jni com.exponent..openssl.EcKeyPair
 */
public class EcKeyPair
{
	public int curveId;
	public byte[] publicKeyX;
	public byte[] publicKeyY;
	public byte[] privateKey;
	public String error;

	private static Map<String, Integer> curves;
	static
	{
		curves = new HashMap<>();
		curves.put("secp112r1", 704);
		curves.put("secp112r2", 705);
		curves.put("secp128r1", 706);
		curves.put("secp128r2", 707);
		curves.put("secp160k1", 708);
		curves.put("secp160r1", 709);
		curves.put("secp160r2", 710);
		curves.put("secp192k1", 711);
		curves.put("secp224k1", 712);
		curves.put("secp224r1", 713);
		curves.put("secp256k1", 714);
		curves.put("secp384r1", 715);
		curves.put("secp521r1", 716);
		curves.put("sect113r1", 717);
		curves.put("sect113r2", 718);
		curves.put("sect131r1", 719);
		curves.put("sect131r2", 720);
		curves.put("sect163k1", 721);
		curves.put("sect163r1", 722);
		curves.put("sect163r2", 723);
		curves.put("sect193r1", 724);
		curves.put("sect193r2", 725);
		curves.put("sect233k1", 726);
		curves.put("sect233r1", 727);
		curves.put("sect239k1", 728);
		curves.put("sect283k1", 729);
		curves.put("sect283r1", 730);
		curves.put("sect409k1", 731);
		curves.put("sect409r1", 732);
		curves.put("sect571k1", 733);
		curves.put("sect571r1", 734);
		curves.put("prime256v1", 415);

		System.loadLibrary("exp-openssl");
	}

	/**
	 * Constructs a key pair given the constituent parts
	 */
	public EcKeyPair(int curveId, byte[] privateKey, byte[] encodedPublicKey)
	{
		this.curveId = curveId;
		this.privateKey = (null == privateKey) ? null : Arrays.copyOf(privateKey, privateKey.length);
		decodePublicKey(encodedPublicKey);
	}

	/**
	 * Generates a new key pair using an elliptic curve with the given name.
	 * @param curveName see the hash map, above, for the supported curve names
	 * @return null is returned if the key pair cannot be generated
	 */
	public static EcKeyPair generate(String curveName)
	{
		Integer i = curves.get(curveName);
		return null == i ? null : generate(i);
	}

	private native static EcKeyPair generate(int curveId);

	/**
	 * Checks the keys contained herein for validity:
	 * @return true is returned if the keys are valid
	 */
	public native boolean checkKey();

	/**
	 * Decodes the provided public key into its X and Y parts.
	 */
	public void decodePublicKey(byte[] key)
	{
		if (null == key)
		{
			publicKeyX = null;
			publicKeyY = null;
			return;
		}

		if (key[0] != 0x04)
		{
			throw new IllegalArgumentException("Encoded public key starts with " + key[0] + ", not expected 0x04");
		}

		int length = (key.length - 1) / 2;
		publicKeyX = new byte[length];
		publicKeyY = new byte[length];
		System.arraycopy(key, 1, publicKeyX, 0, length);
		System.arraycopy(key, 1 + length, publicKeyY, 0, length);
	}

	public native byte[] getEcdhKey();

	/**
	 * Returns the encoded public key.
	 */
	public byte[] getEncodedPublicKey()
	{
		byte[] key = new byte[1 + publicKeyX.length + publicKeyY.length];
		int i = 0;
		key[i++] = 0x04;
		System.arraycopy(publicKeyX, 0, key, i, publicKeyX.length);
		i += publicKeyX.length;
		System.arraycopy(publicKeyY, 0, key, i, publicKeyY.length);

		return key;
	}
}
