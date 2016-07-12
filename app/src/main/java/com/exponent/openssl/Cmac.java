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

import com.exponent.androidopacitydemo.ByteUtil;

import java.util.Arrays;

/**
 * Support for generating amd verifying CMACs.
 *
 * The hard labor is done in the OpenSSL library accessed through JNI.
 * Although not used directly here or in the JNI C code, the corresponding
 * header (.h) file was created using the following command. This command
 * was run in the jni parent directory (app/src/main) and the CLASSPATH
 * environment variable included ..\..\build\intermediates\classes\arm7\debug.
 *
 * "%JAVA_HOME%\bin\javah" -d jni -verbose -stubs -jni com.exponent..openssl.Cmac
 */
public class Cmac
{
	public byte[] key;
	public byte[] message;
	public byte[] mac;
	public String error;

	public final static String NIST_TEST_KEY = "2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c";
	public final static String NIST_TEST_MESSAGE = "";
	public final static String NIST_TEST_MAC = "bb 1d 69 29 e9 59 37 28 7f a3 7d 12 9b 75 67 46";

	/**
	 * Creates a new instance using the given key and message.
	 */
	public Cmac(byte[] key, byte[] message)
	{
		this.key = Arrays.copyOf(key, key.length);
		this.message = Arrays.copyOf(message, message.length);
		generate();
	}

	/**
	 * Checks the CMAC implementation against NIST test data. NIST SP 800-38B Appendix D.1 (p.15)
	 */
	public static boolean nistCheck()
	{
		Cmac cmac = new Cmac(ByteUtil.hexStringToByteArray(NIST_TEST_KEY), ByteUtil.hexStringToByteArray(NIST_TEST_MESSAGE));
		return (null == cmac.error && cmac.verify(ByteUtil.hexStringToByteArray(NIST_TEST_MAC)));
	}

	/**
	 * Verifies generated MAC against provided expected MAC.
	 * @return true if the two MACs are the same
	 */
	public boolean verify(byte[] expectedMac)
	{
		return Arrays.equals(mac, expectedMac);
	}

	/**
	 * Generates the MAC using AES-128.
	 */
	public native void generate();
}
