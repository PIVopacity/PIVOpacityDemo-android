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

package com.exponent.opacity;

import java.security.GeneralSecurityException;
import java.util.HashMap;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * Parameters for AES operations.
 */
public class AesParameters
{
	public int count;
	public byte[] mcv;
	public byte[] rmcv;
	public HashMap<String, byte[]> sessionKeys;
	public Cipher ivCipher;

	public AesParameters(int count, byte[] mcv, byte[] rmcv, HashMap<String, byte[]> sessionKeys)
			throws GeneralSecurityException
	{
		this.count = count;
		this.mcv = mcv;
		this.rmcv = rmcv;
		this.sessionKeys = sessionKeys;

		ivCipher = Cipher.getInstance(Opacity.ECB_TRANSFORMATION, Opacity.PROVIDER);
		SecretKeySpec keySpec = new SecretKeySpec(sessionKeys.get("enc"), "AES");
		ivCipher.init(Cipher.ENCRYPT_MODE, keySpec);
	}
}
