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

import com.exponent.androidopacitydemo.MainActivity;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * This is the result of parsing the response to a GENERAL_AUTHENTICATE command.
 */
public class CardSignature
{
	public final byte[] cb;
	public final byte[] nonce;
	public final byte[] cryptogram;
	public final byte[] issuerId;
	public final byte[] guid;
	public final byte[] algorithmOID;
	public final byte[] publicKey;
	public final byte[] cvc;
	public final byte[] message;
	public final byte[] id;

	/**
	 * Create a new instance with the given properties.
	 */
	public CardSignature(byte[] cb, byte[] nonce, byte[] cryptogram, byte[] issuerId,
						 byte[] guid, byte[] algorithmOID, byte[] publicKey, byte[] cvc,
						 byte[] message, byte[] id)
	{
		this.cb = cb;
		this.nonce = nonce;
		this.cryptogram = cryptogram;
		this.issuerId = issuerId;
		this.guid = guid;
		this.algorithmOID = algorithmOID;
		this.publicKey = publicKey;
		this.cvc = cvc;
		this.message = message;
		this.id = id;
	}

	/**
	 * Returns a new instance created by parsing the given message.
	 */
	public static CardSignature parse(byte[] data)
	{
		int start = 6;
		int end = start + 1;
		byte[] cb = Arrays.copyOfRange(data, start, end);

		start = end;
		end = start + 16;
		byte[] nonce = Arrays.copyOfRange(data, start, end);

		start = end;
		end = start + 16;
		byte[] cryptogram = Arrays.copyOfRange(data, start, end);

		start = end;
		byte[] id;
		try
		{
			MessageDigest md = MessageDigest.getInstance("sha256");
			byte[] digest = md.digest(Arrays.copyOfRange(data, start, data.length));
			id = Arrays.copyOfRange(digest, 0, 8);
		}
		catch (NoSuchAlgorithmException e)
		{
			MainActivity.logger.error(Opacity.TAG, "Unable to create sha256 digest", e);
			id = new byte[8];
		}

		start = end + 8;
		end = start + (data[start - 1] & 0xff);
		byte[] issuerId = Arrays.copyOfRange(data, start, end);

		start = end + 3;
		end = start + (data[start - 1] & 0xff);
		byte[] guid = Arrays.copyOfRange(data, start, end);

		start = end + 5;
		end = start + (data[start - 1] & 0xff);
		byte[] algorithmOID = Arrays.copyOfRange(data, start, end);

		start = end + 2;
		end = start + (data[start - 1] & 0xff);
		byte[] publicKey = Arrays.copyOfRange(data, start, end);

		start = end + 7;
		end = start + (data[start - 1] & 0xff);
		byte[] cvc = Arrays.copyOfRange(data, start, end);

		byte[] message = Arrays.copyOfRange(data, 6 + 1 + 16 + 16 + 2, start - 3);

		return new CardSignature(cb, nonce, cryptogram, issuerId, guid, algorithmOID, publicKey, cvc, message, id);
	}
}
