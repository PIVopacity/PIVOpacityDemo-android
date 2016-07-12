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

package com.exponent.androidopacitydemo;

/**
 * General byte handling utilities.
 */
public class ByteUtil
{
	private ByteUtil()
	{
	}

	/**
	 * Concatenates an arbitrary number of byte arrays, returning the result.
	 */
	public static byte[] concatenate(byte[]... byteArrays)
	{
		int resultLength = 0;
		for (byte[] ba : byteArrays)
		{
			resultLength += (null == ba) ? 0 : ba.length;
		}

		byte[] result = new byte[resultLength];

		int idx = 0;
		for (byte[] ba : byteArrays)
		{
			if (ba != null)
			{
				System.arraycopy(ba, 0, result, idx, ba.length);
				idx += ba.length;
			}
		}

		return result;
	}

	/**
	 * Converts a byte to a hex string.
	 */
	public static String toHexString(byte by)
	{
		return String.format("%02X", by & 0xff);
	}

	/**
	 * Converts an array of bytes to a hex string, with no separator between bytes.
	 */
	public static String toHexString(byte[] bytes)
	{
		return toHexString(bytes, null);
	}

	/**
	 * Converts a range of an array of bytes to a hex string, with no separator between bytes.
	 */
	@SuppressWarnings("unused")
	public static String toHexString(byte[] bytes, int start, int end)
	{
		return toHexString(bytes, start, end, null);
	}

	/**
	 * Converts an array of bytes to a hex string, with the specified separator between bytes.
	 */
	public static String toHexString(byte[] bytes, String separator)
	{
		return toHexString(bytes, 0, bytes.length, separator);
	}

	/**
	 * Converts a range of an array of bytes to a hex string, with the specified separator between bytes.
	 */
	public static String toHexString(byte[] bytes, int start, int end, String separator)
	{
		StringBuilder sb = new StringBuilder();
		for (int i = start; i < end; i++)
		{
			if (sb.length() > 0 && null != separator)
			{
				sb.append(' ');
			}
			sb.append(toHexString(bytes[i]));
		}
		return sb.toString();
	}

	/**
	 * Converts a hex string to a byte array.
	 * The string may contain embedded white space.
	 */
	public static byte[] hexStringToByteArray(String s)
	{
		s = s.replaceAll("\\s+", "");
		byte[] data = new byte[s.length() / 2];
		for (int i = 0; i < data.length * 2; i += 2)
		{
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i+1), 16));
		}
		return data;
	}
}
