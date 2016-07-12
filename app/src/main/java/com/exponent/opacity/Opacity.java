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

import com.exponent.androidopacitydemo.ByteUtil;
import com.exponent.androidopacitydemo.Logger;
import com.exponent.androidopacitydemo.MainActivity;
import com.exponent.openssl.Cmac;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashMap;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Provides constants and utility methods for the Opacity protocol.
 */
public class Opacity
{
	public static final String SELECT = "00 A4 04 00";
	public static final String PIV = "A0 00 00 03 08 00 00 10 00";
	public static final String PIV_LENGTH = "09";
	public static final String SELECT_PIV = SELECT + ' ' + PIV_LENGTH + ' ' + PIV + " 00";
	public static final String CBH = "00";
	public static final String IDH = "00 00 00 00 00 00 00 00";
	public static final String GENERAL_AUTHENTICATE = "00 87 27 04";

	public final static String TAG = "Opacity";
	public final static String PROVIDER = "AndroidOpenSSL";
	public final static String CBC_TRANSFORMATION = "AES/CBC/NoPadding";
	public final static String ECB_TRANSFORMATION = "AES/ECB/NoPadding";

	private final static byte[] LE = {0};

	private enum IvFormat { MESSAGE, RESPONSE }

	public static Logger logger;

	/**
	 * Builds a General Authenticate message.
	 */
	public static byte[] buildGeneralAuthenticate(byte[] cbh, byte[] idh, byte[] key)
	{
		// Compute length of: chb + idh + key
		byte[] mm = {(byte) (cbh.length + idh.length + key.length)};

		// Compute length of: "81" + mm + cbh + idh + key + "8200"
		byte[] nn = {(byte) (1 + 1 + (mm[0] & 0xff) + 2)};

		// Compute length of: "7C" + nn + "81" + mm + cbh + idh + key + "8200"
		byte[] ll = {(byte) (1 + 1 + (nn[0] & 0xff))};

		return ByteUtil.concatenate(
				ByteUtil.hexStringToByteArray(GENERAL_AUTHENTICATE),
				ll,
				new byte[]{(byte) 0x7c},
				nn,
				new byte[]{(byte) 0x81},
				mm,
				cbh,
				idh,
				key,
				new byte[]{(byte) 0x82},
				LE,
				LE
		);
	}

	/**
	 * Confirms the RMAC in the supplied AES parameters with that in the supplied data.
	 *
	 * @return true is returned if the RMACs compare
	 */
	public static boolean confirmRmac(AesParameters params, byte[] data)
	{
		Cmac cmac = new Cmac(
				params.sessionKeys.get("rmac"),
				ByteUtil.concatenate(params.rmcv, Arrays.copyOfRange(data, 0, data.length - 10)));
		params.rmcv = cmac.mac;

		byte[] rmcvCheck = Arrays.copyOfRange(params.rmcv, 0, 8);
		byte[] dataCheck = Arrays.copyOfRange(data, data.length - 8, data.length);

		logger.newLine();
		logger.info(TAG, "Check Response CMAC:");
		logger.info(TAG, "    " + ByteUtil.toHexString(rmcvCheck, " "));
		logger.info(TAG, "    " + ByteUtil.toHexString(dataCheck, " "));

		return Arrays.equals(rmcvCheck, dataCheck);
	}

	/**
	 * Encrypts APDU.
	 *
	 * @param le may be null or empty
	 * @return the encrypted APDU
	 */
	public static byte[] encryptApdu(AesParameters params, byte[] ins, byte[] p1, byte[] p2, byte[] message, byte[] le)
			throws GeneralSecurityException
	{
		logger.info(TAG, "ENC Counter: " + String.format("%032X", params.count));

		byte[] msgIv = getIv(params.count, params.ivCipher, IvFormat.MESSAGE);
		logger.info(TAG, "IV: " + ByteUtil.toHexString(msgIv, " "));

		Cipher msgCipher = Cipher.getInstance(CBC_TRANSFORMATION, PROVIDER);
		SecretKeySpec keySpec = new SecretKeySpec(params.sessionKeys.get("enc"), "AES");
		msgCipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(msgIv));

		byte[] encryptedMessage = getEncryptedMessage(message, msgCipher);
		logger.info(TAG, "Encrypted message: " + ByteUtil.toHexString(encryptedMessage, " "));

		Cmac encryptedMessageCmac = getMessageCmac(params, new byte[]{(byte) 0x0c}, ins, p1, p2, encryptedMessage, le);
		params.mcv = encryptedMessageCmac.mac;
		logger.info(TAG, "Encrypted message CMAC and MCV: " + ByteUtil.toHexString(params.mcv, " "));

		byte[] berTlvCmac = ByteUtil.concatenate(ByteUtil.hexStringToByteArray("8E 08"), Arrays.copyOfRange(params.mcv, 0, 8));
		logger.info(TAG, "BER-TLV CMAC: " + ByteUtil.toHexString(berTlvCmac, " "));

		byte[] fullMessage;
		if (null == le || le.length == 0)
		{
			fullMessage = ByteUtil.concatenate(
					new byte[] { (byte) 0x0c },
					ins,
					p1,
					p2,
					new byte[] { (byte) (encryptedMessage.length + berTlvCmac.length) },
					encryptedMessage,
					berTlvCmac,
					new byte[1]);
		}
		else
		{
			byte[] berTlvLen = ByteUtil.concatenate(
					ByteUtil.hexStringToByteArray(String.format("97 %02x", le.length)),
					le);
			fullMessage = ByteUtil.concatenate(
					new byte[] { (byte) 0x0c },
					ins,
					p1,
					p2,
					new byte[] { (byte) (encryptedMessage.length + berTlvLen.length + berTlvCmac.length) },
					encryptedMessage,
					berTlvLen,
					berTlvCmac,
					new byte[1]);
		}

		logger.info(TAG, "Full encryption wrapped APDU: " + ByteUtil.toHexString(fullMessage, " "));

		return fullMessage;
	}

	/**
	 * Decrypts the provided message response.
	 *
	 * @return null if there is no response to decrypt
	 * @throws GeneralSecurityException
	 */
	public static byte[] getDecryptedResponse(AesParameters params, byte[] data)
			throws GeneralSecurityException
	{
		if (data.length < 15)
		{
			return null;
		}

		byte[] msgIv = getIv(params.count, params.ivCipher, IvFormat.RESPONSE);
		//Legacy print for debugging
		//logger.info(TAG, "IV: " + ByteUtil.toHexString(msgIv, " "));

		Cipher cipher = Cipher.getInstance(CBC_TRANSFORMATION, PROVIDER);
		SecretKeySpec keySpec = new SecretKeySpec(params.sessionKeys.get("enc"), "AES");
		cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(msgIv));

		@SuppressWarnings("UnnecessaryLocalVariable")
		byte[] decryptedResponse = (data[1] & 0xff) < 127
				? cipher.doFinal(Arrays.copyOfRange(data, 3, data.length - 14))
				: cipher.doFinal(Arrays.copyOfRange(data, (data[1] & 0xff) - 0x7d, data.length - 14));

		return decryptedResponse;
	}

	private static byte[] getEncryptedMessage(byte[] message, Cipher cipher)
			throws GeneralSecurityException
	{
		byte[] paddedMessage = pad(message, cipher);
		logger.info(TAG, "Padded message: " + ByteUtil.toHexString(paddedMessage, " "));

		byte[] encryptedMessage = cipher.doFinal(paddedMessage);
		byte[] header = ByteUtil.hexStringToByteArray(String.format("87 %02X 01", encryptedMessage.length + 1));
		return ByteUtil.concatenate(header, encryptedMessage);
	}

	private static byte[] getIv(int count, Cipher cipher, IvFormat format)
			throws GeneralSecurityException
	{
		byte[] data = IvFormat.MESSAGE == format
				? ByteUtil.hexStringToByteArray(String.format("%032X", count))
				: ByteUtil.hexStringToByteArray(String.format("80 %030X", count));
		return cipher.doFinal(data);
	}

	private static Cmac getMessageCmac(AesParameters params, byte[] cla, byte[] ins, byte[] p1, byte[] p2, byte[] enc, byte[] le)
	{
		byte[] message;
		if (null == le || 0 == le.length)
		{
			message = ByteUtil.concatenate(
					params.mcv,
					new byte[] { (byte)0x0c },
					ins,
					p1,
					p2,
					new byte[] { (byte)0x80 },
					new byte[11],
					enc);
		}
		else
		{
			message = ByteUtil.concatenate(
					params.mcv,
					cla,
					ins,
					p1,
					p2,
					new byte[] { (byte)0x80 },
					new byte[11],
					enc,
					ByteUtil.hexStringToByteArray(String.format("97 %02x", le.length)),
					le);
		}

		return new Cmac(params.sessionKeys.get("mac"), message);
	}

	/**
	 * KDF function defined in NIST 800-56A 5.8.1
	 *
	 * @param z         shared secret key
	 * @param length    length of number of bits of derived keying material (512 for NIST 800-73-4 4.1.6)
	 * @param otherInfo construction of byte string defined in NIST 800-73-4 4.1.6
	 */
	public static byte[] kdf(byte[] z, int length, byte[] otherInfo)
	{
		MessageDigest digest;
		try
		{
			digest = MessageDigest.getInstance("sha256");
		}
		catch (Exception e)
		{
			MainActivity.logger.error(TAG, "Unable to create sha256 digest", e);
			return null;
		}

		// Omitted: Source data and derived keying material length checks

		int hashLength = 256;
		int reps = (int) Math.ceil((double) length / (double) hashLength);
		byte[] output = null;
		for (int i = 1; i < reps; i++)
		{
			digest.update(ByteUtil.hexStringToByteArray(String.format("%08X", i)));
			digest.update(z);
			output = ByteUtil.concatenate(output, digest.digest(otherInfo));
			digest.reset();
		}

		digest.update(ByteUtil.hexStringToByteArray(String.format("%08X", reps)));
		digest.update(z);
		byte[] b = digest.digest(otherInfo);
		if (length % hashLength != 0)
		{
			b = Arrays.copyOfRange(b, 0, (length % hashLength) / 8);
		}
		output = ByteUtil.concatenate(output, b);

		return output;
	}

	/**
	 * Builds formatted dictionary for secret keys from derived keying material from KDF
	 *
	 * @param keyingMaterial map of keying material
	 * @return a map with keys "cfrm", "mac", "enc", "rmac"
	 */
	public static HashMap<String, byte[]> kdfToDict(byte[] keyingMaterial)
	{
		HashMap<String, byte[]> result = new HashMap<>();
		result.put("cfrm", Arrays.copyOfRange(keyingMaterial, 0, 16));
		result.put("mac", Arrays.copyOfRange(keyingMaterial, 16, 32));
		result.put("enc", Arrays.copyOfRange(keyingMaterial, 32, 48));
		result.put("rmac", Arrays.copyOfRange(keyingMaterial, 48, 64));

		return result;
	}

	/**
	 * Pads the provided byte array according to the block size of the provided cipher.
	 *
	 * @return the padded byte array
	 */
	private static byte[] pad(byte[] s, Cipher cipher)
	{
		// Padding as defined by NIST SP800-73-4 Part 2 Page 32
		int padLength = (s.length + 1) % cipher.getBlockSize();
		padLength = 0 == padLength ? 0 : cipher.getBlockSize() - padLength;
		byte[] pad = new byte[padLength];
		return ByteUtil.concatenate(s, new byte[] { (byte)0x80 }, pad);
	}
}
