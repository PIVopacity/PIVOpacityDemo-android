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
import com.exponent.androidopacitydemo.Transceiver;


import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import java.util.HashMap;

import javax.crypto.KeyAgreement;


/**
 * Holds the code for opening a secure tunnel for the Opacity protocol.
 */
public class OpacitySecureTunnel
{
	private Logger logger;

	private final static String TAG = "OpacitySecureTunnel";

	private final static String ERROR_TITLE = "Error";

	private final static String CARD_COMM_ERROR = "Error communicating with card: check log for details.";
	private final static String CARD_RESP_ERROR = "Unexpected response from card: check log for details.";
	private final static String CRYPTO_ERROR = "Cryptography error: check log for details.";

	public Integer TunnelCreationTimer;
	public CardSignature cardSignature;

	public OpacitySecureTunnel(Logger logger)
	{
		this.logger = logger;
	}

	public Integer getCreationTime()
	{
		if(TunnelCreationTimer==null)
		{
			return null;
		}
		else
		{
			return TunnelCreationTimer;
		}
	}

	/**
	 * Opens the secure tunnel using the supplied transceiver.
	 *
	 * @param transceiver the mechanism for communicating with the card
	 * @return the session keys (cfrm, mac, enc, rmac) for the secure tunnel
	 * @throws GeneralSecurityException
	 */
	public HashMap<String, byte[]> openTunnel(Transceiver transceiver)
			throws GeneralSecurityException
	{
		long startTime = System.currentTimeMillis();

		// Construct representation of public key required for sending to card:
        // NIST Prime256v1 Constructor if named curve does not exist.
        //EllipticCurve p256v1 = new EllipticCurve(new ECFieldFp(new BigInteger("FFFFFFFF"+"00000001"+"00000000"+"00000000"+"00000000"+"FFFFFFFF"+"FFFFFFFF"+"FFFFFFFF", 16)), new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16), new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16));
        //ECParameterSpec ecSpec = new ECParameterSpec(p256v1,new ECPoint(new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16), new BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16)),new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16), 1);

        ECGenParameterSpec ecSpec = new ECGenParameterSpec("prime256v1");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(ecSpec, new SecureRandom());
        KeyPair pair = kpg.generateKeyPair();
        ECPrivateKey ecPriv = (ECPrivateKey) pair.getPrivate();
        ECPublicKey ecPub = (ECPublicKey) pair.getPublic();

        byte[] hostPrivateKey=Arrays.copyOfRange(ecPriv.getEncoded(),ecPriv.getEncoded().length-70-32,ecPriv.getEncoded().length-70);
        logger.info(TAG,"Private Key: "+ ByteUtil.toHexString(ecPriv.getEncoded()," ")+"\n"+ByteUtil.toHexString(hostPrivateKey," ")+"\n"+ByteUtil.toHexString(ecPriv.getS().toByteArray(), " "));

        byte[] hostPublicKey = Arrays.copyOfRange(ecPub.getEncoded(),ecPub.getEncoded().length-65,ecPub.getEncoded().length);


		logger.newLine();
		logger.info(TAG, "Host Generated prime256v1 Ephemeral Pubic Key: " + ByteUtil.toHexString(hostPublicKey, " "));


		Transceiver.Response response = transceiver.transceive("GENERAL AUTHENTICATE",
				Opacity.buildGeneralAuthenticate(
						ByteUtil.hexStringToByteArray(Opacity.CBH),
						ByteUtil.hexStringToByteArray(Opacity.IDH),
						hostPublicKey
				));
		if (null == response)
		{
			logger.alert(CARD_COMM_ERROR, ERROR_TITLE);
			transceiver.close();
			return null;
		}

		cardSignature = CardSignature.parse(response.data);

		logger.newLine();
		logger.info(TAG, "CBicc: " + ByteUtil.toHexString(cardSignature.cb, " "));

		logger.newLine();
		logger.info(TAG, "Nicc: " + ByteUtil.toHexString(cardSignature.nonce, " "));

		logger.newLine();
		logger.info(TAG, "AuthCryptogram: " + ByteUtil.toHexString(cardSignature.cryptogram, " "));

		logger.newLine();
		logger.info(TAG, "Sig ID: " + ByteUtil.toHexString(cardSignature.id, " "));

		logger.newLine();
		logger.info(TAG, "Issuer ID: " + ByteUtil.toHexString(cardSignature.issuerId, " "));

		logger.newLine();
		logger.info(TAG, "GUID: " + ByteUtil.toHexString(cardSignature.guid, " "));

		logger.newLine();
		logger.info(TAG, "Algorithm OID (2A:86:48:CE:3D:03:01:07 for ECDH, P-256): " + ByteUtil.toHexString(cardSignature.algorithmOID, " "));

		logger.newLine();
		logger.info(TAG, "Public Key: " + ByteUtil.toHexString(cardSignature.publicKey, " "));

		logger.newLine();
		logger.info(TAG, "Digital Signature (CVC): " + ByteUtil.toHexString(cardSignature.cvc, " "));

		logger.newLine();
		if (0 != cardSignature.cb[0])
		{
			logger.error(TAG, "[H4] Persistent binding enabled, Terminating Session");
			logger.alert(CARD_RESP_ERROR, ERROR_TITLE);
			transceiver.close();
			return null;
		}

		logger.info(TAG, "[H4] Persistent binding disabled");

		//logger.info(TAG, "[H5] Verify CVC (ECDSA Algorithm, NIST 800-73-4 optional card to host authentication step)");

        KeyFactory kf=KeyFactory.getInstance("EC");
        ECPublicKeySpec keySpec = new ECPublicKeySpec(new ECPoint(new BigInteger(ByteUtil.toHexString(cardSignature.publicKey,1,33),16), new BigInteger(ByteUtil.toHexString(cardSignature.publicKey,33,65),16)),ecPub.getParams());
        ECPublicKey cardPubKey= (ECPublicKey) kf.generatePublic(keySpec);
        logger.info(TAG,"Card Public Key: "+ByteUtil.toHexString(cardPubKey.getEncoded()));

		KeyAgreement keyAgree = KeyAgreement.getInstance("ECDH");
        keyAgree.init(ecPriv);
        keyAgree.doPhase(cardPubKey,true);
        byte[] z = keyAgree.generateSecret();


		logger.newLine();
		logger.info(TAG, "[H8] Compute ECDH Shared Secret Z using OpenSSL : " + ByteUtil.toHexString(z, " "));

		logger.newLine();
		logger.info(TAG, "[H10] Compute session keys using Cipher Suite 2 from NIST 800-73-4 4.1.6");

		String otherInfo =
				"04 09 09 09 09 08 " +
						Opacity.IDH +
						" 01 " +
						Opacity.CBH +
						" 10 " +
						ByteUtil.toHexString(hostPublicKey, 1, 17, " ") +
						" 08 " +
						ByteUtil.toHexString(cardSignature.id, " ") +
						" 10 " +
						ByteUtil.toHexString(cardSignature.nonce, " ") +
						" 01 " +
						ByteUtil.toHexString(cardSignature.cb, " ");

		//Print otherInfo for debugging
		//logger.info(TAG, "otherInfo = " + otherInfo);

		byte[] kdf = Opacity.kdf(z, 512, ByteUtil.hexStringToByteArray(otherInfo));
		//logger.info(TAG, "kdf = " + ByteUtil.toHexString(kdf, " "));
		HashMap<String, byte[]> sessionKeys = Opacity.kdfToDict(kdf);

		logger.newLine();
		logger.info(TAG, "Session keys:");
		logger.info(TAG, "    CFRM: " + ByteUtil.toHexString(sessionKeys.get("cfrm"), " "));
		logger.info(TAG, "    MAC: " + ByteUtil.toHexString(sessionKeys.get("mac"), " "));
		logger.info(TAG, "    ENC: " + ByteUtil.toHexString(sessionKeys.get("enc"), " "));
		logger.info(TAG, "    RMAC: " + ByteUtil.toHexString(sessionKeys.get("rmac"), " "));


        /*// Test CMAC implementation for NIST compliance:
		if (!Cmac.nistCheck())
		{
            logger.error(TAG, "CMAC NIST test failed");
	        logger.alert(CRYPTO_ERROR, ERROR_TITLE);
            transceiver.close();
            return null;
        }*/


		logger.newLine();
		logger.info(TAG, "[H12]  Check AuthCryptogram (CMAC with AES-128 cipher, NIST 800-73-4 4.1.7)");

		// Verify CMAC of card signature:
		byte[] message = ByteUtil.concatenate(
				ByteUtil.hexStringToByteArray("4B 43 5F 31 5F 56"),
				cardSignature.id,
				ByteUtil.hexStringToByteArray(Opacity.IDH),
				Arrays.copyOfRange(hostPublicKey, 1, hostPublicKey.length)
		);
		Cmac check = new Cmac(sessionKeys.get("cfrm"), message);
		if (check.error != null)
		{
			logger.error(TAG, "Error generating CMAC for card Auth Cryptogram: " + check.error);
			logger.alert(CRYPTO_ERROR, ERROR_TITLE);
			transceiver.close();
			return null;
		}

		logger.info(TAG, "    " + ByteUtil.toHexString(check.mac, " "));
		logger.info(TAG, "    " + ByteUtil.toHexString(cardSignature.cryptogram, " "));

		if (!check.verify(cardSignature.cryptogram))
		{
			logger.error(TAG, "Error verifying CMAC of card Auth Cryptogram");
			logger.alert(CRYPTO_ERROR, ERROR_TITLE);
			transceiver.close();
			return null;
		}

		long stopTime = System.currentTimeMillis();
		TunnelCreationTimer=(int)(stopTime - startTime);
		logger.newLine();
		logger.info(TAG, "Opacity Session Established in " + TunnelCreationTimer.toString() + " ms");
		logger.newLine();

		return sessionKeys;
	}
}