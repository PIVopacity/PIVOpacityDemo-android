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

import android.app.Activity;
import android.content.Intent;
import android.graphics.Path;
import android.net.Uri;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.os.Environment;
import android.util.Log;

import com.exponent.CA.DODCACert;
import com.exponent.opacity.AesParameters;
import com.exponent.opacity.Opacity;
import com.exponent.opacity.OpacitySecureTunnel;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.concurrent.ThreadFactory;


/**
 * Provides access to the Common Access Card reader.
 */
public class CacReader implements NfcAdapter.ReaderCallback
{
    private Activity activity;
	private Logger logger;

	private final static String TAG = "CacReader";

	private final static String GET_DISCOVERY_OBJECT = "00 CB 3F FF 03 5C 01 7E 00";
	private final static String MCV = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"; // 16 bytes
	private final static String RMCV = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"; // 16 bytes

	private final static String ERROR_TITLE = "Error";
	private final static String SUCCESS_TITLE = "SUCCESS";
	private final static String CARD_COMM_ERROR = "Error communicating with card: check log for details.";
	private final static String CRYPTO_ERROR = "Cryptography error: check log for details.";
    private final static String AUTH_ERROR = "Authentication error: check log for details.";

	public CacReader(Activity activity, Logger logger)
	{
        this.activity = activity;
		this.logger = logger;
	}

	/**
	 * Called when the NFS system finds a tag.
	 * @param tag the discovered NFC tag
	 */
	@Override
	public void onTagDiscovered(Tag tag)
    {
        Transceiver.Response response;
        logger.clear();

        logger.info(TAG, "Card Detected on Reader: " + StringUtil.join(tag.getTechList(), ", "));

        Transceiver transceiver = Transceiver.create(logger, tag);
        if (null == transceiver)
        {
            logger.alert(CARD_COMM_ERROR, ERROR_TITLE);
            return;
        }

        // Select the PIV Card Application:

        response = transceiver.transceive("SELECT PIV AID", Opacity.SELECT_PIV);
        if (null == response)
        {
            logger.alert(CARD_COMM_ERROR, ERROR_TITLE);
            transceiver.close();
            return;
        }

        // Open an Opacity secure tunnel, receiving the session keys:

        OpacitySecureTunnel opacityTunnel = new OpacitySecureTunnel(logger);
        HashMap<String, byte[]> sessionKeys;

        try
        {
            sessionKeys = opacityTunnel.openTunnel(transceiver);
            if (sessionKeys == null)
            {
                logger.error(TAG, "Unable to generate Opacity session keys");
                logger.alert(CRYPTO_ERROR, ERROR_TITLE);
                transceiver.close();
                return;
            }
        } catch (GeneralSecurityException e)
        {
            logger.error(TAG, "Unable to establish Opacity Secure Tunnel", e);
            logger.alert(CRYPTO_ERROR, ERROR_TITLE);
            transceiver.close();
            return;
        }

        logger.newLine();
        logger.info(TAG, "*** Begin secure messaging using AES-128 ***");
        logger.newLine();

        // Get the discovery object in the clear for later
        // comparison with that retrieved through a secure channel.

        response = transceiver.transceive("Get Discovery object in clear", GET_DISCOVERY_OBJECT);
        if (null == response)
        {
            logger.alert(CARD_COMM_ERROR, ERROR_TITLE);
            transceiver.close();
            return;
        }

        byte[] discoveryObject = response.data;

        // Secure messaging using AES-128
        // NIST SP800-73-4 says this should start at 1 (Part 2, Page 32)
        int encCount = 1;
        AesParameters encryptionParameters;
        try
        {
            encryptionParameters = new AesParameters(encCount, ByteUtil.hexStringToByteArray(MCV), ByteUtil.hexStringToByteArray(RMCV), sessionKeys);
        } catch (GeneralSecurityException e)
        {
            logger.error(TAG, "Unable to create AES Cipher", e);
            logger.alert(CRYPTO_ERROR, ERROR_TITLE);
            transceiver.close();
            return;
        }

        byte[][] encryptedApdu;
        byte[] decryptedResponse;
        String transaction;

        // Check for need for pairing code:
        if ((0xf & discoveryObject[discoveryObject.length - 2]) == 0x8)
        {
            logger.newLine();
            transaction = "Verify Pairing Code";
            logger.info(TAG, transaction);

            GetNumericInputDialogFragment fragment = GetNumericInputDialogFragment.create("Enter Pairing Code (data encrypted in transit)");
            String input = fragment.showDialog(activity);
            fragment.dismiss();

            if (null == input)
            {
                logger.error(TAG, "Unable to get Pairing Code from user");
                logger.alert("Unable to get Pairing Code from user: try again.", ERROR_TITLE);
                transceiver.close();
                return;
            }

            logger.info(TAG, "Pairing code: " + input);
            byte[] pairingCode = input.getBytes();
            if (pairingCode.length != 8)
            {
                logger.error(TAG, "Pairing Code is too short or too long");
                logger.alert("Pairing code is too short or too long: try again", ERROR_TITLE);
                transceiver.close();
                return;
            }

            try
            {
                encryptedApdu = Opacity.encryptApdu(
                        encryptionParameters,
                        new byte[]{(byte) 0x20},
                        new byte[1],
                        new byte[]{(byte) 0x98},
                        pairingCode,
                        null);
            } catch (GeneralSecurityException e)
            {
                logger.error(TAG, "Unable to encrypt Pairing Code APDU", e);
                logger.alert(CRYPTO_ERROR, ERROR_TITLE);
                transceiver.close();
                return;
            }

            response = transceiver.transceive(transaction, encryptedApdu);
            if (null == response)
            {
                logger.alert(CARD_COMM_ERROR, ERROR_TITLE);
                transceiver.close();
                return;
            }

            if (!Opacity.confirmRmac(encryptionParameters, response.data))
            {
                logger.error(TAG, "Check of Pairing Code response CMAC failed");
                logger.alert(CRYPTO_ERROR, ERROR_TITLE);
                transceiver.close();
                return;
            }

            if (!response.isWrappedStatusSuccess())
            {
                logger.error(TAG, "Pairing Code verification failed");
                logger.alert("Pairing code verification failed.", ERROR_TITLE);
                transceiver.close();
                return;
            }

            encryptionParameters.count++;
        }



        /*// Get the X.509 certificate for card authentication:

		logger.newLine();
		transaction = "Get X.509 Cert. for Card Auth.";
		logger.info(TAG, transaction);

		try
		{
			encryptedApdu = Opacity.encryptApdu(
					encryptionParameters,
					ByteUtil.hexStringToByteArray("CB"),
					ByteUtil.hexStringToByteArray("3F"),
					ByteUtil.hexStringToByteArray("FF"),
					ByteUtil.hexStringToByteArray("5C 03 5F C1 01"),
					null);
		}
		catch (Exception ex)
		{
			logger.error(TAG, "Unable to encrypt APDU", ex);
			logger.alert(CRYPTO_ERROR, ERROR_TITLE);
			transceiver.close();
			return;
		}

		response = transceiver.transceive(transaction, encryptedApdu);
		if (null == response)
		{
			logger.alert(CARD_COMM_ERROR, ERROR_TITLE);
			transceiver.close();
			return;
		}

		if (!Opacity.confirmRmac(encryptionParameters, response.data))
		{
			logger.error(TAG, "Check of Response CMAC failed");
			logger.alert(CRYPTO_ERROR, ERROR_TITLE);
			transceiver.close();
			return;
		}


		try
		{
			decryptedResponse = Opacity.getDecryptedResponse(encryptionParameters, response.data);
			if (null != decryptedResponse) {
				logger.info(TAG, "Decrypted response: " + ByteUtil.toHexString(decryptedResponse, " "));
			}
		}
		catch (GeneralSecurityException e)
		{
			logger.error(TAG, "Unable to decrypt response", e);
			logger.alert(CRYPTO_ERROR, ERROR_TITLE);
			transceiver.close();
			return;
		}

		encryptionParameters.count++;*/

        // Get the X.509 certificate for PIV authentication:

        logger.newLine();
        transaction = "Get X.509 Cert. for PIV Auth.";
        logger.info(TAG, transaction);

        X509Certificate pivCert = null;
        X509Certificate dodCaCert = new DODCACert().getDODCert();

        File file = new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), "PIV_Auth_Cert_"+ByteUtil.toHexString(opacityTunnel.cardSignature.id)+".der");
        FileOutputStream fos = null;

        if(file.exists())
        {
            try
            {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                FileInputStream fis;
                try
                {
                    fis = new FileInputStream(file);
                } catch (FileNotFoundException e)
                {
                    e.printStackTrace();
                    return;
                }
                pivCert = (X509Certificate) cf.generateCertificate(fis);

                try
                {
                    pivCert.checkValidity();
                    pivCert.verify(dodCaCert.getPublicKey());
                    //Should do Cert CRL check here, will implement at a later date.
                }catch(Exception ex)
                {
                    logger.error(ERROR_TITLE,"PIV Auth. Certificate Invalid! "+ex.toString());
                    logger.alert(AUTH_ERROR,ERROR_TITLE);
                    transceiver.close();
                    return;
                }

                logger.info(TAG, "Stored PIV Auth. Cert:\n" + pivCert.toString());




            } catch (GeneralSecurityException e)
            {
                logger.error(TAG, "Unable to decrypt response", e);
                logger.alert(CRYPTO_ERROR, ERROR_TITLE);
                transceiver.close();
                return;
            }
        }
        else
        {



            try
            {
                encryptedApdu = Opacity.encryptApdu(
                        encryptionParameters,
                        ByteUtil.hexStringToByteArray("CB"),
                        ByteUtil.hexStringToByteArray("3F"),
                        ByteUtil.hexStringToByteArray("FF"),
                        ByteUtil.hexStringToByteArray("5C 03 5F C1 05"),
                        null);
            } catch (Exception ex)
            {
                logger.error(TAG, "Unable to encrypt APDU", ex);
                logger.alert(CRYPTO_ERROR, ERROR_TITLE);
                transceiver.close();
                return;
            }

            response = transceiver.transceive(transaction, encryptedApdu);
            if (null == response)
            {
                logger.alert(CARD_COMM_ERROR, ERROR_TITLE);
                transceiver.close();
                return;
            }

            if (!Opacity.confirmRmac(encryptionParameters, response.data))
            {
                logger.error(TAG, "Check of Response CMAC failed");
                logger.alert(CRYPTO_ERROR, ERROR_TITLE);
                transceiver.close();
                return;
            }

            try
            {
                decryptedResponse = Opacity.getDecryptedResponse(encryptionParameters, response.data);
                if (null != decryptedResponse)
                {
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    ByteArrayInputStream bis = new ByteArrayInputStream(Arrays.copyOfRange(decryptedResponse, 8, 8 + (((decryptedResponse[6] & 0xFF) << 8) | (decryptedResponse[7] & 0xFF))));
                    pivCert = (X509Certificate) cf.generateCertificate(bis);

                    try
                    {
                        pivCert.checkValidity();
                        pivCert.verify(dodCaCert.getPublicKey());
                        //Should do Cert CRL check here, will implement at a later date.
                    } catch (Exception ex)
                    {
                        logger.error(ERROR_TITLE, "PIV Auth. Certificate Invalid! " + ex.toString());
                        logger.alert(AUTH_ERROR, ERROR_TITLE);
                        transceiver.close();
                        return;
                    }

                    logger.info(TAG, "Decrypted response:\n" + pivCert.toString());


                }
            } catch (GeneralSecurityException e)
            {
                logger.error(TAG, "Unable to decrypt response", e);
                logger.alert(CRYPTO_ERROR, ERROR_TITLE);
                transceiver.close();
                return;
            }
            try
            {
                fos = new FileOutputStream(file);
                // Writes bytes from the specified byte array to this file output stream
                try
                {
                    fos.write(pivCert.getEncoded());
                } catch (CertificateEncodingException e)
                {
                    e.printStackTrace();
                }
            }catch (FileNotFoundException e)
            {
                System.out.println("File not found" + e);
            }
            catch (IOException ioe)
            {
                System.out.println("Exception while writing file " + ioe);
            }
            finally
            {
                // Make sure the stream is closed:
                try
                {
                    if (fos != null)
                    {
                        fos.close();
                    }
                }
                catch (IOException ioe)
                {
                    System.out.println("Error while closing stream: " + ioe);
                }
            }
            logger.info(TAG, "PIV Auth. Cert. Path: " + file.getPath());
            encryptionParameters.count++;
        }

        // Get the PIN from the user and verify it:

        logger.newLine();
        transaction = "Verify PIN";
        logger.info(TAG, transaction);

        GetNumericInputDialogFragment fragment = GetNumericInputDialogFragment.create("Enter PIN (data encrypted in transit)");
        String input = fragment.showDialog(activity);
        fragment.dismiss();


        if (null == input)
        {
            logger.error(TAG, "Unable to get PIN from user");
            logger.alert("Unable to get PIN from user: try again.", ERROR_TITLE);
            transceiver.close();
            return;
        }

        logger.info(TAG, "PIN: " + input);
        byte[] pin = input.getBytes();
        if (pin.length < 6 || pin.length > 8)
        {
            logger.error(TAG, "PIN is too short or too long");
            logger.alert("PIN is too short or too long: try again.", ERROR_TITLE);
            transceiver.close();
            return;
        } else if (pin.length < 8)
        {
            byte[] pad = new byte[8 - pin.length];
            Arrays.fill(pad, (byte) 0xff);
            pin = ByteUtil.concatenate(pin, pad);
        }

        try
        {
            encryptedApdu = Opacity.encryptApdu(
                    encryptionParameters,
                    new byte[]{(byte) 0x20},
                    new byte[1],
                    new byte[]{(byte) 0x80},
                    pin,
                    null);
        } catch (GeneralSecurityException e)
        {
            logger.error(TAG, "Unable to encrypt PIN APDU", e);
            logger.alert(CRYPTO_ERROR, ERROR_TITLE);
            transceiver.close();
            return;
        }

        response = transceiver.transceive(transaction, encryptedApdu);
        if (null == response)
        {
            logger.alert(CARD_COMM_ERROR, ERROR_TITLE);
            transceiver.close();
            return;
        }

        if (!Opacity.confirmRmac(encryptionParameters, response.data))
        {
            logger.error(TAG, "Check of PIN response CMAC failed");
            logger.alert(CRYPTO_ERROR, ERROR_TITLE);
            transceiver.close();
            return;
        }

        if (!response.isWrappedStatusSuccess())
        {
            logger.error(TAG, "PIN verification failed");
            logger.alert("PIN verification failed: try again.", ERROR_TITLE);
            transceiver.close();
            return;
        } else
        {
            logger.info(TAG,"Virtual Contact Interface Open\n\n" + "OPACITY Secure Tunnel\nestablished in: " + opacityTunnel.getCreationTime().toString() + " ms\n\n(secure messaging using AES-128)\n");
        }

        encryptionParameters.count++;

        logger.newLine();
        transaction = "PIV Auth. Challenge with 192-Byte Nonce";
        logger.info(TAG, transaction);
        long sigStartTime = System.currentTimeMillis();
        byte[] nonce=new byte[192];

        SecureRandom rand=new SecureRandom();
        rand.nextBytes(nonce);


        byte[] payload = ByteUtil.hexStringToByteArray("7C" + "820106" + "8200" + "81820100");
        payload = ByteUtil.concatenate(payload, Opacity.pkcs1v15Pad("01", nonce));
        try
        {
            encryptedApdu = Opacity.encryptApdu(
                    encryptionParameters,
                    ByteUtil.hexStringToByteArray("87"),
                    ByteUtil.hexStringToByteArray("07"),
                    ByteUtil.hexStringToByteArray("9A"),
                    payload,
                    new byte[]{(byte) 0x00});
        } catch (Exception ex)
        {
            logger.error(TAG, "Unable to encrypt APDU", ex);
            logger.alert(CRYPTO_ERROR, ERROR_TITLE);
            transceiver.close();
            return;
        }

        response = transceiver.transceive(transaction, encryptedApdu);
        if (null == response)
        {
            logger.alert(CARD_COMM_ERROR, ERROR_TITLE);
            transceiver.close();
            return;
        }

        if (!Opacity.confirmRmac(encryptionParameters, response.data))
        {
            logger.error(TAG, "Check of Response CMAC failed");
            logger.alert(CRYPTO_ERROR, ERROR_TITLE);
            transceiver.close();
            return;
        }

        try
        {
            decryptedResponse = Opacity.getDecryptedResponse(encryptionParameters, response.data);
            if (null != decryptedResponse)
            {
                logger.info(TAG, "Decrypted response: " + ByteUtil.toHexString(decryptedResponse, " "));
            }
        } catch (GeneralSecurityException e)
        {
            logger.error(TAG, "Unable to decrypt response", e);
            logger.alert(CRYPTO_ERROR, ERROR_TITLE);
            transceiver.close();
            return;
        }
        encryptionParameters.count++;

        Signature sig = null;
        try
        {
            sig = Signature.getInstance("NONEwithRSA");
        } catch (NoSuchAlgorithmException e)
        {
            e.printStackTrace();
        }
        if(null!=sig)
        {
            try
            {
                sig.initVerify(pivCert);
            } catch (InvalidKeyException e)
            {
                e.printStackTrace();
            }


            try
            {
                sig.update(nonce);
            } catch (SignatureException e)
            {
                e.printStackTrace();
            }

            try
            {
                if (sig.verify(decryptedResponse, 8, 256))
                {
                    logger.info(TAG, "PIV Challenge Valid");
                    logger.alert("Contactless PIV Authentication\nFIPS 201 Level 4 Assurance\n\nRSA Challenge Time: " + (System.currentTimeMillis() - sigStartTime) + " ms\n\n" + "OPACITY Secure Tunnel\nestablished in: " + opacityTunnel.getCreationTime().toString() + " ms\n\n(secure messaging using AES-128)\n", SUCCESS_TITLE);
                } else
                {
                    logger.info(TAG, "PIV Challenge Invalid");
                    logger.alert(AUTH_ERROR, ERROR_TITLE);
                    transceiver.close();
                    return;
                }
            } catch (SignatureException e)
            {
                e.printStackTrace();
            }
        }



        // Get the discovery object through a secure messaging tunnel:

		logger.newLine();
		transaction = "Get Discovery Object through secure messaging tunnel";
		logger.info(TAG, transaction);

		try
		{
			encryptedApdu = Opacity.encryptApdu(
					encryptionParameters,
					ByteUtil.hexStringToByteArray("CB"),
					ByteUtil.hexStringToByteArray("3F"),
					ByteUtil.hexStringToByteArray("FF"),
					ByteUtil.hexStringToByteArray("5C 01 7E"),
					new byte[1]);
		}
		catch (Exception ex)
		{
			logger.error(TAG, "Unable to encrypt APDU", ex);
			logger.alert(CRYPTO_ERROR, ERROR_TITLE);
			transceiver.close();
			return;
		}

		response = transceiver.transceive(transaction, encryptedApdu);
		if (null == response)
		{
			logger.alert(CARD_COMM_ERROR, ERROR_TITLE);
			transceiver.close();
			return;
		}

		if (!Opacity.confirmRmac(encryptionParameters, response.data))
		{
			logger.error(TAG, "Check of Response CMAC failed");
			logger.alert(CRYPTO_ERROR, ERROR_TITLE);
			transceiver.close();
			return;
		}

		try
		{
			decryptedResponse = Opacity.getDecryptedResponse(encryptionParameters, response.data);
			if (null != decryptedResponse)
			{
				logger.info(TAG, "Decrypted response: " + ByteUtil.toHexString(decryptedResponse, " "));
			}
			else
			{
				logger.error(TAG, "There is no response to decrypt");
				logger.alert(CRYPTO_ERROR, ERROR_TITLE);
				transceiver.close();
				return;
			}
		}
		catch (GeneralSecurityException e)
		{
			logger.error(TAG, "Unable to decrypt response", e);
			logger.alert(CRYPTO_ERROR, ERROR_TITLE);
			transceiver.close();
			return;
		}

		logger.newLine();
		logger.info(TAG, "Check Discovery Object decryption:");
		logger.info(TAG, "    " + ByteUtil.toHexString(discoveryObject, " "));
		logger.info(TAG, "    " + ByteUtil.toHexString(decryptedResponse, " "));

		if (Arrays.equals(discoveryObject, Arrays.copyOfRange(decryptedResponse, 0, discoveryObject.length)))
		{
			logger.info(TAG,"Decrypted Discovery Object matches that received in the clear.");
		}
		else
		{
			logger.info(TAG,"Decrypted Discovery Object does not match that received in the clear: check log for details");
		}

		encryptionParameters.count++;


        // Get and display the cardholder facial image from the card:

		logger.newLine();
		transaction = "Get Cardholder Facial Image";
		logger.info(TAG, transaction);

		try
		{
			encryptedApdu = Opacity.encryptApdu(
					encryptionParameters,
					ByteUtil.hexStringToByteArray("CB"),
					ByteUtil.hexStringToByteArray("3F"),
					ByteUtil.hexStringToByteArray("FF"),
					ByteUtil.hexStringToByteArray("5C 03 5F C1 08"),
					null);
		}
		catch (Exception ex)
		{
			logger.error(TAG, "Unable to encrypt APDU", ex);
			logger.alert(CRYPTO_ERROR, ERROR_TITLE);
			transceiver.close();
			return;
		}

		response = transceiver.transceive(transaction, encryptedApdu);
		if (null == response)
		{
			logger.alert(CARD_COMM_ERROR, ERROR_TITLE);
			transceiver.close();
			return;
		}

		if (!Opacity.confirmRmac(encryptionParameters, response.data))
		{
			logger.error(TAG, "Check of Response CMAC failed");
			logger.alert(CRYPTO_ERROR, ERROR_TITLE);
			transceiver.close();
			return;
		}

		try
		{
			decryptedResponse = Opacity.getDecryptedResponse(encryptionParameters, response.data);
			if (null != decryptedResponse)
			{
				logger.info(TAG, "Decrypted response: " + ByteUtil.toHexString(Arrays.copyOfRange(decryptedResponse,0,100)," ")+" ... response truncated ... ");
			}
			else
			{
				logger.warn(TAG, "No decrypted facial image to store");
				transceiver.close();
				return;
			}
		}
		catch (GeneralSecurityException e)
		{
			logger.error(TAG, "Unable to decrypt response", e);
			logger.alert(CRYPTO_ERROR, ERROR_TITLE);
			transceiver.close();
			return;
		}

		encryptionParameters.count++;

		transceiver.close();

		String decryptedResponseHexString = ByteUtil.toHexString(decryptedResponse);
		int headerStartIndex = decryptedResponseHexString.indexOf("4641430030313000") / 2;
		int imageStartIndex = decryptedResponseHexString.indexOf("FF4FFF51") / 2;
		int imageLength = 0;

		logger.info(TAG, "Header start index: " + headerStartIndex);
		logger.info(TAG, "Image start index: " + imageStartIndex);

		if (0 != headerStartIndex)
		{
			imageLength = Integer.parseInt(decryptedResponseHexString.substring(headerStartIndex * 2 + 16, headerStartIndex * 2 + 24), 16) - 46;
			logger.info(TAG, "Image length: " + imageLength);
			logger.info(TAG, String.format("Received %d-byte facial image from card!", imageLength));
		}

		file = new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), "face_image.jp2");
		fos = null;
		logger.info(TAG, "Image Path: " + file.getPath());

		boolean success = false;
		try
        {
			fos = new FileOutputStream(file);
			// Writes bytes from the specified byte array to this file output stream
			fos.write(Arrays.copyOfRange(decryptedResponse, imageStartIndex, imageStartIndex + imageLength));
	        success = true;
		}

		catch (FileNotFoundException e)
        {
			System.out.println("File not found" + e);
		}
		catch (IOException ioe)
        {
			System.out.println("Exception while writing file " + ioe);
		}
		finally
		{
			// Make sure the stream is closed:
			try
			{
				if (fos != null)
				{
					fos.close();
				}
			}
			catch (IOException ioe)
			{
				System.out.println("Error while closing stream: " + ioe);
			}
		}

		if (success)
		{
            // Launch an activity to view the facial image, which is in JPEG 2000 format.
            // The Android app "Image Converter" seems to work pretty well.
			Intent sendIntent = new Intent();
			sendIntent.setAction(Intent.ACTION_VIEW);
			sendIntent.setData(Uri.fromFile(file));
			sendIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);

			if (sendIntent.resolveActivity(activity.getPackageManager()) != null)
			{
				activity.startActivity(sendIntent);
			}
		}


    }


}
