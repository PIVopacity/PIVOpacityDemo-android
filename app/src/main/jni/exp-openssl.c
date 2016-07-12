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

#include <jni.h>
#include <openssl/bn.h>
#include <openssl/cmac.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/err.h>

#ifndef max
#define max(a, b) (((a) > (b)) ? (a) : (b))
#endif

/*
 * This file contains the JNI native methods for interfacing with the OpenSSL library.
 */

/*
 * Class:     com_exponent_openssl_EcKeyPair
 * Method:    generate
 * Signature: (I)Lcom/exponent/openssl/EcKeyPair;
 */
jobject Java_com_exponent_openssl_EcKeyPair_generate(JNIEnv *env, jclass clazz,
																 jint curveId)
{
	// Declare all these here to make cleanup easier
	BIGNUM *pubKeyX = NULL;
	BIGNUM *pubKeyY = NULL;
	EC_KEY *key = NULL;
	const BIGNUM *privKey = NULL;
	const EC_GROUP *group;
	const EC_POINT *pubKey;
	unsigned char *privKeyBytes = NULL;
	unsigned char *pubKeyXBytes = NULL;
	unsigned char *pubKeyYBytes = NULL;

	char error[256];

	// Create an instance of the Java class that we will return:
	jobject keyPair = (*env)->AllocObject(env, clazz);

	// Get information about the fields in that class:
	jfieldID curveIdId = (*env)->GetFieldID(env, clazz, "curveId", "I");
	jfieldID publicKeyXId = (*env)->GetFieldID(env, clazz, "publicKeyX", "[B");
	jfieldID publicKeyYId = (*env)->GetFieldID(env, clazz, "publicKeyY", "[B");
	jfieldID privateKeyId = (*env)->GetFieldID(env, clazz, "privateKey", "[B");
	jfieldID errorId = (*env)->GetFieldID(env, clazz, "error", "Ljava/lang/String;");

	// Create a new elliptic curve with the given ID:
	pubKeyX = BN_new();
	pubKeyY = BN_new();
	key = EC_KEY_new_by_curve_name(curveId);

	if (key == NULL)
	{
		sprintf(error, "[OpenSSL] EC_KEY_new_by_curve_name FAIL: %ld", ERR_get_error());
		(*env)->SetObjectField(env, keyPair, errorId, (*env)->NewStringUTF(env, error));
		goto CLEAN_UP_AND_EXIT;
	}

	// Generate a key pair for the elliptic curve:
	if (EC_KEY_generate_key(key) == 0)
	{
		sprintf(error, "[OpenSSL] EC_KEY_generate_key FAIL: %ld", ERR_get_error());
		(*env)->SetObjectField(env, keyPair, errorId, (*env)->NewStringUTF(env, error));
		goto CLEAN_UP_AND_EXIT;
	}

	if (EC_KEY_check_key(key) == 0)
	{
		sprintf(error, "[OpenSSL] EC_KEY_check_key FAIL: %ld", ERR_get_error());
		(*env)->SetObjectField(env, keyPair, errorId, (*env)->NewStringUTF(env, error));
		goto CLEAN_UP_AND_EXIT;
	}

	// Get the public and private keys:
	privKey = EC_KEY_get0_private_key(key);
	group = EC_KEY_get0_group(key);
	pubKey = EC_KEY_get0_public_key(key);

	if (EC_POINT_get_affine_coordinates_GFp(group, pubKey, pubKeyX, pubKeyY, 0) == 0)
	{
		sprintf(error, "[OpenSSL] EC_POINT_get_affine_coordinates_GFp FAIL: %ld", ERR_get_error());
		(*env)->SetObjectField(env, keyPair, errorId, (*env)->NewStringUTF(env, error));
		goto CLEAN_UP_AND_EXIT;
	}

	int fieldSize = EC_GROUP_get_degree(group);
	int secretLength = (fieldSize + 7) / 8;

	/**
	 * There is a bunch of code here that handles the case when the secret key length is
	 * larger than the size of the public key X and public key Y big numbers. According
	 * to the code in ecc.py that I am porting this code from, the final public key X
	 * and public key Y values should be the length of the secret key, padding on the
	 * "left" with 0x00 as necessary.
	 */

	int privKeyByteCount = BN_num_bytes(privKey);
	int pubKeyXByteCount = BN_num_bytes(pubKeyX);
	int pubKeyYByteCount = BN_num_bytes(pubKeyY);

	int pubKeyXBytePadCount = secretLength > pubKeyXByteCount ? secretLength - pubKeyXByteCount : 0;
	int pubKeyYBytePadCount = secretLength > pubKeyYByteCount ? secretLength - pubKeyYByteCount : 0;

	pubKeyXByteCount += pubKeyXBytePadCount;
	pubKeyYByteCount += pubKeyYBytePadCount;

	privKeyBytes = malloc((size_t) privKeyByteCount);
	pubKeyXBytes = malloc((size_t) pubKeyXByteCount);
	pubKeyYBytes = malloc((size_t) pubKeyYByteCount);

	memset(pubKeyXBytes, 0, (size_t) pubKeyXByteCount);
	memset(pubKeyYBytes, 0, (size_t) pubKeyYByteCount);

	BN_bn2bin(privKey, privKeyBytes);
	BN_bn2bin(pubKeyX, pubKeyXBytes + pubKeyXBytePadCount);
	BN_bn2bin(pubKeyY, pubKeyYBytes + pubKeyYBytePadCount);

	// Fill key fields in Java class:
	jbyteArray privKeyByteArray = (*env)->NewByteArray(env, privKeyByteCount);
	jbyteArray pubKeyXByteArray = (*env)->NewByteArray(env, pubKeyXByteCount);
	jbyteArray pubKeyYByteArray = (*env)->NewByteArray(env, pubKeyYByteCount);
	jbyte *b;

	b = (*env)->GetByteArrayElements(env, privKeyByteArray, NULL);
	memcpy(b, privKeyBytes, (size_t) privKeyByteCount);
	(*env)->ReleaseByteArrayElements(env, privKeyByteArray, b, 0);

	b = (*env)->GetByteArrayElements(env, pubKeyXByteArray, NULL);
	memcpy(b, pubKeyXBytes, (size_t) pubKeyXByteCount);
	(*env)->ReleaseByteArrayElements(env, pubKeyXByteArray, b, 0);

	b = (*env)->GetByteArrayElements(env, pubKeyYByteArray, NULL);
	memcpy(b, pubKeyYBytes, (size_t) pubKeyYByteCount);
	(*env)->ReleaseByteArrayElements(env, pubKeyYByteArray, b, 0);

	(*env)->SetIntField(env, keyPair, curveIdId, curveId);
	(*env)->SetObjectField(env, keyPair, privateKeyId, privKeyByteArray);
	(*env)->SetObjectField(env, keyPair, publicKeyXId, pubKeyXByteArray);
	(*env)->SetObjectField(env, keyPair, publicKeyYId, pubKeyYByteArray);

	CLEAN_UP_AND_EXIT:
	// Clean up:
	if (pubKeyX != NULL)
	{
		BN_free(pubKeyX);
	}
	if (pubKeyY != NULL)
	{
		BN_free(pubKeyY);
	}
	if (key != NULL)
	{
		EC_KEY_free(key);
	}
	if (privKeyBytes != NULL)
	{
		free(privKeyBytes);
	}
	if (pubKeyXBytes != NULL)
	{
		free(pubKeyXBytes);
	}
	if (pubKeyYBytes != NULL)
	{
		free(pubKeyYBytes);
	}

	return keyPair;
}

/*
 * Class:     com_exponent_openssl_EcKeyPair
 * Method:    checkKey
 * Signature: ()Z
 */
jboolean Java_com_exponent_openssl_EcKeyPair_checkKey(JNIEnv *env, jobject object)
{
	// Declare all these here to make cleanup easier
	BIGNUM *pubKeyX = NULL;
	BIGNUM *pubKeyY = NULL;
	EC_KEY *key = NULL;
	BIGNUM *privKey = NULL;
	const EC_GROUP *group = NULL;
	EC_POINT *pubKey = NULL;

	char error[256];

	// Assume key information is not valid:
	jboolean isValid = JNI_FALSE;

	// Get class of object:
	jclass clazz = (*env)->GetObjectClass(env, object);

	// Get information about the fields in that class:
	jfieldID curveIdId = (*env)->GetFieldID(env, clazz, "curveId", "I");
	jfieldID publicKeyXId = (*env)->GetFieldID(env, clazz, "publicKeyX", "[B");
	jfieldID publicKeyYId = (*env)->GetFieldID(env, clazz, "publicKeyY", "[B");
	jfieldID privateKeyId = (*env)->GetFieldID(env, clazz, "privateKey", "[B");
	jfieldID errorId = (*env)->GetFieldID(env, clazz, "error", "Ljava/lang/String;");

	// Create a new elliptic curve using the curve ID from the Java object:
	jint curveId = (*env)->GetIntField(env, object, curveIdId);
	key = EC_KEY_new_by_curve_name(curveId);
	if (key == NULL)
	{
		sprintf(error, "[OpenSSL] EC_KEY_new_by_curve_name FAIL: %ld", ERR_get_error());
		(*env)->SetObjectField(env, object, errorId, (*env)->NewStringUTF(env, error));
		goto CLEAN_UP_AND_EXIT;
	}

	// Get references to various fields in the Java object:
	jarray privKeyField = (*env)->GetObjectField(env, object, privateKeyId);
	jarray pubKeyXField = (*env)->GetObjectField(env, object, publicKeyXId);
	jarray pubKeyYField = (*env)->GetObjectField(env, object, publicKeyYId);

	jsize length;
	void *b;

	// Get key data from Java object:
	if (NULL != privKeyField)
	{
		length = (*env)->GetArrayLength(env, privKeyField);
		b = (*env)->GetPrimitiveArrayCritical(env, privKeyField, NULL);
		privKey = BN_bin2bn(b, length, NULL);
		(*env)->ReleasePrimitiveArrayCritical(env, privKeyField, b, 0);
	}

	length = (*env)->GetArrayLength(env, pubKeyXField);
	b = (*env)->GetPrimitiveArrayCritical(env, pubKeyXField, NULL);
	pubKeyX = BN_bin2bn(b, length, NULL);
	(*env)->ReleasePrimitiveArrayCritical(env, pubKeyXField, b, 0);

	length = (*env)->GetArrayLength(env, pubKeyYField);
	b = (*env)->GetPrimitiveArrayCritical(env, pubKeyYField, NULL);
	pubKeyY = BN_bin2bn(b, length, NULL);
	(*env)->ReleasePrimitiveArrayCritical(env, pubKeyYField, b, 0);

	// Set key information in the elliptic curve:
	if (NULL != privKeyField && EC_KEY_set_private_key(key, privKey) == 0)
	{
		sprintf(error, "[OpenSSL] EC_KEY_set_private_key FAIL: %ld", ERR_get_error());
		(*env)->SetObjectField(env, object, errorId, (*env)->NewStringUTF(env, error));
		goto CLEAN_UP_AND_EXIT;
	}

	group = EC_KEY_get0_group(key);
	pubKey = EC_POINT_new(group);

	if (EC_POINT_set_affine_coordinates_GFp(group, pubKey, pubKeyX, pubKeyY, 0) == 0)
	{
		sprintf(error, "[OpenSSL] EC_POINT_set_affine_coordinates_GFp FAIL: %ld", ERR_get_error());
		(*env)->SetObjectField(env, object, errorId, (*env)->NewStringUTF(env, error));
		goto CLEAN_UP_AND_EXIT;
	}

	if (EC_KEY_set_public_key(key, pubKey) == 0)
	{
		sprintf(error, "[OpenSSL] EC_KEY_set_public_key FAIL: %ld", ERR_get_error());
		(*env)->SetObjectField(env, object, errorId, (*env)->NewStringUTF(env, error));
		goto CLEAN_UP_AND_EXIT;
	}

	// Veify the key information using the elliptic curve:
	if (EC_KEY_check_key(key) == 0)
	{
		sprintf(error, "[OpenSSL] EC_KEY_check_key FAIL: %ld", ERR_get_error());
		(*env)->SetObjectField(env, object, errorId, (*env)->NewStringUTF(env, error));
		goto CLEAN_UP_AND_EXIT;
	}

	// If we get here, all is well with the world (and the key data):
	isValid = JNI_TRUE;

	CLEAN_UP_AND_EXIT:
	if (key != NULL)
	{
		EC_KEY_free(key);
	}
	if (pubKeyX != NULL)
	{
		BN_free(pubKeyX);
	}
	if (pubKeyY != NULL)
	{
		BN_free(pubKeyY);
	}
	if (privKey != NULL)
	{
		BN_free(privKey);
	}
	if (pubKey != NULL)
	{
		EC_POINT_free(pubKey);
	}

	return isValid;
}

/*
 * Class:     com_exponent_openssl_EcKeyPair
 * Method:    getEcdhKey
 * Signature: ()[B
 */
jbyteArray Java_com_exponent_openssl_EcKeyPair_getEcdhKey(JNIEnv *env, jobject object)
{
	// Declare all these here to make cleanup easier
	BIGNUM *otherPubKeyX = NULL;
	BIGNUM *otherPubKeyY = NULL;
	EC_KEY *otherKey = NULL;
	EC_POINT *otherPubKey = NULL;
	const EC_GROUP *otherGroup = NULL;
	EC_KEY *ownKey = NULL;
	BIGNUM *ownPrivKey = NULL;
	jbyte *ecdhKeyBuffer = NULL;

	jbyteArray ecdhKey = NULL;

	char error[256];

	ecdhKeyBuffer = malloc(32);

	// Get class of object:
	jclass clazz = (*env)->GetObjectClass(env, object);

	// Get information about the fields in that class:
	jfieldID curveIdId = (*env)->GetFieldID(env, clazz, "curveId", "I");
	jfieldID publicKeyXId = (*env)->GetFieldID(env, clazz, "publicKeyX", "[B");
	jfieldID publicKeyYId = (*env)->GetFieldID(env, clazz, "publicKeyY", "[B");
	jfieldID privateKeyId = (*env)->GetFieldID(env, clazz, "privateKey", "[B");
	jfieldID errorId = (*env)->GetFieldID(env, clazz, "error", "Ljava/lang/String;");

	jint curveId = (*env)->GetIntField(env, object, curveIdId);

	// Create an elliptic curve using the ID from the Java object:
	otherKey = EC_KEY_new_by_curve_name(curveId);
	if (NULL == otherKey)
	{
		sprintf(error, "[OpenSSL] EC_KEY_new_by_curve_name FAIL: %ld", ERR_get_error());
		(*env)->SetObjectField(env, object, errorId, (*env)->NewStringUTF(env, error));
		goto CLEAN_UP_AND_EXIT;
	}

	// Get references to various fields in the java object:
	jarray privKeyField = (*env)->GetObjectField(env, object, privateKeyId);
	jarray pubKeyXField = (*env)->GetObjectField(env, object, publicKeyXId);
	jarray pubKeyYField = (*env)->GetObjectField(env, object, publicKeyYId);

	jsize length;
	void *b;

	// Get public key data from Java object:
	length = (*env)->GetArrayLength(env, pubKeyXField);
	b = (*env)->GetPrimitiveArrayCritical(env, pubKeyXField, NULL);
	otherPubKeyX = BN_bin2bn(b, length, NULL);
	(*env)->ReleasePrimitiveArrayCritical(env, pubKeyXField, b, 0);

	length = (*env)->GetArrayLength(env, pubKeyYField);
	b = (*env)->GetPrimitiveArrayCritical(env, pubKeyYField, NULL);
	otherPubKeyY = BN_bin2bn(b, length, NULL);
	(*env)->ReleasePrimitiveArrayCritical(env, pubKeyYField, b, 0);

	otherGroup = EC_KEY_get0_group(otherKey);
	otherPubKey = EC_POINT_new(otherGroup);

	if (NULL == otherPubKey)
	{
		sprintf(error, "[OpenSSL] EC_POINT_new FAIL: %ld", ERR_get_error());
		(*env)->SetObjectField(env, object, errorId, (*env)->NewStringUTF(env, error));
		goto CLEAN_UP_AND_EXIT;
	}

	// Set public key information in the elliptic curve:
	if (EC_POINT_set_affine_coordinates_GFp(otherGroup, otherPubKey, otherPubKeyX, otherPubKeyY, 0) == 0)
	{
		sprintf(error, "[OpenSSL] EC_POINT_set_affine_coordinates_GFp FAIL: %ld", ERR_get_error());
		(*env)->SetObjectField(env, object, errorId, (*env)->NewStringUTF(env, error));
		goto CLEAN_UP_AND_EXIT;
	}

	if (EC_KEY_set_public_key(otherKey, otherPubKey) == 0)
	{
		sprintf(error, "[OpenSSL] EC_KEY_set_public_key FAIL: %ld", ERR_get_error());
		(*env)->SetObjectField(env, object, errorId, (*env)->NewStringUTF(env, error));
		goto CLEAN_UP_AND_EXIT;
	}

	if (EC_KEY_check_key(otherKey) == 0)
	{
		sprintf(error, "[OpenSSL] EC_KEY_check_key FAIL: %ld", ERR_get_error());
		(*env)->SetObjectField(env, object, errorId, (*env)->NewStringUTF(env, error));
		goto CLEAN_UP_AND_EXIT;
	}

	// Create another elliptic curve using the IF from the Java object:
	ownKey = EC_KEY_new_by_curve_name(curveId);
	if (NULL == ownKey)
	{
		sprintf(error, "[OpenSSL] EC_KEY_new_by_curve_name FAIL: %ld", ERR_get_error());
		(*env)->SetObjectField(env, object, errorId, (*env)->NewStringUTF(env, error));
		goto CLEAN_UP_AND_EXIT;
	}

	// Get private key info from Java object:
	length = (*env)->GetArrayLength(env, privKeyField);
	b = (*env)->GetPrimitiveArrayCritical(env, privKeyField, NULL);
	ownPrivKey = BN_bin2bn(b, length, NULL);
	(*env)->ReleasePrimitiveArrayCritical(env, privKeyField, b, 0);

	// Set private key information in the elliptic curve:
	if (EC_KEY_set_private_key(ownKey, ownPrivKey) == 0)
	{
		sprintf(error, "[OpenSSL] EC_KEY_set_private_key FAIL: %ld", ERR_get_error());
		(*env)->SetObjectField(env, object, errorId, (*env)->NewStringUTF(env, error));
		goto CLEAN_UP_AND_EXIT;
	}

	ECDH_set_method(ownKey, ECDH_OpenSSL());
	jint ecdhKeyLength = ECDH_compute_key(ecdhKeyBuffer, 32, otherPubKey, ownKey, 0);
	if (ecdhKeyLength != 32)
	{
		sprintf(error, "[OpenSSL] ECDH keylen FAIL: %ld", ERR_get_error());
		(*env)->SetObjectField(env, object, errorId, (*env)->NewStringUTF(env, error));
		goto CLEAN_UP_AND_EXIT;
	}

	ecdhKey = (*env)->NewByteArray(env, 32);
	b = (*env)->GetByteArrayElements(env, ecdhKey, NULL);
	memcpy(b, ecdhKeyBuffer, 32);
	(*env)->ReleaseByteArrayElements(env, ecdhKey, b, 0);

	CLEAN_UP_AND_EXIT:
	if (otherKey != NULL)
	{
		EC_KEY_free(otherKey);
	}
	if (otherPubKeyX != NULL)
	{
		BN_free(otherPubKeyX);
	}
	if (otherPubKeyY != NULL)
	{
		BN_free(otherPubKeyY);
	}
	if (otherPubKey != NULL)
	{
		EC_POINT_free(otherPubKey);
	}
	if (ownKey != NULL)
	{
		EC_KEY_free(ownKey);
	}
	if (ownPrivKey != NULL)
	{
		BN_free(ownPrivKey);
	}
	if (ecdhKeyBuffer != NULL)
	{
		free(ecdhKeyBuffer);
	}

	return ecdhKey;
}

/*
 * Class:     com_exponent_openssl_Cmac
 * Method:    computeCmac
 * Signature: ()V
 */
void Java_com_exponent_openssl_Cmac_generate(JNIEnv *env, jobject object)
{
	// Declare all these here to make cleanup easier
	CMAC_CTX *ctx = NULL;
	jbyte *keyBytes = NULL;
	jbyte *messageBytes = NULL;

	char error[256];

	// Get class of object:
	jclass clazz = (*env)->GetObjectClass(env, object);

	// Get information about the fields in that class:
	jfieldID keyId = (*env)->GetFieldID(env, clazz, "key", "[B");
	jfieldID messageId = (*env)->GetFieldID(env, clazz, "message", "[B");
	jfieldID macId = (*env)->GetFieldID(env, clazz, "mac", "[B");
	jfieldID errorId = (*env)->GetFieldID(env, clazz, "error", "Ljava/lang/String;");

	jarray keyField = (*env)->GetObjectField(env, object, keyId);
	jarray messageField = (*env)->GetObjectField(env, object, messageId);

	unsigned char mac[16] = {0};
	size_t macLength;

	// Get primitive access to key and message data:
	jsize keyLength = (*env)->GetArrayLength(env, keyField);
	keyBytes = (*env)->GetPrimitiveArrayCritical(env, keyField, NULL);
	jsize messageLength = (*env)->GetArrayLength(env, messageField);
	messageBytes = (*env)->GetPrimitiveArrayCritical(env, messageField, NULL);

	ctx = CMAC_CTX_new();
	if (NULL == ctx)
	{
		sprintf(error, "[OpenSSL] CMAC_CTX_NEW FAIL: %ld", ERR_get_error());
		(*env)->SetObjectField(env, object, errorId, (*env)->NewStringUTF(env, error));
		goto CLEAN_UP_AND_EXIT;
	}

	if (CMAC_Init(ctx, keyBytes, (size_t) keyLength, EVP_aes_128_cbc(), NULL) == 0)
	{
		sprintf(error, "[OpenSSL] CMAC_Init FAIL: %ld", ERR_get_error());
		(*env)->SetObjectField(env, object, errorId, (*env)->NewStringUTF(env, error));
		goto CLEAN_UP_AND_EXIT;
	}

	if (CMAC_Update(ctx, messageBytes, (size_t) messageLength) == 0)
	{
		sprintf(error, "[OpenSSL] CMAC_Update FAIL: %ld", ERR_get_error());
		(*env)->SetObjectField(env, object, errorId, (*env)->NewStringUTF(env, error));
		goto CLEAN_UP_AND_EXIT;
	}

	(*env)->ReleasePrimitiveArrayCritical(env, messageField, messageBytes, 0);
	(*env)->ReleasePrimitiveArrayCritical(env, keyField, keyBytes, 0);
	messageBytes = NULL;
	keyBytes = NULL;

	if (CMAC_Final(ctx, mac, &macLength) == 0)
	{
		sprintf(error, "[OpenSSL] CMAC_Final FAIL: %ld", ERR_get_error());
		(*env)->SetObjectField(env, object, errorId, (*env)->NewStringUTF(env, error));
		goto CLEAN_UP_AND_EXIT;
	}

	// Copy generated MAC to the object:
	jbyteArray macByteArray = (*env)->NewByteArray(env, macLength);
	jbyte *b = (*env)->GetByteArrayElements(env, macByteArray, NULL);
	memcpy(b, mac, macLength);
	(*env)->ReleaseByteArrayElements(env, macByteArray, b, 0);
	(*env)->SetObjectField(env, object, macId, macByteArray);

CLEAN_UP_AND_EXIT:
	if (messageBytes != NULL)
	{
		(*env)->ReleasePrimitiveArrayCritical(env, messageField, messageBytes, 0);
	}
	if (keyBytes != NULL)
	{
		(*env)->ReleasePrimitiveArrayCritical(env, keyField, keyBytes, 0);
	}
	if (ctx != NULL)
	{
		CMAC_CTX_free(ctx);
	}

	return;
}


