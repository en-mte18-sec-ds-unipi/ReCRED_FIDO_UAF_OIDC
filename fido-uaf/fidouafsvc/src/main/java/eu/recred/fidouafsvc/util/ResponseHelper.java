package eu.recred.fidouafsvc.util;

import com.google.gson.Gson;
import eu.recred.fido.uaf.crypto.*;
import eu.recred.fido.uaf.msg.AuthenticationResponse;
import eu.recred.fido.uaf.msg.FinalChallengeParams;
import eu.recred.fido.uaf.msg.Operation;
import eu.recred.fido.uaf.msg.RegistrationResponse;
import eu.recred.fido.uaf.msg.Version;
import eu.recred.fido.uaf.tlv.*;
import eu.recred.fidouafsvc.dao.TrustedFacetDao;
import eu.recred.fidouafsvc.model.FidoConfig;
import eu.recred.fidouafsvc.model.TrustedFacet;
import eu.recred.fidouafsvc.ops.ServerDataExpiredException;
import eu.recred.fidouafsvc.ops.ServerDataSignatureNotMatchException;
import eu.recred.fidouafsvc.storage.AuthenticatorRecord;
import eu.recred.fidouafsvc.storage.RegistrationRecord;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.springframework.stereotype.Component;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by sorin.teican on 26-Nov-16.
 */

/*
 * This class contains additional functions that contribute to response creation.
 */

@Component
public class ResponseHelper {

	private TrustedFacetDao trustedFacetDao = new TrustedFacetDao();

	private Logger logger = Logger.getLogger(this.getClass().getName());
	private Gson gson = new Gson();

	private String _challenge;

	/**
	 * checkServerData
	 * <p>%%% BEGIN SOURCE CODE %%%
     * {@codesnippet ResponseHelper-checkServerData}
     * %%% END SOURCE CODE %%%
	 * <p>This function checks the server data of the registration response and stores the username 
	 * and the timestamp
	 * 
	 * <p>REGres 2.2.1.1.3
	 * {@link eu.recred.fidouafsvc.util.ResponseHelper#setUsernameAndTimeStamp(String, String, RegistrationRecord[])}
	 * 
	 * @param serverDataB64
	 * @param records
	 * @param notary
	 * @param serverDataExpiry
	 * @throws Exception
	 */
	public void checkServerData(String serverDataB64, RegistrationRecord[] records, Notary notary,
			long serverDataExpiry) throws Exception {
		// BEGIN: ResponseHelper-checkServerData
		if (notary == null) {
			return;
		}
		String serverData = new String(Base64.decodeBase64(serverDataB64));
		String[] tokens = serverData.split("\\.");
		String signature, timeStamp, username, challenge, dataToSign;
		try {
			signature = tokens[0];
			timeStamp = tokens[1];
			username = tokens[2];
			challenge = tokens[3];
			_challenge = challenge;
			dataToSign = timeStamp + "." + username + "." + challenge;
			if (!notary.verify(dataToSign, signature)) {
				// for (int i = 0; i < records.length; i++)
				// records[i].status = "1491";
				throw new ServerDataSignatureNotMatchException();
			}
			if (isExpired(timeStamp, serverDataExpiry)) {
				// for (int i = 0; i < records.length; i++)
				// records[i].status = "1491";
				throw new ServerDataExpiredException();
			}
			setUsernameAndTimeStamp(username, timeStamp, records);
		} catch (ServerDataExpiredException e) {
			setErrorStatus(records, "1491");
			logger.log(Level.INFO, "[1491] checkServerData() - ServerDataExpiredException");
			// throw new Exception("Invalid server data - Expired data");
		} catch (ServerDataSignatureNotMatchException e) {
			setErrorStatus(records, "1491");
			logger.log(Level.INFO, "[1491] checkServerData() - ServerDataSignatureNotMatchException");
			// throw new Exception("Invalid server data - Signature not match");
		} catch (Exception e) {
			StringWriter sw = new StringWriter();
			PrintWriter pw = new PrintWriter(sw);
			e.printStackTrace(pw);
			logger.log(Level.INFO, "[1491] checkServerData() - Exception: " + sw.toString());
			setErrorStatus(records, "1491");
			// throw new Exception("Server data check failed");
		}
		// END: ResponseHelper-checkServerData
	}

	public void verifyAttestationSignature(Tags tags, RegistrationRecord record,
			CertificateValidator certificateValidator) throws NoSuchAlgorithmException, IOException, Exception {
		byte[] certBytes = tags.getTags().get(TagsEnum.TAG_ATTESTATION_CERT.id).value;
		record.attestCert = Base64.encodeBase64URLSafeString(certBytes);

		Tag krd = tags.getTags().get(TagsEnum.TAG_UAFV1_KRD.id);
		Tag signature = tags.getTags().get(TagsEnum.TAG_SIGNATURE.id);

		byte[] signedBytes = new byte[krd.value.length + 4];
		System.arraycopy(UnsignedUtil.encodeInt(krd.id), 0, signedBytes, 0, 2);
		System.arraycopy(UnsignedUtil.encodeInt(krd.length), 0, signedBytes, 2, 2);
		System.arraycopy(krd.value, 0, signedBytes, 4, krd.value.length);

		record.attestDataToSign = Base64.encodeBase64URLSafeString(signedBytes);
		record.attestSignature = Base64.encodeBase64URLSafeString(signature.value);
		record.attestVerifiedStatus = "FAILED_VALIDATION_ATTEMPT";

		if (validate(certBytes, signedBytes, signature.value)) {
			record.attestVerifiedStatus = "VALID";
		} else {
			record.attestVerifiedStatus = "NOT_VERIFIED";
		}
	}

	public boolean verifySurrogate(Tags tags, RegistrationRecord record) throws Exception {
		Tag pubKey = tags.getTags().get(TagsEnum.TAG_PUB_KEY.id);

		Tag krd = tags.getTags().get(TagsEnum.TAG_UAFV1_KRD.id);
		Tag signature = tags.getTags().get(TagsEnum.TAG_SIGNATURE.id);

		byte[] signedBytes = new byte[krd.value.length + 4];
		System.arraycopy(UnsignedUtil.encodeInt(krd.id), 0, signedBytes, 0, 2);
		System.arraycopy(UnsignedUtil.encodeInt(krd.length), 0, signedBytes, 2, 2);
		System.arraycopy(krd.value, 0, signedBytes, 4, krd.value.length);

		Tag info = tags.getTags().get(TagsEnum.TAG_ASSERTION_INFO.id);
		AlgAndEncodingEnum algAndEncoding = getAlgAndEncoding(info);

		return verifySignature(krd, signature, Base64.encodeBase64URLSafeString(pubKey.value), algAndEncoding);
	}

	private boolean validate(byte[] certBytes, byte[] signedDataBytes, byte[] signatureBytes)
			throws NoSuchAlgorithmException, IOException, Exception {
		X509Certificate x509Certificate = X509.parseDer(certBytes);
		logger.info(" : Attestation Cert : " + x509Certificate);

		String sigAlgOID = x509Certificate.getSigAlgName();
		logger.info(" : Cert Alg : " + sigAlgOID);

		try {
			int len = signatureBytes.length;
			if (signatureBytes.length == 256) {
				if (!RSA.verifyPSS(x509Certificate.getPublicKey(), signedDataBytes, signatureBytes)) {
					logger.info(" : Not verified; Cert Alg : " + sigAlgOID);
					return false;
					// throw new Exception(
					// "Signature is RSA - Alg RAWRSASSA-PSS fail - Requested alg:"
					// + sigAlgOID);
				} else {
					return true;
				}
			} else if (signatureBytes.length == 260) {
				byte[] signatureBytesRaw = new byte[256];
				System.arraycopy(signatureBytes, 4, signatureBytesRaw, 0, 256);
				if (!RSA.verifyPSS(x509Certificate.getPublicKey(), signedDataBytes, signatureBytesRaw)) {
					logger.info(" : Not verified; Cert Alg : " + sigAlgOID);
					return false;
					// throw new Exception(
					// "Signature is RSA - Alg RAWRSASSA-PSS fail - Requested alg:"
					// + sigAlgOID);
				} else {
					return true;
				}
			}

			BigInteger[] rs = null;
			if (signatureBytes.length == 64) {
				rs = Asn1.transformRawSignature(signatureBytes);
			} else {
				rs = Asn1.decodeToBigIntegerArray(signatureBytes);
			}
			try {
				if (!NamedCurve.verify(KeyCodec.getKeyAsRawBytes((ECPublicKey) x509Certificate.getPublicKey()),
						SHA.sha(signedDataBytes, "SHA-256"), rs)) {
					logger.info(" : Not verified; Cert Alg : " + sigAlgOID);
					return false;
					// throw new Exception(
					// "Signature is 64 bytes - Alg SHA256withEC fail - Requested alg:"
					// + sigAlgOID);
				} else {
					return true;
				}
			} catch (Exception fromVerify) {
				if (!NamedCurve.verifyUsingSecp256k1(
						KeyCodec.getKeyAsRawBytes((ECPublicKey) x509Certificate.getPublicKey()),
						SHA.sha(signedDataBytes, "SHA-256"), rs)) {
					logger.info(" : Not verified; Cert Alg : " + sigAlgOID);
					return false;
					// throw new Exception(
					// "Signature is 64 bytes - Alg SHA256withEC fail - Requested alg:"
					// + sigAlgOID);
				} else {
					return true;
				}
			}

		} catch (Exception thrown) {
			logger.log(Level.INFO, "Exception in attest cert validation!", thrown);
			throw thrown;
			// return false;
		}
	}

	/**
	 * getFcp
	 * <p>%%% BEGIN SOURCE CODE %%%
     * {@codesnippet ResponseHelper-getFcp}
     * %%% END SOURCE CODE %%%
	 * <p>This function reads the challenge from registration response
	 * 
	 * <p>REGres 2.2.1.1.5
	 * 
	 * @param response
	 * @return
	 * @throws Exception
	 */
	public FinalChallengeParams getFcp(RegistrationResponse response) throws Exception {
		// BEGIN: ResponseHelper-getFcp
		if (response.fcParams == null || response.fcParams.isEmpty())
			throw new Exception();
		String fcp = new String(Base64.decodeBase64(response.fcParams.getBytes()));
		return gson.fromJson(fcp, FinalChallengeParams.class);
		// END: ResponseHelper-getFcp
	}

	public String getAuthenticatorVersion(Tags tags) {
		return "" + tags.getTags().get(TagsEnum.TAG_ASSERTION_INFO.id).value[0] + "."
				+ tags.getTags().get(TagsEnum.TAG_ASSERTION_INFO.id).value[1];
	}

	/**
	 * checkAssertions
	 * <p>%%% BEGIN SOURCE CODE %%%
     * {@codesnippet ResponseHelper-checkAssertions}
     * %%% END SOURCE CODE %%%
	 * <p>This function checks the response assertions
	 * 
	 * <p>REGres 2.2.1.1.1
	 * @see RegistrationRecord
	 * @see FidoConfig
	 * 
	 * @param response
	 * @return
	 * @throws Exception
	 */
	public RegistrationRecord[] checkAssertions(RegistrationResponse response) throws Exception {
		// BEGIN: ResponseHelper-checkAssertions
		if (response.assertions != null && response.assertions.length > 0) {
			for (int i = 0; i < response.assertions.length; i++) {
				if (response.assertions[i].assertionScheme == null || response.assertions[i].assertionScheme.isEmpty()
						|| !response.assertions[i].assertionScheme.equals("UAFV1TLV")) {
					logger.log(Level.INFO, "[1498]: checkAssertions() - fail");
					RegistrationRecord[] records = new RegistrationRecord[1];
					records[0] = new RegistrationRecord();
					records[0].status = "1498";
					return records;

				}
			}
			FidoConfig config = new FidoConfig();
			if (response.header.op == null || response.header.op != Operation.Reg) {
				logger.log(Level.INFO, "EXCEPTION: ***OP INVALID***");
				throw new Exception();
			}
			if (response.header.appID == null || response.header.appID.isEmpty()
			/*|| !response.header.appID.equals(config.getAppId())*/) {
				logger.log(Level.INFO, "EXCEPTION: ***APPID INVALID***");

				throw new Exception();
			}
			return null;
		} else {
			logger.log(Level.INFO, "[1400]: checkAssertions() - fail");
			RegistrationRecord[] records = new RegistrationRecord[1];
			records[0] = new RegistrationRecord();
			records[0].status = "1400";
			return records;
		}
		// END: ResponseHelper-checkAssertions
	}

	/**
	 * checkAssertions
	 * <p>%%% BEGIN SOURCE CODE %%%
     * {@codesnippet ResponseHelper-checkAssertions}
     * %%% END SOURCE CODE %%%
	 * <p>This function checks the response assertions
	 * 
	 * <p>AUTHres 2.2.1.1.1
	 * @see AuthenticatorRecord
	 * @see FidoConfig
	 * 
	 * @param response
	 * @return
	 * @throws Exception
	 */
	public AuthenticatorRecord[] checkAssertions(AuthenticationResponse response) throws Exception {
		// BEGIN: ResponseHelper-checkAssertions
		if (response.assertions != null && response.assertions.length > 0) {
			for (int i = 0; i < response.assertions.length; i++) {
				if (response.assertions[i].assertionScheme == null || response.assertions[i].assertionScheme.isEmpty()
						|| !response.assertions[i].assertionScheme.equals("UAFV1TLV")) {
					logger.log(Level.INFO, "[1498]: checkAssertions() failed");
					AuthenticatorRecord[] records = new AuthenticatorRecord[1];
					records[0] = new AuthenticatorRecord();
					records[0].status = "1498";
					return records;

				}
			}
			FidoConfig config = new FidoConfig();
			if (response.header.op == null || response.header.op != Operation.Auth)
				throw new Exception();
			if (response.header.appID == null || response.header.appID.isEmpty()
			/* || !response.header.appID.equals(config.getAppId()) */)
				throw new Exception();
			return null;
		} else {
			logger.log(Level.INFO, "[1400]: checkAssertions() failed");
			AuthenticatorRecord[] records = new AuthenticatorRecord[1];
			records[0] = new AuthenticatorRecord();
			records[0].status = "1400";
			return records;
		}
		// END: ResponseHelper-checkAssertions
	}

	private void setUsernameAndTimeStamp(String username, String timeStamp, RegistrationRecord[] records) {
		if (records == null || records.length == 0) {
			return;
		}
		for (int i = 0; i < records.length; i++) {
			RegistrationRecord rec = records[i];
			if (rec == null) {
				rec = new RegistrationRecord();
			}
			rec.username = new String(Base64.decodeBase64(username));
			rec.timeStamp = new String(Base64.decodeBase64(timeStamp));
			records[i] = rec;
		}
	}

	private void setErrorStatus(RegistrationRecord[] records, String status) {
		if (records == null || records.length == 0) {
			return;
		}
		for (RegistrationRecord rec : records) {
			if (rec == null) {
				rec = new RegistrationRecord();
			}
			rec.status = status;
		}
	}

	/**
	 * checkVersion
	 * <p>%%% BEGIN SOURCE CODE %%%
     * {@codesnippet ResponseHelper-checkVersion}
     * %%% END SOURCE CODE %%%
	 * <p>This function checks the version of the response
	 * 
	 * <p>REGres 2.2.1.1.2
	 * 
	 * @param upv
	 * @param records
	 * @throws Exception
	 */
	public void checkVersion(Version upv, RegistrationRecord[] records) throws Exception {
		// BEGIN: ResponseHelper-checkVersion
		if (upv.major == 1 && upv.minor == 0) {
			return;
		} else {
			for (int i = 0; i < records.length; i++) {
				logger.log(Level.INFO, "[1400]: checkVersion() failed");
				records[i].status = "1400";
			}
			// throw new Exception("Invalid version: " + upv.major + "."
			// + upv.minor);
		}
		// END: ResponseHelper-checkVersion
	}

	private boolean isExpired(String timeStamp, long serverDataExpiryInMs) {
		// return Long.parseLong(new String(Base64.decodeBase64(timeStamp)))
		// + serverDataExpiryInMs < System.currentTimeMillis();
		return false;
	}

	/**
	 * checkServerData
	 * <p>%%% BEGIN SOURCE CODE %%%
     * {@codesnippet ResponseHelper-checkServerData}
     * %%% END SOURCE CODE %%%
	 * <p>This function checks the server data of the authentication response and stores the username 
	 * and the timestamp
	 * 
	 * <p>AUTHres 2.2.1.1.3
	 * 
	 * @param serverDataB64
	 * @param records
	 * @param notary
	 * @param serverDataExpiry
	 * @throws Exception
	 */
	public void checkServerData(String serverDataB64, AuthenticatorRecord[] records, Notary notary,
			long serverDataExpiry) throws Exception {
		// BEGIN: ResponseHelper-checkServerData
		if (notary == null) {
			return;
		}
		String serverData = new String(Base64.decodeBase64(serverDataB64));
		String[] tokens = serverData.split("\\.");
		String signature, timeStamp, challenge, dataToSign;
		try {
			signature = tokens[0];
			timeStamp = tokens[1];
			challenge = tokens[2];
			_challenge = challenge;
			dataToSign = timeStamp + "." + challenge;
			if (!notary.verify(dataToSign, signature)) {
				throw new ServerDataSignatureNotMatchException();
			}
			if (isExpired(timeStamp, serverDataExpiry)) {
				throw new ServerDataExpiredException();
			}
		} catch (ServerDataExpiredException e) {
			logger.log(Level.INFO, "[1491]: checkServerData() - ServerDataExpiredException");
			setErrorStatus(records, "1491");
			// throw new Exception("Invalid server data - Expired data");
		} catch (ServerDataSignatureNotMatchException e) {
			logger.log(Level.INFO, "[1491]: checkServerData() - ServerDataExpiredException");
			setErrorStatus(records, "1491");
			// throw new Exception("Invalid server data - Signature not match");
		} catch (Exception e) {
			StringWriter sw = new StringWriter();
			PrintWriter pw = new PrintWriter(sw);
			e.printStackTrace(pw);
			logger.log(Level.INFO, "[1491]: checkServerData() - EXCEPTION: " + sw.toString());
			setErrorStatus(records, "1491");
			// throw new Exception("Server data check failed");
		}
		// END: ResponseHelper-checkServerData
	}

	public byte[] sha256(String text) throws Exception {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(text.getBytes());
		return md.digest();
	}

	public boolean compareByteArr(byte[] l, byte[] r) {
		if (l.length != r.length)
			return false;
		for (int i = 0; i < l.length; i++)
			if (l[i] != r[i])
				return false;

		return true;
	}

	private void setErrorStatus(AuthenticatorRecord[] records, String status) {
		if (records == null || records.length == 0) {
			return;
		}
		for (AuthenticatorRecord rec : records) {
			if (rec == null) {
				rec = new AuthenticatorRecord();
			}
			rec.status = status;
		}
	}

	/**
	 * checkVersion
	 * <p>%%% BEGIN SOURCE CODE %%%
     * {@codesnippet ResponseHelper-checkVersion}
     * %%% END SOURCE CODE %%%
	 * <p>This function checks the version of the response
	 * 
	 * <p>AUTHres 2.2.1.1.2
	 * 
	 * @param upv
	 * @param records
	 * @throws Exception
	 */
	public void checkVersion(Version upv, AuthenticatorRecord[] records) throws Exception {
		// BEGIN: ResponseHelper-checkVersion
		if (upv.major == 1 && upv.minor == 0) {
			return;
		} else {
			logger.log(Level.INFO, "checkVersion() - fail");
			throw new Exception();
			// for (AuthenticatorRecord record : records) {
			// if (record == null)
			// record = new AuthenticatorRecord();
			// record.status = "1400";
			// }

			// throw new Exception("Invalid version: " + upv.major + "."
			// + upv.minor);
		}
		// END: ResponseHelper-checkVersion
	}

	private byte[] encodeInt(int id) {

		byte[] bytes = new byte[2];
		bytes[0] = (byte) (id & 0x00ff);
		bytes[1] = (byte) ((id & 0xff00) >> 8);
		return bytes;
	}

	private byte[] getDataForSigning(Tag signedData) throws IOException {
		ByteArrayOutputStream byteout = new ByteArrayOutputStream();
		byteout.write(encodeInt(signedData.id));
		byteout.write(encodeInt(signedData.length));
		byteout.write(signedData.value);
		return byteout.toByteArray();
	}

	public boolean verifySignature(Tag signedData, Tag signature, String pubKey, AlgAndEncodingEnum algAndEncoding)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException,
			UnsupportedEncodingException, Exception {

		byte[] dataForSigning = getDataForSigning(signedData);

		logger.info(" : pub 		   : " + pubKey);
		logger.info(" : dataForSigning : " + Base64.encodeBase64URLSafeString(dataForSigning));
		logger.info(" : signature 	   : " + Base64.encodeBase64URLSafeString(signature.value));

		// This works
		// return NamedCurve.verify(KeyCodec.getKeyAsRawBytes(pubKey),
		// dataForSigning, Asn1.decodeToBigIntegerArray(signature.value));

		byte[] decodeBase64 = Base64.decodeBase64(pubKey);
		if (algAndEncoding == AlgAndEncodingEnum.UAF_ALG_SIGN_RSASSA_PSS_SHA256_RAW) {
			PublicKey publicKey = null;
			if (decodeBase64.length == 259) {
				byte[] der = getRSADer(decodeBase64);
				publicKey = KeyCodec.getRSAPublicKey(der);
			} else
				publicKey = KeyCodec.getRSAPublicKey(decodeBase64);
			// return RSA.verifyPSS(publicKey, SHA.sha(dataForSigning, "SHA-256"),
			// signature.value);
			return RSA.verifyPSS(publicKey, dataForSigning, signature.value);
		} else if (algAndEncoding == AlgAndEncodingEnum.UAF_ALG_SIGN_RSASSA_PSS_SHA256_DER) {
			// PublicKey publicKey = KeyCodec.getRSAPublicKey(new
			// DEROctetString(decodeBase64).getOctets());
			PublicKey publicKey = null;
			if (decodeBase64.length == 259) {
				byte[] der = getRSADer(decodeBase64);
				publicKey = KeyCodec.getRSAPublicKey(der);
			} else
				publicKey = KeyCodec.getRSAPublicKey(decodeBase64);
			// return RSA.verifyPSS(publicKey, SHA.sha(dataForSigning, "SHA-256"),
			// new DEROctetString(signature.value).getOctets());
			if (signature.length == 260) {
				byte[] sig = new byte[256];
				System.arraycopy(signature.value, 4, sig, 0, 256);
				return RSA.verifyPSS(publicKey, dataForSigning, sig);
			} else
				return RSA.verifyPSS(publicKey, dataForSigning, signature.value);
		} else {
			if (algAndEncoding == AlgAndEncodingEnum.UAF_ALG_SIGN_SECP256K1_ECDSA_SHA256_DER) {
				// ECPublicKey decodedPub = (ECPublicKey)
				// KeyCodec.getPubKeyFromCurve(decodeBase64, "secp256k1");
				ECPublicKey decodedPub = null;
				if (decodeBase64.length != 65) {
					byte[] raw = new byte[65];
					System.arraycopy(decodeBase64, decodeBase64.length - 65, raw, 0, 65);
					decodedPub = (ECPublicKey) KeyCodec.getPubKeyFromCurve(raw, "secp256k1");
				} else
					decodedPub = (ECPublicKey) KeyCodec.getPubKeyFromCurve(decodeBase64, "secp256k1");
				return NamedCurve.verifyUsingSecp256k1(KeyCodec.getKeyAsRawBytes(decodedPub),
						SHA.sha(dataForSigning, "SHA-256"), Asn1.decodeToBigIntegerArray(signature.value));
			}
			if (algAndEncoding == AlgAndEncodingEnum.UAF_ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW) {
				ECPublicKey decodedPub = null;
				if (decodeBase64.length != 65) {
					byte[] raw = new byte[65];
					System.arraycopy(decodeBase64, decodeBase64.length - 65, raw, 0, 65);
					decodedPub = (ECPublicKey) KeyCodec.getPubKeyFromCurve(raw, "secp256k1");
				} else
					decodedPub = (ECPublicKey) KeyCodec.getPubKeyFromCurve(decodeBase64, "secp256k1");
				return NamedCurve.verifyUsingSecp256k1(KeyCodec.getKeyAsRawBytes(decodedPub),
						SHA.sha(dataForSigning, "SHA-256"), Asn1.transformRawSignature(signature.value));
			}
			if (algAndEncoding == AlgAndEncodingEnum.UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_DER) {
				if (decodeBase64.length > 65) {
					return NamedCurve.verify(KeyCodec.getKeyAsRawBytes(pubKey), SHA.sha(dataForSigning, "SHA-256"),
							Asn1.decodeToBigIntegerArray(signature.value));
				} else {
					ECPublicKey decodedPub = (ECPublicKey) KeyCodec.getPubKeyFromCurve(decodeBase64, "secp256r1");
					return NamedCurve.verify(KeyCodec.getKeyAsRawBytes(decodedPub), SHA.sha(dataForSigning, "SHA-256"),
							Asn1.decodeToBigIntegerArray(signature.value));
				}
			}
			if (signature.value.length == 64) {
				ECPublicKey decodedPub = null;
				if (decodeBase64.length != 65) {
					byte[] raw = new byte[65];
					System.arraycopy(decodeBase64, decodeBase64.length - 65, raw, 0, 65);
					decodedPub = (ECPublicKey) KeyCodec.getPubKeyFromCurve(raw, "secp256r1");
				} else
					decodedPub = (ECPublicKey) KeyCodec.getPubKeyFromCurve(decodeBase64, "secp256r1");
				// ECPublicKey decodedPub = (ECPublicKey)
				// KeyCodec.getPubKeyFromCurve(decodeBase64, "secp256r1");
				return NamedCurve.verify(KeyCodec.getKeyAsRawBytes(decodedPub), SHA.sha(dataForSigning, "SHA-256"),
						Asn1.transformRawSignature(signature.value));
			} else if (65 == decodeBase64.length
					&& AlgAndEncodingEnum.UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_DER == algAndEncoding) {
				ECPublicKey decodedPub = (ECPublicKey) KeyCodec.getPubKeyFromCurve(decodeBase64, "secp256r1");
				return NamedCurve.verify(KeyCodec.getKeyAsRawBytes(decodedPub), SHA.sha(dataForSigning, "SHA-256"),
						Asn1.decodeToBigIntegerArray(signature.value));
			} else {
				return NamedCurve.verify(KeyCodec.getKeyAsRawBytes(pubKey), SHA.sha(dataForSigning, "SHA-256"),
						Asn1.decodeToBigIntegerArray(signature.value));
			}
		}
	}

	private byte[] getRSADer(byte[] raw) throws Exception {
		if (raw.length != 259)
			throw new Exception();

		byte[] der = new byte[269];
		der[0] = (byte) 0x30;
		der[1] = (byte) 0x82;
		der[2] = (byte) 0x01;
		der[3] = (byte) 0x09;
		der[4] = (byte) 0x02;
		der[5] = (byte) 0x82;
		der[6] = (byte) 0x01;
		der[7] = (byte) 0x00;
		System.arraycopy(raw, 0, der, 8, 256);
		der[264] = (byte) 0x02;
		der[265] = (byte) 0x03;
		System.arraycopy(raw, 256, der, 266, 3);

		return der;

	}

	private PublicKey getPublicKeyFromBytesK1(byte[] pubKey, String curve)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(curve);
		KeyFactory kf = KeyFactory.getInstance("ECDSA", new BouncyCastleProvider());
		ECNamedCurveSpec params = new ECNamedCurveSpec(curve, spec.getCurve(), spec.getG(), spec.getN());
		ECPoint point = ECPointUtil.decodePoint(params.getCurve(), pubKey);
		ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, params);
		ECPublicKey pk = (ECPublicKey) kf.generatePublic(pubKeySpec);
		return pk;
	}

	public static boolean verify(byte[] pub, byte[] dataForSigning, BigInteger[] rs) throws Exception {

		Security.insertProviderAt(new BouncyCastleProvider(), 1);

		ECDSASigner signer = new ECDSASigner();
		X9ECParameters params = SECNamedCurves.getByName("secp256r1");
		ECDomainParameters ecParams = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(),
				params.getH());

		// byte[] asn1Pub = getPubKeyFromCurve2(pub, "secp256r1").getEncoded();

		byte[] x = new byte[32];
		System.arraycopy(pub, 1, x, 0, 32);

		byte[] y = new byte[32];
		System.arraycopy(pub, 32, y, 0, 32);

		org.bouncycastle.math.ec.ECPoint sigpoint = ecParams.getCurve().createPoint(rs[0], rs[1]);

		ECPublicKeyParameters pubKeyParams = new ECPublicKeyParameters(
				ecParams.getCurve().createPoint(new BigInteger(1, x), new BigInteger(1, y)), ecParams);
		signer.init(false, pubKeyParams);

		return signer.verifySignature(dataForSigning, rs[0], rs[1]);
	}

	private static PublicKey getPubKeyFromCurve(byte[] pubKey, String curveName)
			throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {
		ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(curveName);
		KeyFactory kf = KeyFactory.getInstance("ECDSA", new BouncyCastleProvider());
		ECNamedCurveSpec params = new ECNamedCurveSpec(curveName, spec.getCurve(), spec.getG(), spec.getN());
		ECPoint point = ECPointUtil.decodePoint(params.getCurve(), pubKey);
		ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, params);
		java.security.interfaces.ECPublicKey pk = (java.security.interfaces.ECPublicKey) kf.generatePublic(pubKeySpec);
		return pk;
	}

	private static PublicKey getPubKeyFromCurve2(byte[] pubKey, String curveName)
			throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {
		byte[] x = new byte[32];
		System.arraycopy(pubKey, 1, x, 0, 32);

		byte[] y = new byte[32];
		System.arraycopy(pubKey, 32, y, 0, 32);

		ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(curveName);
		KeyFactory kf = KeyFactory.getInstance("ECDSA", new BouncyCastleProvider());
		ECNamedCurveSpec params = new ECNamedCurveSpec(curveName, spec.getCurve(), spec.getG(), spec.getN());
		// ECPoint point = ECPointUtil.decodePoint(params.getCurve(), pubKey);
		ECPoint point = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
		ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, params);
		java.security.interfaces.ECPublicKey pk = (java.security.interfaces.ECPublicKey) kf.generatePublic(pubKeySpec);

		return pk;
	}

	/**
	 * getFcp
	 * <p>%%% BEGIN SOURCE CODE %%%
     * {@codesnippet ResponseHelper-getFcp}
     * %%% END SOURCE CODE %%%
	 * <p>This function reads the challenge from registration response
	 * 
	 * <p>AUTHres 2.2.1.1.4
	 * 
	 * @param response
	 * @return
	 * @throws Exception
	 */
	public FinalChallengeParams getFcp(AuthenticationResponse response) throws Exception {
		// BEGIN: ResponseHelper-getFcp
		if (response.fcParams == null || response.fcParams.isEmpty())
			throw new Exception();
		String fcp = new String(Base64.decodeBase64(response.fcParams.getBytes()));
		return gson.fromJson(fcp, FinalChallengeParams.class);
		// END: ResponseHelper-getFcp
	}

	public void checkFcp(FinalChallengeParams fcp) throws Exception {
		FidoConfig config = new FidoConfig();
		if (fcp.appID == null || fcp.appID.isEmpty() || !fcp.appID.equals(config.getAppId())) {
			logger.log(Level.INFO, "checkFcp() - invalid appID");
			throw new Exception();
		}
		if (fcp.challenge == null || fcp.challenge.isEmpty()
				|| !Base64.encodeBase64URLSafeString(fcp.challenge.getBytes()).equals(_challenge)) {
			// logger.log(Level.INFO, "checkFcp() - invalid challenge");
			throw new Exception();
		}

		if (fcp.facetID == null || fcp.facetID.isEmpty()) {
			logger.log(Level.INFO, "checkFcp() - invalid facetID");
			throw new Exception();
		}

		// String[] facets = getFacetIDs();
		// boolean found = false;
		// for (String facet : facets) {
		// if (fcp.facetID.equals(facet)) {
		// found = true;
		// break;
		// }
		// }
		// if (!found) {
		// if (!fcp.facetID.equals(config.getAppId())) {
		// logger.log(Level.INFO, "checkFcp() - invalid facetID");
		// throw new Exception();
		// }
		// }
	}

	private String[] getFacetIDs() {
		List<TrustedFacet> facets = trustedFacetDao.listAllTrustedFacets();
		String[] trustedIds = new String[facets.size()];

		for (int i = 0; i < facets.size(); i++)
			trustedIds[i] = facets.get(i).getName();

		return trustedIds;
	}

	public AlgAndEncodingEnum getAlgAndEncoding(Tag info) {
		int id = (int) info.value[3] + (int) info.value[4] * 256;
		AlgAndEncodingEnum ret = null;
		AlgAndEncodingEnum[] values = AlgAndEncodingEnum.values();
		for (AlgAndEncodingEnum algAndEncodingEnum : values) {
			if (algAndEncodingEnum.id == id) {
				ret = algAndEncodingEnum;
				break;
			}
		}
		logger.info(" : SignatureAlgAndEncoding : " + ret);
		return ret;
	}
}
