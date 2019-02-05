package eu.recred.fidouafsvc.ops;

import eu.recred.fido.uaf.crypto.Notary;
import eu.recred.fido.uaf.crypto.SHA;
import eu.recred.fido.uaf.msg.AuthenticationRequest;
import eu.recred.fido.uaf.msg.AuthenticationResponse;
import eu.recred.fido.uaf.msg.AuthenticatorSignAssertion;
import eu.recred.fido.uaf.msg.FinalChallengeParams;
import eu.recred.fido.uaf.tlv.*;
import eu.recred.fidouafsvc.storage.AuthenticatorRecord;
import eu.recred.fidouafsvc.storage.RegistrationRecord;
import eu.recred.fidouafsvc.storage.RequestAccountant;
import eu.recred.fidouafsvc.storage.StorageInterface;
import eu.recred.fidouafsvc.util.ResponseHelper;
import org.apache.commons.codec.binary.Base64;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/*
 * This class generates Authentication Responses.
 */

public class AuthenticationResponseProcessing {

	private ResponseHelper responseHelper;

	private Logger logger = Logger.getLogger(this.getClass().getName());
	private long serverDataExpiryInMs;
	private Notary notary;
	private RequestAccountant accountant = RequestAccountant.getInstance();

	// Empty Constractor
	public AuthenticationResponseProcessing() {

	}

	// Constractor with 3 parameters
	public AuthenticationResponseProcessing(long serverDataExpiryInMs, Notary notary, ResponseHelper responseHelper) {
		this.responseHelper = responseHelper;
		this.serverDataExpiryInMs = serverDataExpiryInMs;
		this.notary = notary;
	}

	// Check if response is not empty
	/**
	 * verify
	 * <p>%%% BEGIN SOURCE CODE %%%
     * {@codesnippet AuthenticationResponseProcessing-verify}
     * %%% END SOURCE CODE %%%
	 * <p>This function checks if response is not empty
	 * 
	 * <p>AUTHres 2.2.1.1
	 * @see AuthenticatorRecord
	 * @see FinalChallengeParams
	 * {@link eu.recred.fidouafsvc.util.ResponseHelper#checkAssertions(AuthenticationResponse)}
	 * {@link eu.recred.fidouafsvc.util.ResponseHelper#checkVersion(eu.recred.fido.uaf.msg.Version, AuthenticatorRecord[])}
	 * {@link eu.recred.fidouafsvc.util.ResponseHelper#checkServerData(String, AuthenticatorRecord[], Notary, long)}
	 * {@link eu.recred.fidouafsvc.util.ResponseHelper#getFcp(AuthenticationResponse)}
	 * {@link eu.recred.fidouafsvc.ops.AuthenticationResponseProcessing#processAssertions(AuthenticatorSignAssertion, StorageInterface, byte[], AuthenticationResponse)}
	 * 
	 * @param response
	 * @param serverData
	 * @return
	 * @throws Exception
	 */
	public AuthenticatorRecord[] verify(AuthenticationResponse response, StorageInterface serverData) throws Exception {
		// BEGIN: AuthenticationResponseProcessing-verify
		// AuthenticatorRecord[] result = new
		// AuthenticatorRecord[response.assertions.length];
		AuthenticatorRecord[] temp = responseHelper.checkAssertions(response);
		if (temp != null)
			return temp;

		AuthenticatorRecord[] records = new AuthenticatorRecord[response.assertions.length];
		for (int i = 0; i < records.length; i++) {
			records[i] = new AuthenticatorRecord();
		}

		responseHelper.checkVersion(response.header.upv, records);
		responseHelper.checkServerData(response.header.serverData, records, notary, serverDataExpiryInMs);
		FinalChallengeParams fcp = responseHelper.getFcp(response);
		// responseHelper.checkFcp(fcp);

		byte[] FCHash = responseHelper.sha256(response.fcParams);

		for (int i = 0; i < records.length; i++) {
			records[i] = processAssertions(response.assertions[i], serverData, FCHash, response);
		}
		return records;
		// END: AuthenticationResponseProcessing-verify
	}

	// Verify response that is going to send
	/**
	 * processAssertions
	 * <p>%%% BEGIN SOURCE CODE %%%
     * {@codesnippet AuthenticationResponseProcessing-processAssertions}
     * %%% END SOURCE CODE %%%
	 * <p>This function processes the assertions of the registration response record
	 * 
	 * <p>AUTHres 2.2.1.1.5
	 * @see TlvAssertionParser
	 * @see AuthenticatorRecord
	 * @see RegistrationRecord
	 * @see Tags
	 * @see Tag
	 * @see AlgAndEncodingEnum
	 * {@link eu.recred.fidouafsvc.ops.AuthenticationResponseProcessing#getRegistration(AuthenticatorRecord, StorageInterface)}
	 * 
	 * @param authenticatorSignAssertion
	 * @param storage
	 * @param FCHash
	 * @param response
	 * @return
	 */
	private AuthenticatorRecord processAssertions(AuthenticatorSignAssertion authenticatorSignAssertion,
			StorageInterface storage, byte[] FCHash, AuthenticationResponse response) {
		// BEGIN: AuthenticationResponseProcessing-processAssertions
		TlvAssertionParser parser = new TlvAssertionParser();
		AuthenticatorRecord authRecord = new AuthenticatorRecord();
		RegistrationRecord registrationRecord = null;

		try {
			authRecord.timestamp = "" + new Date().getTime();
			Tags tags = parser.parse(authenticatorSignAssertion.assertion);
			authRecord.AAID = new String(tags.getTags().get(TagsEnum.TAG_AAID.id).value);

			byte[] finalChallenge = tags.getTags().get(TagsEnum.TAG_FINAL_CHALLENGE.id).value;
			if (!responseHelper.compareByteArr(finalChallenge, FCHash)) {
				logger.log(Level.INFO, "Final challenge verification failed");
				authRecord.status = "1498";
				return authRecord;
			}

			if (!checkTransactionHash(tags, response)) {
				logger.log(Level.INFO, "Transcation verification failed!");
				authRecord.status = "1498";
				return authRecord;
			}

			byte[] keyid = tags.getTags().get(TagsEnum.TAG_KEYID.id).value;
			System.out.println("KeyID bytes: " + keyid);
			authRecord.KeyID = Base64.encodeBase64URLSafeString(tags.getTags().get(TagsEnum.TAG_KEYID.id).value);
			// authRecord.KeyID = new String(
			// tags.getTags().get(TagsEnum.TAG_KEYID.id).value);
			registrationRecord = getRegistration(authRecord, storage);
			int receivedCounter = Integer
					.reverseBytes(ByteBuffer.wrap(tags.getTags().get(TagsEnum.TAG_COUNTERS.id).value).getInt());
			int storedCounter = Integer.reverseBytes(Integer.parseInt(registrationRecord.SignCounter));
			// log the values;
			logger.log(Level.INFO, "[!!!COUNTERS!!!]received counter: " + receivedCounter);
			logger.log(Level.INFO, "[!!!COUNTERS!!!]stored counter: " + storedCounter);
			if (storedCounter != 0 && receivedCounter != 0) {
				if (storedCounter == 268435456 && receivedCounter == 268435456) {
					// TODO: Server-Auth-Resp-9-P-1 keeps sending the same counter value and fails.
				} else if (storedCounter >= receivedCounter) {
					logger.log(Level.INFO, "Counter verification failed!");
					authRecord.status = "1498";
					return authRecord;
				}
			}
			registrationRecord.SignCounter = "" + Integer.reverseBytes(receivedCounter);
			try {
				updateRecord(registrationRecord, storage);
			} catch (Exception e) {
				logger.log(Level.INFO, "Update sign counter db exception");
				authRecord.status = "1500";
				return authRecord;
			}

			Tag signnedData = tags.getTags().get(TagsEnum.TAG_UAFV1_SIGNED_DATA.id);
			Tag signature = tags.getTags().get(TagsEnum.TAG_SIGNATURE.id);
			Tag info = tags.getTags().get(TagsEnum.TAG_ASSERTION_INFO.id);
			AlgAndEncodingEnum algAndEncoding = responseHelper.getAlgAndEncoding(info);
			String pubKey = registrationRecord.PublicKey;
			try {
				if (!responseHelper.verifySignature(signnedData, signature, pubKey, algAndEncoding)) {
					logger.log(Level.INFO, "Signature verification failed for authenticator: " + authRecord.toString());
					authRecord.status = "1498";
					return authRecord;
				}
			} catch (Exception e) {
				logger.log(Level.INFO, "Signature verification failed for authenticator: " + authRecord.toString(), e);
				authRecord.status = "1498";
				return authRecord;
			}
			authRecord.username = registrationRecord.username;
			authRecord.deviceId = registrationRecord.deviceId;
			authRecord.status = "1200";
			return authRecord;
		} catch (IOException e) {
			logger.log(Level.INFO, "Fail to parse assertion: " + authenticatorSignAssertion.assertion, e);
			authRecord.status = "1498";
			return authRecord;
		}
		// END: AuthenticationResponseProcessing-processAssertions
	}

	private RegistrationRecord getRegistration(AuthenticatorRecord authRecord, StorageInterface serverData) {
		// System.out.println("AuthenticatorResponseProcessing: getRegistration(" +
		// authRecord.toString() + ")");
		return serverData.readRegistrationRecord(authRecord.toString());
	}

	private void updateRecord(RegistrationRecord record, StorageInterface storage) throws Exception {
		RegistrationRecord[] records = new RegistrationRecord[1];
		records[0] = record;
		storage.update(records);
	}

	private boolean checkTransactionHash(Tags tags, AuthenticationResponse response) {
		Tag assertionInfo = tags.getTags().get(TagsEnum.TAG_ASSERTION_INFO.id);
		if (assertionInfo.value[2] == 0x02) {
			logger.log(Level.INFO, "[!!!HASH!!!]Server data: " + response.header.serverData);
			AuthenticationRequest request = null;
			request = accountant.getAuthenticationRequest(response.header.serverData);
			if (request == null) {
				logger.log(Level.INFO, "[!!!HASH!!!]Didn`t find auth req!");
				return false;
			}
			if (request.transaction == null || request.transaction.length == 0) {
				logger.log(Level.INFO, "[!!!HASH!!!]invalid request transaction structure!");

				return false;
			}
			List<byte[]> trxList = new ArrayList<>();
			for (int i = 0; i < request.transaction.length; i++) {
				if (request.transaction[i].content == null || request.transaction[i].content.isEmpty()) {
					logger.log(Level.INFO, "[!!!HASH!!!]invalid request transaction structure!2");
					return false;
				} else {
					try {
						byte[] content = Base64.decodeBase64(request.transaction[i].content);
						trxList.add(SHA.sha(content, "SHA-256"));
					} catch (Exception e) {
						logger.log(Level.INFO, "[!!!HASH!!!]sha exception!");
						return false;
					}
				}
			}

			byte[] hash = tags.getTags().get(TagsEnum.TAG_TRANSACTION_CONTENT_HASH.id).value;

			boolean found = false;
			for (byte[] trxHash : trxList) {
				if (trxHash.length == hash.length) {
					if (Arrays.equals(trxHash, hash)) {
						found = true;
						break;
					}
				} else
					continue;
			}

			if (!found)
				logger.log(Level.INFO, "[!!!HASH!!!]didn`t find hash in cache!");
			else
				logger.log(Level.INFO, "[!!!HASH!!!]found hash in cache");

			return found;
		} else
			return true;
	}

}
