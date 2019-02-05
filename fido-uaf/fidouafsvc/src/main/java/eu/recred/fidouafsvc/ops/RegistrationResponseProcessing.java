package eu.recred.fidouafsvc.ops;

import com.google.gson.Gson;
import eu.recred.fido.uaf.crypto.CertificateValidator;
import eu.recred.fido.uaf.crypto.CertificateValidatorImpl;
import eu.recred.fido.uaf.crypto.Notary;
import eu.recred.fido.uaf.msg.AuthenticatorRegistrationAssertion;
import eu.recred.fido.uaf.msg.FinalChallengeParams;
import eu.recred.fido.uaf.msg.Policy;
import eu.recred.fido.uaf.msg.RegistrationResponse;
import eu.recred.fido.uaf.tlv.Tags;
import eu.recred.fido.uaf.tlv.TagsEnum;
import eu.recred.fido.uaf.tlv.TlvAssertionParser;
import eu.recred.fidouafsvc.model.FidoConfig;
import eu.recred.fidouafsvc.model.metadata.MetadataStatement;
import eu.recred.fidouafsvc.storage.AuthenticatorRecord;
import eu.recred.fidouafsvc.storage.RegistrationRecord;
import eu.recred.fidouafsvc.storage.RequestAccountant;
import eu.recred.fidouafsvc.storage.StorageInterface;
import eu.recred.fidouafsvc.util.RequestHelper;
import eu.recred.fidouafsvc.util.ResponseHelper;
import org.apache.commons.codec.binary.Base64;

import java.nio.ByteBuffer;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

/*
 * This class generates Registration Responses.
 */

public class RegistrationResponseProcessing {

	private ResponseHelper responseHelper;

	private Logger logger = Logger.getLogger(this.getClass().getName());
	private long serverDataExpiryInMs = 5 * 60 * 1000;
	private Notary notary = null;
	private Gson gson = new Gson();
	private CertificateValidator certificateValidator;
	private StorageInterface storageDao;
	private RequestAccountant accountant = RequestAccountant.getInstance();

	// Constractor
	public RegistrationResponseProcessing() {
		this.certificateValidator = new CertificateValidatorImpl();
	}

	// Constractor with 4 parameters
	public RegistrationResponseProcessing(long serverDataExpiryInMs, Notary notary, ResponseHelper responseHelper,
			StorageInterface storageDao) {
		this.responseHelper = responseHelper;
		this.serverDataExpiryInMs = serverDataExpiryInMs;
		this.notary = notary;
		this.certificateValidator = new CertificateValidatorImpl();
		this.storageDao = storageDao;
	}

	// Check if response is not empty
	/**
	 * processResponse
	 * <p>%%% BEGIN SOURCE CODE %%%
     * {@codesnippet RegistrationResponseProcessing-processResponse}
     * %%% END SOURCE CODE %%%
	 * <p>This function validates registration response
	 * 
	 * <p>REGres 2.2.1.1
	 * @see RegistrationRecord
	 * 
	 * @param response
	 * @return
	 * @throws Exception
	 */
	public RegistrationRecord[] processResponse(RegistrationResponse response) throws Exception {
		// BEGIN: RegistrationResponseProcessing-processResponse
		RegistrationRecord[] temp = responseHelper.checkAssertions(response);
		if (temp != null)
			return temp;

		RegistrationRecord[] records = new RegistrationRecord[response.assertions.length];
		for (int i = 0; i < records.length; i++) {
			records[i] = new RegistrationRecord();
		}
		responseHelper.checkVersion(response.header.upv, records);
		responseHelper.checkServerData(response.header.serverData, records, notary, serverDataExpiryInMs);
		if (checkRegisteredTwice(records))
			return records;
		FinalChallengeParams fcp = responseHelper.getFcp(response);
		// responseHelper.checkFcp(fcp);

		byte[] FCHash = responseHelper.sha256(response.fcParams);

		for (int i = 0; i < records.length; i++) {
			records[i] = processAssertions(response.assertions[i], records[i], FCHash);
		}

		return records;
		// END: RegistrationResponseProcessing-processResponse
	}

	// Doublecheck if response is not empty
	/**
	 * checkRegisteredTwice
	 * <p>%%% BEGIN SOURCE CODE %%%
     * {@codesnippet RegistrationResponseProcessing-checkRegisteredTwice}
     * %%% END SOURCE CODE %%%
	 * <p>This function checks if the username of the registration response is stored
	 * 
	 * <p>REGres 2.2.1.1.4
	 * @see RegistrationRecord
	 * {@link eu.recred.fidouafsvc.storage.StorageInterface#readRegistrationRecordUsername(String)}
	 * 
	 * @param records
	 * @return
	 * @throws Exception
	 */
	private boolean checkRegisteredTwice(RegistrationRecord[] records) throws Exception {
		// BEGIN: RegistrationResponseProcessing-checkRegisteredTwice
		for (RegistrationRecord record : records) {
			if (storageDao.readRegistrationRecordUsername(record.username).size() == 2) {
				record.status = "1403";
				return true;
			}
		}

		return false;
		// END: RegistrationResponseProcessing-checkRegisteredTwice
	}

	/**
	 * processAssertions
	 * <p>%%% BEGIN SOURCE CODE %%%
     * {@codesnippet RegistrationResponseProcessing-processAssertions}
     * %%% END SOURCE CODE %%%
	 * <p>This function processes the assertions of the registration response record
	 * 
	 * <p>REGres 2.2.1.1.6
	 * @see RegistrationRecord
	 * @see TlvAssertionParser
	 * @see Tags
	 * @see MetadataStatement
	 * @see AuthenticatorRecord
	 * {@link eu.recred.fidouafsvc.util.ResponseHelper#verifyAttestationSignature(Tags, RegistrationRecord, CertificateValidator)}
	 * 
	 * @param authenticatorRegistrationAssertion
	 * @param record
	 * @param FCHash
	 * @return
	 */
	private RegistrationRecord processAssertions(AuthenticatorRegistrationAssertion authenticatorRegistrationAssertion,
			RegistrationRecord record, byte[] FCHash) {
		// BEGIN: RegistrationResponseProcessing-processAssertions
		if (record == null) {
			logger.log(Level.INFO, "[1400]: record null");
			record = new RegistrationRecord();
			record.status = "1400";
		}
		TlvAssertionParser parser = new TlvAssertionParser();
		try {
			Tags tags = parser.parse(authenticatorRegistrationAssertion.assertion);
			// if (!checkTLVMandatoryFields(tags))
			// throw new Exception();

			if (!tags.getTags().containsKey(TagsEnum.TAG_COUNTERS.id)) {
				logger.log(Level.INFO, "[1498]: no counters tag");
				record.status = "1498";
				return record;
			}

			String AAID = new String(tags.getTags().get(TagsEnum.TAG_AAID.id).value);
			if (!checkAAIDinPolicy(AAID)) {
				logger.log(Level.INFO, "[1498]: AAID not in policy");
				record.status = "1498";
				return record;
			}

			byte[] finalChallenge = tags.getTags().get(TagsEnum.TAG_FINAL_CHALLENGE.id).value;
			if (!responseHelper.compareByteArr(finalChallenge, FCHash)) {
				logger.log(Level.INFO, "[1498]: invalid FCHash");
				record.status = "1498";
				return record;
			}

			if (tags.getTags().containsKey(TagsEnum.TAG_ATTESTATION_BASIC_SURROGATE.id)) {
				MetadataStatement statement = null;
				try {
					statement = storageDao.getMetadataStatement(AAID);
				} catch (Exception e) {
					logger.log(Level.INFO, "[1500]: no metadata");
					record.status = "1500";
					return record;
				}
				if (statement.attestationRootCertificates.length == 0) {
					if (!responseHelper.verifySurrogate(tags, record)) {
						logger.log(Level.INFO, "[1496]: fail verify surrogate");
						record.attestVerifiedStatus = "NOT_VERIFIED";
						record.status = "1496";
						return record;
					} else {
						record.attestVerifiedStatus = "VALID";
						record.status = "1200";
					}
				} else {
					logger.log(Level.INFO, "[1496]: surrogate and root certificate");
					record.attestVerifiedStatus = "NOT_VERIFIED";
					record.status = "1496";
					return record;
				}
			} else {
				try {
					responseHelper.verifyAttestationSignature(tags, record, certificateValidator);
				} catch (Exception e) {
					logger.log(Level.INFO, "[1496]: faild attestation");
					record.attestVerifiedStatus = "NOT_VERIFIED";
					record.status = "1496";
					return record;
				}
			}

			if (record.attestVerifiedStatus.equals("NOT_VERIFIED")) {
				logger.log(Level.INFO, "[1496]: faild attestation");
				record.status = "1496";
				return record;
			}

			// if (tags.getTags().containsKey(TagsEnum.TAG_ATTESTATION_BASIC_SURROGATE.id))
			// {
			// record.status = "1496";
			// return record;
			// }

			AuthenticatorRecord authRecord = new AuthenticatorRecord();
			authRecord.AAID = new String(tags.getTags().get(TagsEnum.TAG_AAID.id).value);
			authRecord.KeyID = Base64.encodeBase64URLSafeString(tags.getTags().get(TagsEnum.TAG_KEYID.id).value);
			record.authenticator = authRecord;
			byte[] key = tags.getTags().get(TagsEnum.TAG_PUB_KEY.id).value;
			record.PublicKey = Base64.encodeBase64URLSafeString(tags.getTags().get(TagsEnum.TAG_PUB_KEY.id).value);
			record.AuthenticatorVersion = responseHelper.getAuthenticatorVersion(tags);
			byte[] counters = tags.getTags().get(TagsEnum.TAG_COUNTERS.id).value;
			byte[] sigcounter = new byte[4];
			System.arraycopy(counters, 0, sigcounter, 0, 4);
			record.SignCounter = "" + ByteBuffer.wrap(sigcounter).getInt();
			record.timeStamp = "" + new Date().getTime();
			record.deviceId = new String(tags.getTags().get(TagsEnum.TAG_DEVICE_ID.id).value);
			String fc = Base64.encodeBase64URLSafeString(tags.getTags().get(TagsEnum.TAG_FINAL_CHALLENGE.id).value);
			logger.log(Level.INFO, "FC: " + fc);
			if (record.status == null) {
				record.status = "1200";
			}
		} catch (Exception e) {
			record.status = "1498";
			logger.log(Level.INFO, "Fail to parse assertion: " + authenticatorRegistrationAssertion.assertion, e);
		}
		return record;
		// END: RegistrationResponseProcessing-processAssertions
	}

	private boolean checkTLVMandatoryFields(Tags tags) {
		if (!tags.getTags().containsKey(TagsEnum.TAG_UAFV1_REG_ASSERTION.id))
			return false;
		if (!tags.getTags().containsKey(TagsEnum.TAG_UAFV1_KRD.id))
			return false;
		if (!tags.getTags().containsKey(TagsEnum.TAG_AAID.id))
			return false;
		if (!tags.getTags().containsKey(TagsEnum.TAG_ASSERTION_INFO.id))
			return false;
		if (!tags.getTags().containsKey(TagsEnum.TAG_FINAL_CHALLENGE.id))
			return false;
		if (!tags.getTags().containsKey(TagsEnum.TAG_KEYID.id))
			return false;
		if (!tags.getTags().containsKey(TagsEnum.TAG_COUNTERS.id))
			return false;
		if (!tags.getTags().containsKey(TagsEnum.TAG_PUB_KEY.id))
			return false;
		if (!tags.getTags().containsKey(TagsEnum.TAG_ATTESTATION_BASIC_FULL.id)) {
			if (!tags.getTags().containsKey(TagsEnum.TAG_ATTESTATION_BASIC_SURROGATE.id))
				return false;
		}
		if (!tags.getTags().containsKey(TagsEnum.TAG_SIGNATURE.id))
			return false;
		return tags.getTags().containsKey(TagsEnum.TAG_ATTESTATION_CERT.id);
	}

	private boolean checkAAIDinPolicy(String AAID) {
		RequestHelper requestHelper = new RequestHelper();
		FidoConfig config = new FidoConfig();
		Policy policy = requestHelper.constructPolicy(config.getAaids());

		for (int i = 0; i < policy.accepted.length; i++) {
			if (policy.accepted[i][0].aaid[0].equals(AAID)) {
				return true;
			}
		}

		return false;
	}

}
