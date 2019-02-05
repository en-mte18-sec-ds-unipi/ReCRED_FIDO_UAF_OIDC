package eu.recred.fidouafsvc.ops;

import eu.recred.fido.uaf.crypto.Notary;
import eu.recred.fido.uaf.msg.AuthenticationRequest;
import eu.recred.fido.uaf.msg.Operation;
import eu.recred.fido.uaf.msg.OperationHeader;
import eu.recred.fido.uaf.msg.Version;
import eu.recred.fidouafsvc.storage.StorageInterface;
import eu.recred.fidouafsvc.util.RequestHelper;
import org.springframework.stereotype.Component;

/*
 * This class generates Authentication Requests.
 */

@Component
public class AuthenticationRequestGeneration {

	private RequestHelper requestHelper;

	private String appId = RegistrationRequestGeneration.APP_ID;
	private String[] acceptedAaids = null;
	private String username = null;
	private StorageInterface storageDao;

	// Empty Constractor
	public AuthenticationRequestGeneration() {
	}

	// Constractor with 3 parameters
	public AuthenticationRequestGeneration(String appId, String[] acceptedAaids, RequestHelper requestHelper) {
		this.requestHelper = requestHelper;
		this.appId = appId;
		this.acceptedAaids = acceptedAaids;
	}

	// Constractor with 5 parameters
	public AuthenticationRequestGeneration(String appId, String[] acceptedAaids, String username,
			StorageInterface storageDao, RequestHelper requestHelper) {
		this.requestHelper = requestHelper;
		this.appId = appId;
		this.acceptedAaids = acceptedAaids;
		this.username = username;
		this.storageDao = storageDao;
	}

	// This function creates an Authentication request
	// FIDOUAFAUT II
	/**
	 * createAuthenticationRequest
	 * <p>%%% BEGIN SOURCE CODE %%%
     * {@codesnippet AuthenticationRequestGeneration-createAuthenticationRequest}
     * %%% END SOURCE CODE %%%
	 * <p>This function creates an authentication request
	 * 
	 * <p>AUTHreq 1.2.1.1
	 * @see AuthenticationRequest
	 * @see OperationHeader
	 * 
	 * @param notary
	 * @return
	 */
	public AuthenticationRequest createAuthenticationRequest(Notary notary) {
		// BEGIN: AuthenticationRequestGeneration-createAuthenticationRequest
		AuthenticationRequest authRequest = new AuthenticationRequest();
		OperationHeader header = new OperationHeader();
		authRequest.challenge = requestHelper.generateChallenge();
		header.serverData = requestHelper.generateServerData(authRequest.challenge, notary);
		authRequest.header = header;
		authRequest.header.op = Operation.Auth;
		authRequest.header.appID = appId;
		authRequest.header.upv = new Version(1, 0);

		authRequest.policy = requestHelper.constructPolicy(acceptedAaids);
		// addKeyIDsToPolicy(authRequest.policy);

		return authRequest;
		// END: AuthenticationRequestGeneration-createAuthenticationRequest
	}

	// private void addKeyIDsToPolicy(Policy policy) {
	// String aaid = null, keyID = null;
	//
	// if (username != null) {
	// //System.out.println("Looking for the record");
	// RegistrationRecord record =
	// storageDao.readRegistrationRecordUsername(username);
	// if (record == null)
	// return;
	// aaid = record.authenticator.AAID;
	// keyID = record.authenticator.KeyID;
	//
	// for (int i = 0; i < policy.accepted.length; i++) {
	// if (policy.accepted[i][0].aaid[0].equals(aaid)) {
	// policy.accepted[i][0].keyIDs = new String[1];
	// policy.accepted[i][0].keyIDs[0] = keyID;
	// }
	// }
	// }
	// }

}
