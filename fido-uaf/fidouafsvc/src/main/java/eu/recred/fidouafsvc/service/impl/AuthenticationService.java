package eu.recred.fidouafsvc.service.impl;

import com.google.gson.Gson;
import eu.recred.fido.uaf.msg.AuthenticationRequest;
import eu.recred.fido.uaf.msg.AuthenticationResponse;
import eu.recred.fido.uaf.msg.OperationHeader;
import eu.recred.fido.uaf.msg.Transaction;
import eu.recred.fidouafsvc.dao.MetadataStatementDao;
import eu.recred.fidouafsvc.dao.TrustedFacetDao;
import eu.recred.fidouafsvc.model.TrustedFacet;
import eu.recred.fidouafsvc.model.metadata.MetadataStatement;
import eu.recred.fidouafsvc.storage.AuthenticatorRecord;
import eu.recred.fidouafsvc.storage.RegistrationRecord;
import eu.recred.fidouafsvc.storage.RequestAccountant;
import eu.recred.fidouafsvc.storage.StorageInterface;
import eu.recred.fidouafsvc.util.RequestHelper;
import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/*
 * This class impliments the authentication service.
 */

@Service
public class AuthenticationService {

	Logger logger = Logger.getLogger(this.getClass().getName());

	Gson gson = new Gson();

	@Autowired
	TrustedFacetDao trustedFacetDao;

	@Autowired
	FetchRequestService fetchRequestService;

	@Autowired
	ProcessResponseService processResponseService;

	@Autowired
	MetadataStatementDao metadataStatementDao;

	@Autowired
	StorageInterface storageDao;

	private RequestAccountant accountant = RequestAccountant.getInstance();

	/**
	 * getAuthReqObj
	 * <p>%%% BEGIN SOURCE CODE %%%
     * {@codesnippet AuthenticationService-getAuthReqObj}
     * %%% END SOURCE CODE %%%
	 * <p>This function process the authentication request
	 * 
	 * <p>AUTHreq 1.2
	 * @see AuthenticationRequest
	 * {@link eu.recred.fidouafsvc.service.impl.FetchRequestService#getAuthenticationRequest()}
	 * {@link eu.recred.fidouafsvc.storage.RequestAccountant#addAuthenticationRequest(AuthenticationRequest)}
	 * 
	 * @return
	 */
	public AuthenticationRequest[] getAuthReqObj() {
		// BEGIN: AuthenticationService-getAuthReqObj
		AuthenticationRequest[] requests = new AuthenticationRequest[1];
		requests[0] = fetchRequestService.getAuthenticationRequest();

		accountant.addAuthenticationRequest(requests[0]);

		return requests;
		// END: AuthenticationService-getAuthReqObj
	}

	public AuthenticationRequest[] getAuthReqObj(String username) {
		AuthenticationRequest[] requests = new AuthenticationRequest[1];
		requests[0] = fetchRequestService.getAuthenticationRequest(username);

		return requests;
	}

	public AuthenticationRequest[] getAuthReqObjAppId(String appId) {
		AuthenticationRequest[] request = getAuthReqObj();
		setAppId(appId, request[0].header);

		return request;
	}

	public AuthenticationRequest[] getAuthReqObjAppIdTrx(String appId, String trx) {
		AuthenticationRequest[] request = getAuthReqObjAppId(appId);
		// setTransaction(trx, request);

		return request;
	}

	public AuthenticationRequest[] getAuthReqObjTrx(String username, String trx) throws Exception {
		AuthenticationRequest[] request = getAuthReqObj(username);
		setTransaction(trx, request, username);

		accountant.addAuthenticationRequest(request[0]);

		return request;
	}

	// FIDOUAFAUT IV
	/**
	 * response
	 * <p>%%% BEGIN SOURCE CODE %%%
     * {@codesnippet AuthenticationService-response}
     * %%% END SOURCE CODE %%%
	 * <p>This function checks the server response is not empty and stores the authentication record
	 * 
	 * <p>AUTHres 2.2
	 * @see AuthenticatorRecord
	 * @see AuthenticationResponse
	 * {@link eu.recred.fidouafsvc.service.impl.ProcessResponseService#processAuthResponse(AuthenticationResponse)}
	 * 
	 * @param payload
	 * @return
	 */
	public AuthenticatorRecord[] response(String payload) {
		// BEGIN: AuthenticationService-response
		AuthenticatorRecord[] result = null;
		try {
			if (!payload.isEmpty()) {
				AuthenticationResponse[] responses = gson.fromJson(payload, AuthenticationResponse[].class);
				result = processResponseService.processAuthResponse(responses[0]);
				return result;
			} else {
				logger.log(Level.INFO, "[1400]: EMPTY PAYLOAD");
				result = new AuthenticatorRecord[1];
				result[0] = new AuthenticatorRecord();
				result[0].status = "1400";
			}
		} catch (Exception e) {
			StringWriter sw = new StringWriter();
			PrintWriter pw = new PrintWriter(sw);
			e.printStackTrace(pw);
			logger.log(Level.INFO, "[1400]: EXCEPTION: " + sw.toString());
			result = new AuthenticatorRecord[1];
			result[0] = new AuthenticatorRecord();
			result[0].status = "1400";
		}
		return result;
		// END: AuthenticationService-response
	}

	private void setAppId(String appId, OperationHeader header) {
		if (appId == null || appId.isEmpty()) {
			return;
		}

		String decodedAppId = new String(Base64.decodeBase64(appId));
		List<TrustedFacet> facets = trustedFacetDao.listAllTrustedFacets();
		if (facets == null || facets.isEmpty())
			return;
		int len = facets.size();
		for (int i = 0; i < len; i++) {
			if (decodedAppId.equals(facets.get(i).getName())) {
				header.appID = decodedAppId;
				break;
			}
		}
	}

	private void setTransaction(String trxcontent, AuthenticationRequest[] requests, String username) throws Exception {
		RegistrationRecord record = storageDao.readRegistrationRecordUsername(username).get(0);
		if (record == null)
			throw new Exception("0");
		String AAID = record.authenticator.AAID;
		MetadataStatement statement = metadataStatementDao.getStatement(AAID);
		requests[0].transaction = new Transaction[1];
		Transaction t = new Transaction();

		if (statement.tcDisplay <= 0)
			throw new Exception("0");
		t.contentType = statement.tcDisplayContentType;
		if (t.contentType.equals("image/png")) {
			t.content = Base64.encodeBase64URLSafeString(
					RequestHelper.generateImage(trxcontent, (int) statement.tcDisplayPNGCharacteristics[0].width,
							(int) statement.tcDisplayPNGCharacteristics[0].height));
			t.tcDisplayPNGCharacteristics = statement.tcDisplayPNGCharacteristics[0];
		} else
			t.content = Base64.encodeBase64URLSafeString(trxcontent.getBytes());
		requests[0].transaction[0] = t;
	}

}
