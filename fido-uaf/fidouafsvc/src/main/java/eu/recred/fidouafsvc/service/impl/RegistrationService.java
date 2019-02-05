package eu.recred.fidouafsvc.service.impl;

import com.google.gson.Gson;
import eu.recred.fido.uaf.msg.OperationHeader;
import eu.recred.fido.uaf.msg.RegistrationRequest;
import eu.recred.fido.uaf.msg.RegistrationResponse;
import eu.recred.fidouafsvc.dao.RegistrationRecordDao;
import eu.recred.fidouafsvc.dao.TrustedFacetDao;
import eu.recred.fidouafsvc.model.TrustedFacet;
import eu.recred.fidouafsvc.storage.RegistrationRecord;
import eu.recred.fidouafsvc.storage.RequestAccountant;
import org.apache.commons.codec.binary.Base64;
import org.hibernate.HibernateException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/*
 * This class impliments the registration service.
 */

@Service
public class RegistrationService {

	private Logger logger = Logger.getLogger(this.getClass().getName());

	Gson gson = new Gson();

	@Autowired
	TrustedFacetDao trustedFacetDao;

	@Autowired
	RegistrationRecordDao registrationRecordDao;

	@Autowired
	FetchRequestService fetchRequestService;

	@Autowired
	ProcessResponseService processResponseService;

	RequestAccountant accountant = RequestAccountant.getInstance();

	/**
	 * regReqUsername
	 * <p>%%% BEGIN SOURCE CODE %%%
     * {@codesnippet RegistrationService-regReqUsername}
     * %%% END SOURCE CODE %%%
	 * <p>This function process the registration request
	 * 
	 * <p>REGreq 1.2
	 * @see RegistrationRequest
	 * {@link eu.recred.fidouafsvc.service.impl.FetchRequestService#getRegistrationRequest(String)}
	 * {@link eu.recred.fidouafsvc.storage.RequestAccountant#addRegistrationRequest(RegistrationRequest)}
	 * 
	 * @param username
	 * @return
	 */
	public RegistrationRequest[] regReqUsername(String username) {
		// BEGIN: RegistrationService-regReqUsername
		RegistrationRequest[] request = new RegistrationRequest[1];
		request[0] = fetchRequestService.getRegistrationRequest(username);
		accountant.addRegistrationRequest(request[0]);
		return request;
		// END: RegistrationService-regReqUsername
	}

	public RegistrationRequest[] regReqUsernameAppId(String username, String appId) {
		RegistrationRequest[] request = regReqUsername(username);
		setAppId(appId, request[0].header);

		return request;
	}

	// FIDOUAFREG IV
	/**
	 * response
	 * <p>%%% BEGIN SOURCE CODE %%%
     * {@codesnippet RegistrationService-response}
     * %%% END SOURCE CODE %%%
	 * <p>This function checks the server response is not empty and stores the registration record
	 * 
	 * <p>REGres 2.2
	 * @see RegistrationRecord
	 * @see RegistrationResponse
	 * {@link eu.recred.fidouafsvc.service.impl.ProcessResponseService#processRegResponse(RegistrationResponse)}
	 * {@link eu.recred.fidouafsvc.dao.RegistrationRecordDao#addRegistrationRecords(RegistrationRecord[])}
	 * 
	 * @param payload
	 * @return
	 */
	public RegistrationRecord[] response(String payload) {
		// BEGIN: RegistrationService-response
		RegistrationRecord[] result = null;
		try {
			if (!payload.isEmpty()) {
				RegistrationResponse[] fromJson = gson.fromJson(payload, RegistrationResponse[].class);

				RegistrationResponse response = fromJson[0];
				result = processResponseService.processRegResponse(response);
				if (result[0].status.equals("1200")) {
					try {
						registrationRecordDao.addRegistrationRecords(result);
					} catch (HibernateException e) {
						// result = new RegistrationRecord[1];
						// result[0] = new RegistrationRecord();
						logger.log(Level.INFO, "[1500]: Exception while saving registration record");
						result[0].status = "1500";
					}

					// } else {
					// result = new RegistrationRecord[1];
					// result[0] = new RegistrationRecord();
					// result[0].status = "Error: payload could not be empty";
					// }
				}

			}

		} catch (Exception e) {
			StringWriter sw = new StringWriter();
			PrintWriter pw = new PrintWriter(sw);
			e.printStackTrace(pw);
			logger.log(Level.INFO, "[1498] RegistrationServiceException: " + sw.toString());
			result = new RegistrationRecord[1];
			result[0] = new RegistrationRecord();
			result[0].status = "1498";
		}
		return result;
		// END: RegistrationService-response
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
}
