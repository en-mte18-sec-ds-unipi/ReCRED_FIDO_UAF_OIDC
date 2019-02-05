package eu.recred.fidouafsvc.service.impl;

import com.google.gson.Gson;
import eu.recred.fido.uaf.msg.*;
import eu.recred.fidouafsvc.storage.AuthenticatorRecord;
import eu.recred.fidouafsvc.storage.RegistrationRecord;
import eu.recred.fidouafsvc.storage.StorageInterface;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by sorin.teican on 8/29/2016.
 */

/*
 * This class impliments the deregistration service.
 */

@Service
public class DeregRequestProcessorService {
	Logger logger = Logger.getLogger(this.getClass().getSimpleName());

	private Gson gson = new Gson();

	@Value("${appId}")
	private String appId;

	@Autowired
	@Qualifier("storageDao")
	private StorageInterface storageDao;

	public String process(String payload) {
		if (!payload.isEmpty()) {
			try {
				DeregistrationRequest[] deregFromJson = gson.fromJson(payload, DeregistrationRequest[].class);
				DeregistrationRequest request = deregFromJson[0];

				AuthenticatorRecord record = new AuthenticatorRecord();
				for (DeregisterAuthenticator authenticator : request.authenticators) {
					record.AAID = authenticator.aaid;
					record.KeyID = authenticator.keyID;
					try {
						String key = record.toString();
						storageDao.deleteRegistrationRecord(key);
					} catch (Exception e) {
						System.out.println("Dereg " + "Failure: Problem in deleting record from local DB");
						return "Failure: Problem in deleting record from local DB";
					}
				}
			} catch (Exception e) {
				System.out.println("Dereg " + "Failure: problem processing deregistration request");
				return "Failure: problem processing deregistration request";
			}
			System.out.println("Dereg " + "Success");
			return "Success";
		}
		System.out.println("Dereg " + "Failure: problem processing deregistration request");
		return "Failure: problem processing deregistration request";
	}

	// FIDOUAFDER II
	/**
	 * getRequest
	 * <p>%%% BEGIN SOURCE CODE %%%
     * {@codesnippet DeregRequestProcessorService-getRequest}
     * %%% END SOURCE CODE %%%
	 * <p>This function processes the deregistration request
	 * 
	 * <p>DEREGreq 1.2
	 * @see DeregistrationRequest
	 * @see RegistrationRecord
	 * @see DeregisterAuthenticator
	 * {@link eu.recred.fidouafsvc.storage.StorageInterface#readRegistrationRecordUsername(String)}
	 * {@link eu.recred.fidouafsvc.storage.StorageInterface#deleteRegistrationRecord(String)}
	 * 
	 * @param username
	 * @return
	 * @throws Exception
	 */
	public DeregistrationRequest[] getRequest(String username) throws Exception {
		// BEGIN: DeregRequestProcessorService-getRequest
		DeregistrationRequest[] request = new DeregistrationRequest[1];
		request[0] = new DeregistrationRequest();

		List<RegistrationRecord> records = storageDao.readRegistrationRecordUsername(username);

		request[0].header = new OperationHeader();
		request[0].header.op = Operation.Dereg;
		request[0].header.appID = appId + "/v1/trustedfacets";
		request[0].header.upv = new Version(1, 0);
		request[0].authenticators = new DeregisterAuthenticator[1];

		long freshestKeyTimestamp = 0;
		int freshestKeyIndex = 0;
		for (int i = 0; i < records.size(); i++) {
			if (Long.parseLong(records.get(i).timeStamp) > freshestKeyTimestamp) {
				freshestKeyTimestamp = Long.parseLong(records.get(i).timeStamp);
				freshestKeyIndex = i;
			}
		}

		request[0].authenticators[0] = new DeregisterAuthenticator();
		request[0].authenticators[0].aaid = records.get(freshestKeyIndex).authenticator.AAID;
		request[0].authenticators[0].keyID = records.get(freshestKeyIndex).authenticator.KeyID;
		storageDao.deleteRegistrationRecord(records.get(freshestKeyIndex).authenticator.toString());

		// storageDao.deleteRegistrationRecord(record.authenticator.toString());

		return request;
		// END: DeregRequestProcessorService-getRequest
	}

	public DeregResponse getFailoverRequest(String username) throws Exception {
		DeregResponse response = new DeregResponse();
		response.code = 1;
		List<RegistrationRecord> records = storageDao.readRegistrationRecordUsername(username);

		if (records.size() != 2) {
			response.reason = "User has " + records.size() + " keys!";
			return response;
		}

		long timestamp = Long.parseLong(records.get(0).timeStamp);
		long timestamp2 = Long.parseLong(records.get(1).timeStamp);

		if (timestamp == timestamp2)
			throw new Exception();

		if (timestamp < timestamp2) {
			response.code = 0;
			logger.log(Level.INFO, "Failover key: " + records.get(0).authenticator.KeyID);
			storageDao.deleteRegistrationRecord(records.get(0).authenticator.toString());
		} else {
			response.code = 0;
			logger.log(Level.INFO, "Failover key: " + records.get(1).authenticator.KeyID);
			storageDao.deleteRegistrationRecord(records.get(1).authenticator.toString());
		}

		return response;
	}

	public class DeregResponse {
		public int code;
		public String reason;
	}
}
