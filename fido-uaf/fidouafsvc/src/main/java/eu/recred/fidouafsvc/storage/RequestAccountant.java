package eu.recred.fidouafsvc.storage;

import com.google.gson.Gson;
import eu.recred.fido.uaf.msg.AuthenticationRequest;
import eu.recred.fido.uaf.msg.RegistrationRequest;

import java.util.ArrayList;
import java.util.List;

/*
 * This class records requests.
 */

public class RequestAccountant {
	private List<RegistrationRequest> _registrations;
	private List<AuthenticationRequest> _authentications;

	private static RequestAccountant _instance = null;

	public static RequestAccountant getInstance() {
		if (_instance == null)
			_instance = new RequestAccountant();

		return _instance;
	}

	/**
	 * addRegistrationRequest
	 * <p>%%% BEGIN SOURCE CODE %%%
     * {@codesnippet RequestAccountant-addRegistrationRequest}
     * %%% END SOURCE CODE %%%
	 * <p>This function inserts a registration record
	 * 
	 * <p>REGreq 1.2.2
	 * 
	 * @param request
	 */
	public void addRegistrationRequest(RegistrationRequest request) {
		// BEGIN: RequestAccountant-addRegistrationRequest
		_registrations.add(request);
		// END: RequestAccountant-addRegistrationRequest
	}

	/**
	 * addAuthenticationRequest
	 * <p>%%% BEGIN SOURCE CODE %%%
     * {@codesnippet RequestAccountant-addAuthenticationRequest}
     * %%% END SOURCE CODE %%%
	 * <p>This function inserts a authentication record
	 * 
	 * <p>AUTHreq 1.2.2
	 * 
	 * @param request
	 */
	public void addAuthenticationRequest(AuthenticationRequest request) {
		// BEGIN: RequestAccountant-addAuthenticationRequest
		_authentications.add(request);
		// END: RequestAccountant-addAuthenticationRequest
	}

	public RegistrationRequest getRegistrationRequest(String serverData) {
		for (RegistrationRequest request : _registrations) {
			if (request.header.serverData.equals(serverData))
				return request;
		}

		return null;
	}

	public AuthenticationRequest getAuthenticationRequest(String serverData) {
		for (AuthenticationRequest request : _authentications) {
			if (request.header.serverData.equals(serverData))
				return request;
		}

		return null;
	}

	private RequestAccountant() {
		_registrations = new ArrayList<>();
		_authentications = new ArrayList<>();
		_authentications.add(new Gson().fromJson(
				"{\"policy\": {\"accepted\": [[{\"aaid\": [\"EBA0#0001\"]}], [{\"aaid\": [\"FFFF#0001\"]}], [{\"aaid\": [\"FFFF#0002\"]}], [{\"aaid\": [\"FFFF#0003\"]}], [{\"aaid\": [\"FFFF#0004\"]}], [{\"aaid\": [\"FFFF#0005\"], \"keyIDs\": [\"pgPsIhf1r1QiUdbCi2z4LdwBFkqQGU_cQxS5tAs9-8w\"]}], [{\"aaid\": [\"FFFF#0006\"]}], [{\"aaid\": [\"FFFF#0007\"]}], [{\"aaid\": [\"FFFF#0008\"]}], [{\"aaid\": [\"FFFF#0009\"]}], [{\"aaid\": [\"FFFF#0010\"]}], [{\"aaid\": [\"FFFF#0011\"]}], [{\"aaid\": [\"FFFF#0012\"]}], [{\"aaid\": [\"FFFF#0013\"]}], [{\"aaid\": [\"FFFF#0014\"]}], [{\"aaid\": [\"FFFF#0015\"]}], [{\"aaid\": [\"FFFF#0016\"]}], [{\"aaid\": [\"FFFF#0017\"]}], [{\"aaid\": [\"FFFF#5201\"]}]]}, \"header\": {\"upv\": {\"major\": 1, \"minor\": 0}, \"appID\": \"http://recred-dev.certsign.ro:8181/fidouaf-svc/v1/trustedfacets\", \"serverData\": \"bFBQNmdacnV4QnZmWmc1ZTB1R2Q2djZkaldURXFGbWVyVmdUV3VTM2FVOC5NVFE0TURVd01UTTFOVFExT1EuU2tSS2FFcEVSWGRLUmxwRFUwZHNXV1ZyVVhkU01rMTVVMGRXYTJKSE1VOWxSa3BRWkROVg\", \"op\": \"Auth\"}, \"challenge\": \"JDJhJDEwJFZCSGlYekQwR2MySGVkbG1OeFJPd3U\", \"transaction\": [{\"content\": \"YWJjZGVmZw\", \"contentType\": \"text/plain\"}]}",
				AuthenticationRequest.class));
	}
}