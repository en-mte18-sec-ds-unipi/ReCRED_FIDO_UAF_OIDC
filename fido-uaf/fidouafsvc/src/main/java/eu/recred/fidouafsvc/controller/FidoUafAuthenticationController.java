package eu.recred.fidouafsvc.controller;

import com.google.gson.Gson;
import eu.recred.fidouafsvc.dto.ServerResponse;
import eu.recred.fidouafsvc.model.FidoConfig;
import eu.recred.fidouafsvc.service.impl.AuthenticationService;
import eu.recred.fidouafsvc.storage.AuthenticatorRecord;
import eu.recred.fido.uaf.msg.AuthenticationRequest;
import eu.recred.fidouafsvc.storage.RequestAccountant;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by sorin.teican on 8/29/2016.
 */

/*
 * This controller handles authentication requests.
 */

@RestController
@RequestMapping("/v1/authentication")
public class FidoUafAuthenticationController {

	private FidoConfig config = new FidoConfig();

	private Logger logger = Logger.getLogger(this.getClass().getName());

	private Gson _gson = new Gson();

	private RequestAccountant accountant = RequestAccountant.getInstance();

	@Autowired
	private AuthenticationService authenticationService;

	// FIDOUAFAUT I
	/**
	 *getRequest
	 * <p>%%% BEGIN SOURCE CODE %%%
     * {@codesnippet FidoUafAuthenticationController-getRequest}
     * %%% END SOURCE CODE %%%
	 * <p>This function is initiated when authentication request endpoind is called
	 * 
	 * <p>AUTHreq 1
	 * {@link eu.recred.fidouafsvc.model.FidoConfig#getAppId()}
	 * {@link eu.recred.fidouafsvc.service.impl.AuthenticationService#getAuthReqObj()}
	 * 
	 * @return
	 */
	@RequestMapping(value = "/request", method = RequestMethod.GET)
	public String getRequest() {
		// BEGIN: FidoUafAuthenticationController-getRequest
		String request;
		logger.log(Level.INFO, "***-----BEGIN AUTH REQUEST-----***");
		logger.log(Level.INFO, "APPID: " + config.getAppId());
		request = _gson.toJson(authenticationService.getAuthReqObj());
		logger.log(Level.INFO, "REQUEST: " + request);
		logger.log(Level.INFO, "***-----END AUTH REQUEST-----***");

		return request;
		// END: FidoUafAuthenticationController-getRequest
	}

	@RequestMapping(value = "/request/{appid}", method = RequestMethod.GET)
	public AuthenticationRequest[] getRequestByAppid(@PathVariable(value = "appid") String appid) {
		return authenticationService.getAuthReqObjAppId(appid);
	}

	@RequestMapping(value = "/request/{appid}/{trxcontent}", method = RequestMethod.GET)
	public AuthenticationRequest[] getRequestByAppidByTrxcontent(@PathVariable(value = "appid") String appid,
			@PathVariable(value = "trxcontent") String trxcontent) {
		return authenticationService.getAuthReqObjAppIdTrx(appid, trxcontent);
	}

	@RequestMapping(value = "/request/trx/{username:.+}/{trxcontent}", method = RequestMethod.GET)
	public String getRequestByTrxcontent(@PathVariable(value = "username") String username,
			@PathVariable(value = "trxcontent") String trxcontent) {
		try {
			String request;
			logger.log(Level.INFO, "***-----BEGIN AUTH REQUEST-----***");
			logger.log(Level.INFO, "APPID: " + config.getAppId());
			logger.log(Level.INFO, "USERNAME: " + username);
			logger.log(Level.INFO, "TRXCONTENT: " + trxcontent);
			request = _gson.toJson(authenticationService.getAuthReqObjTrx(username, trxcontent));
			logger.log(Level.INFO, "REQUEST: " + request);
			logger.log(Level.INFO, "***-----END AUTH REQUEST-----***");
			return request;
		} catch (Exception e) {
			return "1403";
		}
	}

	// FIDOUAFAUT III
	/**
	 * getResponse
	 * <p>%%% BEGIN SOURCE CODE %%%
     * {@codesnippet FidoUafAuthenticationController-getResponse}
     * %%% END SOURCE CODE %%%
	 * <p>This function is initiated when authentication responce endpoint is called
	 * 
	 * <p>AUTHres 2
	 * @see AuthenticatorRecord
	 * @see ServerResponse
	 * {@link eu.recred.fidouafsvc.model.FidoConfig#getAppId()}
	 * {@link eu.recred.fidouafsvc.service.impl.AuthenticationService#response(String)}
	 * 
	 * @param payload
	 * @return
	 */
	@RequestMapping(value = "/response", method = RequestMethod.POST)
	public AuthenticatorRecord[] getResponse(@RequestBody String payload) {
		// BEGIN: FidoUafAuthenticationController-getResponse
		AuthenticatorRecord[] records;
		ServerResponse response = new ServerResponse();
		logger.log(Level.INFO, "***-----BEGIN AUTH RESPONSE-----***");
		logger.log(Level.INFO, "APPID: " + config.getAppId());
		logger.log(Level.INFO, "PAYLOAD: " + payload);
		records = authenticationService.response(payload);
		response.statusCode = Integer.parseInt(records[0].status);
		logger.log(Level.INFO, "RESPONSE: " + _gson.toJson(records));
		logger.log(Level.INFO, "***-----END AUTH RESPONSE-----***");
		return records;
		// return response;
		// END: FidoUafAuthenticationController-getResponse
	}
}
