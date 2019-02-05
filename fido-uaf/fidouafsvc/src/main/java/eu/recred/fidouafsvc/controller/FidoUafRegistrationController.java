package eu.recred.fidouafsvc.controller;

import com.google.gson.Gson;
import eu.recred.fido.uaf.msg.DeregistrationRequest;
import eu.recred.fido.uaf.msg.RegistrationRequest;
import eu.recred.fidouafsvc.dto.ServerResponse;
import eu.recred.fidouafsvc.model.FidoConfig;
import eu.recred.fidouafsvc.service.impl.DeregRequestProcessorService;
import eu.recred.fidouafsvc.service.impl.RegistrationService;
import eu.recred.fidouafsvc.storage.RegistrationRecord;
import eu.recred.fidouafsvc.storage.RequestAccountant;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by georgeg on 02/07/16.
 */

/*
 * FIDO UAF Registration Messages Flow.
 * Get Registration Request.
 * Get Registration Response.
 */

/*
 * This controller handles registration requests.
 */
@RestController
@RequestMapping("/v1/registration")
public class FidoUafRegistrationController {

	private FidoConfig config = new FidoConfig();

	private Logger logger = Logger.getLogger(this.getClass().getName());

	private Gson gson = new Gson();

	private RequestAccountant accountant = RequestAccountant.getInstance();

	@Autowired
	private DeregRequestProcessorService deregRequestProcessorService;

	@Autowired
	private RegistrationService registrationService;

	// FIDOUAFREG I
	/**
	 * getRequestByUsername
	 * <p>%%% BEGIN SOURCE CODE %%%
     * {@codesnippet FidoUafRegistrationController-getRequestByUsername}
     * %%% END SOURCE CODE %%%
	 * <p>This function is initiated when Registration request endpoind is called
	 * 
	 * <p>REGreq 1
	 * {@link eu.recred.fidouafsvc.model.FidoConfig#getAppId()}
	 * {@link eu.recred.fidouafsvc.service.impl.RegistrationService#regReqUsername(String)}
	 * 
	 * @param username
	 * @return
	 */
	@RequestMapping(value = "/request/{username:.+}", method = RequestMethod.GET)
	public String getRequestByUsername(@PathVariable(value = "username") String username) {
		// BEGIN: FidoUafRegistrationController-getRequestByUsername
		String request;
		logger.log(Level.INFO, "***-----BEGIN REG REQUEST-----***");
		logger.log(Level.INFO, "APPID: " + config.getAppId());
		logger.log(Level.INFO, "USERNAME: " + username);
		request = gson.toJson(registrationService.regReqUsername(username), RegistrationRequest[].class);
		logger.log(Level.INFO, "REQUEST: " + request);
		logger.log(Level.INFO, "***-----END REG REQUEST-----***");

		return request;
		// END: FidoUafRegistrationController-getRequestByUsername
	}

	@RequestMapping(value = "/request/{username:.+}/{appid}", method = RequestMethod.GET)
	public RegistrationRequest[] getRequestByUsernameByAppid(@PathVariable(value = "username") String username,
			@PathVariable(value = "appid") String appid) {
		return registrationService.regReqUsernameAppId(username, appid);
	}

	// FIDOUAFREG III
	/**
	 * getResponse
	 * <p>%%% BEGIN SOURCE CODE %%%
     * {@codesnippet FidoUafRegistrationController-getResponse}
     * %%% END SOURCE CODE %%%
	 * <p>This function is initiated when registration responce endpoint is called
	 * 
	 * <p>REGres 2
	 * @see RegistrationRecord
	 * @see ServerResponse
	 * {@link eu.recred.fidouafsvc.model.FidoConfig#getAppId()}
	 * {@link eu.recred.fidouafsvc.service.impl.RegistrationService#response(String)}
	 * 
	 * @param payload
	 * @return
	 */
	@RequestMapping(value = "/response", method = RequestMethod.POST)
	public RegistrationRecord[] getResponse(@RequestBody String payload) {
		// BEGIN: FidoUafRegistrationController-getResponse
		RegistrationRecord[] records;
		ServerResponse response = new ServerResponse();
		logger.log(Level.INFO, "***-----BEGIN REG RESPONSE-----***");
		logger.log(Level.INFO, "APPID: " + config.getAppId());
		logger.log(Level.INFO, "PAYLOAD: " + payload);
		records = registrationService.response(payload);
		response.statusCode = Integer.parseInt(records[0].status);
		logger.log(Level.INFO, "RESPONSE: " + gson.toJson(records));
		logger.log(Level.INFO, "***-----END REG RESPONSE-----***");
		return records;
		// return response;
		// END: FidoUafRegistrationController-getResponse
	}

	// @RequestMapping(value = "/dereg", method = RequestMethod.POST)
	// public String getDereg(@RequestBody String payload) {
	// return deregRequestProcessorService.process(payload);
	// }

	// FIDOUAFDER I
	/**
	 * getDeregByUsername
	 * <p>%%% BEGIN SOURCE CODE %%%
     * {@codesnippet FidoUafRegistrationController-getDeregByUsername}
     * %%% END SOURCE CODE %%%
	 * <p>This function is initiated when dereistration request endpoind is called
	 * 
	 * <p>DEREGreq 1
	 * {@link eu.recred.fidouafsvc.model.FidoConfig#getAppId()}
	 * {@link eu.recred.fidouafsvc.service.impl.DeregRequestProcessorService#getRequest(String)}
	 * 
	 * @param username
	 * @return
	 */
	@RequestMapping(value = "/dereg/{username:.+}", method = RequestMethod.GET)
	public String getDeregByUsername(@PathVariable(value = "username") String username) {
		// BEGIN: FidoUafRegistrationController-getDeregByUsername
		try {
			String request;
			logger.log(Level.INFO, "***-----BEGIN DEREG REQUEST-----***");
			logger.log(Level.INFO, "APPID: " + config.getAppId());
			logger.log(Level.INFO, "USERNAME: " + username);
			request = gson.toJson(deregRequestProcessorService.getRequest(username), DeregistrationRequest[].class);
			logger.log(Level.INFO, "REQUEST: " + request);
			logger.log(Level.INFO, "***-----END DEREG REQUEST-----***");

			return request;
		} catch (Exception e) {
			return "1403";
		}
		// END: FidoUafRegistrationController-getDeregByUsername
	}
}
