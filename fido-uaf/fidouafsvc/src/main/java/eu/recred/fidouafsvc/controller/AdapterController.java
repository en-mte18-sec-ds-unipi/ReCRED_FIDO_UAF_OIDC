package eu.recred.fidouafsvc.controller;

import com.google.gson.Gson;
import eu.recred.fido.uaf.msg.DeregistrationRequest;
import eu.recred.fido.uaf.msg.RegistrationRequest;
import eu.recred.fidouafsvc.dto.adapter.*;
import eu.recred.fidouafsvc.model.FidoConfig;
import eu.recred.fidouafsvc.service.impl.AuthenticationService;
import eu.recred.fidouafsvc.service.impl.DeregRequestProcessorService;
import eu.recred.fidouafsvc.service.impl.RegistrationService;
import eu.recred.fidouafsvc.storage.AuthenticatorRecord;
import eu.recred.fidouafsvc.storage.RegistrationRecord;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by sorin.teican on 06-Dec-16.
 */

/*
 * This controller creates HTTP responses.
 */

@RestController
public class AdapterController {

	private FidoConfig config = new FidoConfig();

	private Logger logger = Logger.getLogger(this.getClass().getName());

	private Gson gson = new Gson();

	@Autowired
	private RegistrationService registrationService;

	@Autowired
	private AuthenticationService authenticationService;

	@Autowired
	private DeregRequestProcessorService deregRequestProcessorService;

	@RequestMapping(value = "/Get", method = RequestMethod.POST, headers = {
			"content-type=application/fido+uaf; charset=utf-8,application/json;charset=UTF-8" }, produces = "application/fido+uaf; charset=utf-8")
	public @ResponseBody String getRequest(@RequestBody String payload) {
		ReturnUAFRequest response = new ReturnUAFRequest();

		GetRequest request = gson.fromJson(payload, GetRequest.class);

		try {

			switch (request.op) {
			case "Reg":
				logger.log(Level.INFO, "***-----BEGIN REG REQUEST-----***");
				logger.log(Level.INFO, "APPID: " + config.getAppId());
				logger.log(Level.INFO, "USERNAME: " + request.context.userName);
				response.uafRequest = gson.toJson(registrationService.regReqUsername(request.context.userName),
						RegistrationRequest[].class);
				logger.log(Level.INFO, "REQUEST: " + response.uafRequest);
				// logger.log(Level.INFO, "ADAPTER RESPONSE: ", gson.toJson(response));
				logger.log(Level.INFO, "***-----END REG REQUEST-----***\n\n\n\n");
				break;
			case "Auth":
				if (request.context == null || request.context.transaction == null
						|| request.context.transaction.isEmpty()) {
					logger.log(Level.INFO, "***-----BEGIN AUTH REQUEST-----***");
					logger.log(Level.INFO, "APPID: " + config.getAppId());
					response.uafRequest = gson.toJson(authenticationService.getAuthReqObj());
					logger.log(Level.INFO, "REQUEST: " + response.uafRequest);
					// logger.log(Level.INFO, "ADAPTER RESPONSE: ", gson.toJson(response));
					logger.log(Level.INFO, "***-----END AUTH REQUEST-----***\n\n\n\n");
				} else {
					logger.log(Level.INFO, "***-----BEGIN AUTH REQUEST-----***");
					logger.log(Level.INFO, "APPID: " + config.getAppId());
					logger.log(Level.INFO, "USERNAME: " + request.context.userName);
					logger.log(Level.INFO, "TRXCONTENT: " + request.context.transaction);
					response.uafRequest = gson.toJson(authenticationService.getAuthReqObjTrx(request.context.userName,
							request.context.transaction));
					logger.log(Level.INFO, "REQUEST: " + response.uafRequest);
					// logger.log(Level.INFO, "ADAPTER RESPONSE: ", gson.toJson(response));
					logger.log(Level.INFO, "***-----END AUTH REQUEST-----***\n\n\n\n");
				}
				break;
			case "Dereg":
				logger.log(Level.INFO, "***-----BEGIN DEREG REQUEST-----***");
				logger.log(Level.INFO, "APPID: " + config.getAppId());
				logger.log(Level.INFO, "USERNAME: " + request.context.userName);
				response.uafRequest = gson.toJson(deregRequestProcessorService.getRequest(request.context.userName),
						DeregistrationRequest[].class);
				logger.log(Level.INFO, "REQUEST: " + response.uafRequest);
				// logger.log(Level.INFO, "ADAPTER RESPONSE: ", gson.toJson(response));
				logger.log(Level.INFO, "***-----END DEREG REQUEST-----***\n\n\n\n");
				break;
			default:
				break;
			}
			// logger.log(Level.INFO, "ADAPTER RESPONSE: ", gson.toJson(response));
			response.statusCode = 1200;
		} catch (Exception e) {
			response.statusCode = 1403;
			response.uafRequest = null;
		}
		return gson.toJson(response);
	}

	@RequestMapping(value = "/Send/Reg", method = RequestMethod.POST, headers = {
			"content-type=application/fido+uaf; charset=utf-8,application/json;charset=UTF-8" }, produces = "application/fido+uaf; charset=utf-8")
	public @ResponseBody String sendRegResponse(@RequestBody String payload) {
		SendResponse response = new SendResponse();

		SendRequest request = gson.fromJson(payload, SendRequest.class);
		logger.log(Level.INFO, "***-----BEGIN REG RESPONSE-----***");
		logger.log(Level.INFO, "APPID: " + config.getAppId());
		logger.log(Level.INFO, "PAYLOAD: " + request.uafResponse);
		RegistrationRecord[] records = registrationService.response(request.uafResponse);
		logger.log(Level.INFO, "RESPONSE: " + gson.toJson(records));
		// logger.log(Level.INFO, "ADAPTER RESPONSE: ", gson.toJson(response));
		logger.log(Level.INFO, "***-----END REG RESPONSE-----***\n\n\n\n");

		response.statusCode = Integer.parseInt(records[0].status);
		// logger.log(Level.INFO, "ADAPTER RESPONSE: ", gson.toJson(response));
		return gson.toJson(response);
	}

	@RequestMapping(value = "/Send/Auth", method = RequestMethod.POST, headers = {
			"content-type=application/fido+uaf; charset=utf-8,application/json;charset=UTF-8" }, produces = "application/fido+uaf; charset=utf-8")
	public @ResponseBody String sendAuthResponse(@RequestBody String payload) {
		SendResponse response = new SendResponse();

		SendRequest request = gson.fromJson(payload, SendRequest.class);
		logger.log(Level.INFO, "***-----BEGIN AUTH RESPONSE-----***");
		logger.log(Level.INFO, "APPID: " + config.getAppId());
		logger.log(Level.INFO, "PAYLOAD: " + request.uafResponse);
		AuthenticatorRecord[] records = authenticationService.response(request.uafResponse);
		logger.log(Level.INFO, "RESPONSE: " + gson.toJson(records));
		// logger.log(Level.INFO, "ADAPTER RESPONSE: ", gson.toJson(response));
		logger.log(Level.INFO, "***-----END AUTH RESPONSE-----***\n\n\n\n");

		response.statusCode = Integer.parseInt(records[0].status);
		// logger.log(Level.INFO, "ADAPTER RESPONSE: ", gson.toJson(response));
		return gson.toJson(response);
	}
}
