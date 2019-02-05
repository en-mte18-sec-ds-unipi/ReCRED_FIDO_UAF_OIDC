package eu.recred.fidouafsvc.controller;

import com.google.gson.Gson;
import eu.recred.fidouafsvc.service.impl.DeregRequestProcessorService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

/**
 * Created by sorin.teican on 25-Sep-17.
 */


/*
 * This controller handles deregistration requests.
 */

@RestController
@RequestMapping("/v1/recovery")
public class RecoveryController {

	private Gson gson = new Gson();

	@Autowired
	private DeregRequestProcessorService deregRequestProcessorService;

	@RequestMapping(value = "/dereg/{username:.+}", method = RequestMethod.GET)
	public String failoverDereg(@PathVariable(value = "username") String username) {
		try {
			String request = gson.toJson(deregRequestProcessorService.getFailoverRequest(username),
					DeregRequestProcessorService.DeregResponse.class);
			return request;
		} catch (Exception e) {
			return "1403";
		}
	}
}
