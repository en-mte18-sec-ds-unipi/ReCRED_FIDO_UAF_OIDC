package eu.recred.fidouafsvc.controller;

import eu.recred.fidouafsvc.model.Facets;
import eu.recred.fidouafsvc.service.impl.ProcessAuxRequestsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.logging.Logger;

/**
 * Created by georgeg on 01.07.2016.
 */

/*
 * This controller handles the parameters of each request.
 */

@RestController
@RequestMapping("/v1")
public class FidoUafController {
	static Logger logger = Logger.getLogger(FidoUafController.class.getName());

	@Autowired
	private ProcessAuxRequestsService processAuxRequests;

	@RequestMapping(value = "/stats", method = RequestMethod.GET)
	public String getStats() {
		return "";
	}

	@RequestMapping(value = "/trustedfacets", method = RequestMethod.GET, produces = "application/fido.trusted-apps+json")
	public Facets getTrustedFacets() {
		return processAuxRequests.getFacets();
	}

	@RequestMapping(value = "/populatetrustedfacets", method = RequestMethod.GET)
	public void populateTrustedFacets() {
		processAuxRequests.populateFacets();
	}

	@RequestMapping(value = "/registerfacet/{facet:.+}/{description:.+}", method = RequestMethod.GET)
	public void registerFacet(@PathVariable(value = "facet") String facet,
			@PathVariable(value = "description") String description) {
		processAuxRequests.addTrustedFacet(facet, description);
	}

	@RequestMapping(value = "/isauth/{auth}", method = RequestMethod.GET)
	public String getAuthenticated(@PathVariable(value = "auth") String authenticationId) {
		return processAuxRequests.getAuthenticated(authenticationId);
	}

	@RequestMapping(value = "/lastauth/{username:.+}", method = RequestMethod.GET)
	public ProcessAuxRequestsService.GetLastAuth getLastAuth(@PathVariable(value = "username") String username) {
		return processAuxRequests.getLastAuth(username);
	}

	@RequestMapping(value = "/logout/{username:.+}", method = RequestMethod.GET)
	public void logout(@PathVariable(value = "username") String username) {
		processAuxRequests.logOut(username);
	}

	@ExceptionHandler(Exception.class)
	@ResponseStatus(HttpStatus.BAD_REQUEST)
	public String handleExecption(Exception e) {
		return e.getMessage();
	}

}
