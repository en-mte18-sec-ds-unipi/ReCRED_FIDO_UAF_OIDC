package eu.recred.fidouafsvc.controller;

import eu.recred.fidouafsvc.model.About;
import eu.recred.fidouafsvc.service.impl.ProcessAuxRequestsService;
import eu.recred.fidouafsvc.storage.StorageInterface;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

//import javax.servlet.http.HttpServletRequest;

//import org.springframework.web.bind.annotation.PathVariable;

/*
 * This is a controller for /about endpoint.
 */

// TODO: Implement this controller as a Service
@RestController
@RequestMapping("/v1/about")
public class AboutController {

	@Autowired
	ProcessAuxRequestsService processAuxRequestsService;

	@Autowired
	private StorageInterface storageDao;

	@RequestMapping(method = RequestMethod.GET)
	public @ResponseBody About getAbout() throws IOException {
		return processAuxRequestsService.getAbout();
	}

	// @RequestMapping(value = "url",method = RequestMethod.GET)
	// public @ResponseBody String getUrl(HttpServletRequest request) throws
	// IOException {
	// String url = request.getRequestURI().toString();
	// String[] parts = url.split("/");
	// if (parts.length > 0)
	// url = parts[1];
	// return url;
	// }
}
