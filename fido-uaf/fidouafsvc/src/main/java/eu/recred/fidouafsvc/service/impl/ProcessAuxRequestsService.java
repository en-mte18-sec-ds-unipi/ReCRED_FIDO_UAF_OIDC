package eu.recred.fidouafsvc.service.impl;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import eu.recred.fido.uaf.msg.Version;
import eu.recred.fidouafsvc.dao.TrustedFacetDao;
import eu.recred.fidouafsvc.model.*;
import eu.recred.fidouafsvc.storage.RegistrationRecord;
import eu.recred.fidouafsvc.storage.StorageInterface;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.ApplicationContext;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.jar.Manifest;
import java.util.logging.Level;
import java.util.logging.Logger;

//import org.springframework.context.annotation.DependsOn;

@Service
public class ProcessAuxRequestsService {

	Gson gson = new Gson();

	Logger logger = Logger.getLogger(this.getClass().getSimpleName());

	public ProcessAuxRequestsService() {
		// TODO Auto-generated constructor stub
		// System.out.println("ProcessAuxRequestsService created!");
	}

	@Autowired
	private ApplicationContext applicationContext;

	@Autowired
	private TrustedFacetDao trustedFacetDao;

	@Autowired
	@Qualifier("storageDao")
	private StorageInterface storageDao;

	public String getAuthenticated(String authenticationId) {
		JsonObject response = new JsonObject();
		if (authenticationId == null || authenticationId.trim().isEmpty()) {
			response.addProperty("authenticated", false);
			return response.toString();
		}
		AuthenticationIdModel authId = storageDao.getAuthenticated(authenticationId);
		if (authId == null) {
			response.addProperty("authenticated", false);
			return response.toString();
		}
		logger.log(Level.INFO, authId.toString());
		if (authId.getUsername() != null) {
			response.addProperty("authenticated", true);
			response.addProperty("username", authId.getUsername());
			response.addProperty("timestamp", authId.getTimestamp());
		} else {
			response.addProperty("authenticated", false);
			// response.addProperty("username", "");
		}
		return response.toString();
	}

	public GetLastAuth getLastAuth(String username) {
		GetLastAuth dto = new GetLastAuth();
		dto.username_id = username;
		try {
			List<RegistrationRecord> records = storageDao.readRegistrationRecordUsername(username);
			long timestamp = Long.parseLong(records.get(0).authenticator.timestamp);
			if (records.size() == 1) {
				dto.last_auth_timestamp = records.get(0).timeStamp;
			} else {
				for (int i = 0; i > records.size(); i++) {
					long temp_timestamp = Long.parseLong(records.get(i).authenticator.timestamp);
					if (temp_timestamp > timestamp)
						timestamp = temp_timestamp;
				}
				dto.last_auth_timestamp = "" + timestamp;
			}
		} catch (Exception e) {
			e.printStackTrace();
			dto.last_auth_timestamp = "-1";
		}

		return dto;
	}

	public void logOut(String username) {
		storageDao.deleteAuthenticationIdByUsername(username);
	}

	public class GetLastAuth {
		public String username_id;
		public String last_auth_timestamp;
	}

	public Facets getFacets() {
		List<TrustedFacet> facets = trustedFacetDao.listAllTrustedFacets();
		String[] trustedIds = new String[facets.size()];

		TrustedFacets trusted = new TrustedFacets();
		trusted.version = new Version(1, 0);
		trusted.ids = trustedIds;
		for (int i = 0; i < facets.size(); i++)
			trustedIds[i] = facets.get(i).getName();
		trusted.ids = trustedIds;
		Facets trustedFacets = new Facets();
		trustedFacets.trustedFacets = new TrustedFacets[1];
		trustedFacets.trustedFacets[0] = trusted;
		return trustedFacets;
	}

	public void populateFacets() {
		trustedFacetDao.populateTrustedFacets();
	}

	public void addTrustedFacet(String facet, String description) {
		trustedFacetDao.addTrustedFacet(facet, description);
	}

	public About getAbout() throws IOException {
		Resource resManifest = applicationContext.getResource("/META-INF/MANIFEST.MF");
		InputStream streamManifest = resManifest.getInputStream();
		return new About(new Manifest(streamManifest));
	}
}
