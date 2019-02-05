package eu.recred.fidouafsvc.model;

import eu.recred.fidouafsvc.dao.AaidDao;
import eu.recred.fidouafsvc.model.metadata.Aaid;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by georgeg on 02/07/16.
 */

/**
 * This class contains configuration for the FIDO Server.
 * <p>REGreq
 * <p>REGres
 * <p>AUTHreq
 * <p>AUTHres
 */

public class FidoConfig {

	@Autowired
	AaidDao aaidDao;

	private String baseUri = "https://192.168.1.12:8080";
	private String oidcUri = "http://snf-5504.ok-kno.grnetcloud.net:8080/oidc/fidouaf";
	private String appId = baseUri + "/fido_fo/v1/trustedfacets";
	private static String[] _aaids = null;
	// private String[] aaids = { "EBA0#0001", "FFFF#0001", "FFFF#0002",
	// "FFFF#0003", "FFFF#0004",
	// "FFFF#0005", "FFFF#0006", "FFFF#0007", "FFFF#0008", "FFFF#0009", "FFFF#0010",
	// "FFFF#0011",
	// "FFFF#0012", "FFFF#0013", "FFFF#0014", "FFFF#0015", "FFFF#0016", "FFFF#0017",
	// "FFFF#5201",
	// "0047#0001", "0044#0001", "0044#0014", "096E#0004", "0046#0001", "0046#1001",
	// "003D#1111",
	// "0049#0101", "0049#0201", "0019#1005", "0019#1009", "0043#0003", "8086#5002",
	// "8086#5006",
	// "8086#5016", "004B#0001", "001f#0002", "0048#0020" };

	/**
	 * getAppId
	 * <p>%%% BEGIN SOURCE CODE %%%
     * {@codesnippet FidoConfig-getAppId}
     * %%% END SOURCE CODE %%%
	 * <p>This funtion returns the appID
	 * 
	 * <p>REGreq 1.1
	 * <p>REGres 2.1
	 * <p>AUTHreq 1.1
	 * <p>AUTHres 2.1
	 * <p>DEREGreq 1.1
	 * 
	 * @return
	 */
	public String getAppId() {
		// BEGIN: FidoConfig-getAppId
		return appId;
		// END: FidoConfig-getAppId
	}

	public String getOidcUri() {
		return oidcUri;
	}

	public String[] getAaids() {
		if (_aaids == null) {
			List<String> aaids = new ArrayList<>();

			List<Aaid> retrievedAaids = aaidDao.listAllTrustedFacets();
			for (Aaid aaid : retrievedAaids)
				aaids.add(aaid.getName());

			_aaids = new String[retrievedAaids.size()];
			_aaids = aaids.toArray(_aaids);
		}

		return _aaids;
	}

}
