public class RegistrationRequestGenerator {

	private StorageInterface _storageDao;
	private Notary _notary;

	private String _appId;

	private String _username;

	public RegistrationRequestGenerator(StorageInterface storageInterface, Notary notary, String appId, String username) {
		_storageDao = storageInterface;
		_notary = notary;

		_appId = appId;

		_username = username;
	}

	private Policy generatePolicy() {
		
	}

	private String generateServerData(String username, String challenge,
			Notary notary) {
		String dataToSign = Base64.encodeBase64URLSafeString(("" + System.currentTimeMillis()).getBytes());
		dataToSign += "." + Base64.encodeBase64URLSafeString(username.getBytes());
		dataToSign += "." + Base64.encodeBase64URLSafeString(challenge.getBytes());
		String signature = _notary.sign(dataToSign);

		return Base64.encodeBase64URLSafeString((signature + "." + dataToSign).getBytes());
	}

	private String generateChallenge() {
		return Base64.encodeBase64URLSafeString(BCrypt.gensalt().getBytes());
	}


	public RegistrationRequest generateRequest() {
		String challenge = generateChallenge();
		String serverData = generateServerData(_username, challenge, _notary);

		OperationsHeader header = new OperationsHeader();
		header.serverData = serverData;
		header.op = Operation.Reg;
		header.appId = _appId;
		header.upv = new Version(1, 0);

		RegistrationRequest request = new RegistrationRequest();
		request.header = header;
		request.challenge = generateChallenge();
		request.username = _username;
		request.policy = generatePolicy();

		return request;
	}

}