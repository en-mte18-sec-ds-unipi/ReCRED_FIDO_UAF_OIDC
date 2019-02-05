public class RequestAccountant {
	private List<RegistrationRequest> _registrations;
	private List<AuthenticationRequest> _authentications;

	private static RegistrationsAccountant _instance = null;

	public static RegistrationsAccountant getInstance() {
		if (_instance == null)
			_instance = new RegistrationsAccountant();

		return _instance;
	}

	public void addRegistrationRequest(RegistrationRequest request) {
		_registrations.add(request);
	}

	public void addAuthenticationRequest(AuthenticationRequest request) {
		_authentications.add(request);
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

	private RegistrationsAccountant() {
		_registrations = new ArrayList<>();
		_authentications = new ArrayList<>();
	}
}