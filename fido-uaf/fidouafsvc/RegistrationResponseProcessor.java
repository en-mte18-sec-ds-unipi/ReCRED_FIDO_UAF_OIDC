public class RegistrationResponseProcessor {

	private Notary _notary;
	private RequestAccountant _requestAccountant;

	private MetadataStatementDao _metadataStatementDao;

	private List<TrustedFacet> _trustedFacets;

	private Gson _gson;

	private String _appId;

	private RegistrationRequest _registrationRequest;

	public RegistrationResponseProcessor(Notary notary, RequestAccountant accountant,
			 List<TrustedFacet> trustedFacets, String appId, MetadataStatementDao metadataStatementDao) {
		_notary = notary;
		_requestAccountant = accountant;

		_metadataStatementDao = metadataStatementDao;

		_trustedFacets = trustedFacets;

		_gson = new Gson();

		_appId = appId;
	}
	
	public List<RegistrationRecord> processResponse(RegistrationResponse response) {
		// Check version.
		if (response.header.upv.major != 1 || response.header.upv.minor != 0)
			//

		checkServerData(response.header.serverData);
		checkFcp(response.fcParams);

		List<RegistrationRecord> registrationRecords = new ArrayList<>();

		for (AuthenticatorRegistrationAssertion assertion : response.assertions) {
			if (!assertion.assertionScheme.equals("UAFV1TLV"))
				continue;
			TlvAssertionParser parser = new TlvAssertionParser();
			Tags tags = parser.parse(assertion.assertion);

			if (!checkTLVMandatoryFields(tags))
				continue;

			// retrieve aaid from assertion.
			String aaid = new String(tags.getTags().get(TagsEnum.TAG_AAID.id).value);

			// retrieve metadata statement
			MetadataStatement metadataStatement = _metadataStatementDao.getStatement(aaid);
			if (metadataStatement == null)
				continue;
			if (!metadataStatement.assertionScheme.equals(assertion.assertionScheme))
				continue;

			// verify that the AAID matches the policy specified in the request.
			boolean found = false;
			for (MatchCriteria[] criterias : _registrationRequest.policy.allowed) {
				for (MatchCriteria criteria : criterias) {
					for (String _aaid : criteria.aaid) {
						if (_aaid.equals(aaid)) {
							found = true;
							break;
						}
						if (found)
							break;
					}
					if (found)
						break;
				}
				if (found)
					break;
			}
			if (!found)
				continue;

			String FCHash = SHA.sha256(response.fcParams);

			// check authenticator attestation type. ATTESTATION BASIC FULL ALREADY CHECKED.
			found = false;
			for (int attestationType : metadataStatement.attestationTypes) {
				if (attestationType == 15879) {
					found = true;
					break;
				}
			}
			if (!found)
				continue;


			if (!FCHash.equals(new String(tags.getTags().get(TagsEnum.TAG_FINAL_CHALLANGE.id).value)))
				continue;

			// check authenticator version.
			byte[] _version = Arrays.copyOfRange(tags.getTags().get(TagsEnum.TAG_ASSERTION_INFO.id).value, 0, 2);
			if (metadataStatement.authenticatorVersion > UnsignedUtil.read_UAFV1_UINT16(new ByteInputStream(_version)))
				continue;

			// check reg counter.
			byte[] _regCounter = Arrays.copyOfRange(tags.getTags().get(TagsEnum.TAG_COUNTERS.id).value, 0, 5);
			byte[] _signCounter = Arrays.copyOfRange(tags.getTags().get(TagsEnum.TAG_COUNTERS.id).value, 5, tags.getTags().get(TagsEnum.TAG_COUNTERS.id).value.length);

			// verify attestation certificate chain.
			boolean verified = false;
			if (metadataStatement.attestationRootCertificates.length > 0) {
				byte[] derAttestationCertificate = tags.getTags().get(TagsEnum.TAG_ATTESTATION_CERT.id).value;
				for (int i = 0; i < metadataStatement.attestationRootCertificates.length; i++) {
					if (i == 0) {
						verified = verifyAttestationCert(loadCertificate(derAttestationCertificate), loadCertificate(metadataStatement.attestationRootCertificates[i]));
						if (!verified)
							break;
					} else {
						verified = verifyAttestationCert(loadCertificate(metadataStatement.attestationRootCertificates[i - 1]),
							 loadCertificate(metadataStatement.attestationRootCertificates[i]));
						if (!verified)
							break;
					}
				}
			} else continue;
			if (!verified)
				continue;

			if (!validateSignature(tags))
				continue;

			AuthenticatorRecord authenticatorRecord = new AuthenticatorRecord();
			authenticatorRecord.AAID = new String(tags.getTags().get(TagsEnum.TAG_AAID.id).value);
			authenticatorRecord.KeyID = Base64.encodeBase64URLSafeString(tags.getTags().get(TagsEnum.TAG_KEYID.id).value);

			RegistrationRecord registrationRecord = new RegistrationRecord();
			registrationRecord.authenticator = authenticatorRecord;
			registrationRecord.PublicKey = Base64.encodeBase64URLSafeString(tags.getTags().get(TagsEnum.TAG_PUB_KEY.id).value);
			registrationRecord.username = _registrationRequest.username;
			registrationRecord.SignCounter = "" + ByteBuffer.wrap(_signCounter).getInt();
			registrationRecord.tcDisplayPNGCharacteristics = _gson.toJson(metadataStatement.tcDisplayPNGCharacteristics);

			registrationRecords.add(registrationRecord);
		}
	}

	private void checkServerData(String serverDataB64) {
		getRegistrationRequest(serverDataB64);

		if (_registrationRequest == null)
			//

		String serverData = new String(Base64.decodeBase64(serverDataB64));
		String[] tokens = serverData.split("\\.");
		String signature, timeStamp, username, challenge, dataToSign;
		try {
			signature = tokens[0];
			timeStamp = tokens[1];
			username = tokens[2];
			challenge = tokens[3];
			dataToSign = timeStamp + "." + username + "." + challenge;
			if (!_snotary.verify(dataToSign, signature)) {
				throw new ServerDataSignatureNotMatchException();
			}
			if (isExpired(timeStamp)) {
				throw new ServerDataExpiredException();
			}
			//setUsernameAndTimeStamp(username, timeStamp, records);
		} catch (ServerDataExpiredException e) {
			setErrorStatus(records, "1491");
			//throw new Exception("Invalid server data - Expired data");
		} catch (ServerDataSignatureNotMatchException e) {
			setErrorStatus(records, "1491");
			//throw new Exception("Invalid server data - Signature not match");
		} catch (Exception e) {
			setErrorStatus(records, "1491");
			//throw new Exception("Server data check failed");
		}
	}

	private void getRegistrationRequest(String serverData) {
		_registrationRequest = _requestAccountant.getRegistrationRequest(serverData);
	}

	private void checkFcp(FinalChallengeParams fcp) {
		if (!fcp.appId.equals(_appId))
			//
		if (!_registrationRequest.challenge.equals(fcp.challenge))
			//

		boolean foundFacet = false;
		for (TrustedFacet facet : _trustedFacets) {
			if (facet.getName().equals(fcp.facetID)) {
				foundFacet = true;
				break;
			}
		}
		if (!foundFacet)
			//

		// check channelBinding.
	}

	private FinalChallengeParams checkFcp(Sring fcParams) {
		String fcp = new String(Base64.decodeBase64(fcParams.getBytes()));
		checkFcp(_gson.fromJson(fcp, FinalChallengeParams.class));
	}

	private boolean checkTLVMandatoryFields(Tags tags) {
	    if (!tags.getTags().containsKey(TagsEnum.TAG_UAFV1_REG_ASSERTION.id))
	      return false;
	    if (!tags.getTags().containsKey(TagsEnum.TAG_UAFV1_KRD.id))
	      return false;
	    if (!tags.getTags().containsKey(TagsEnum.TAG_AAID.id))
	      return false;
	    if (!tags.getTags().containsKey(TagsEnum.TAG_ASSERTION_INFO.id))
	      return false;
	    if (!tags.getTags().containsKey(TagsEnum.TAG_FINAL_CHALLANGE.id))
	      return false;
	    if (!tags.getTags().containsKey(TagsEnum.TAG_KEYID.id))
	      return false;
	    if (!tags.getTags().containsKey(TagsEnum.TAG_COUNTERS.id))
	      return false;
	    if (!tags.getTags().containsKey(TagsEnum.TAG_PUB_KEY.id))
	      return false;
	    if (!tags.getTags().containsKey(TagsEnum.TAG_ATTESTATION_BASIC_FULL.id))
	      return false;
	    if (!tags.getTags().containsKey(TagsEnum.TAG_SIGNATURE.id))
	      return false;
	    if (!tags.getTags().containsKey(TagsEnum.TAG_ATTESTATION_CERT.id))
	      return false;

	    return true;
	}

  private X509Certificate loadCertificate(byte[] der) {
      CerficateFactory cf = CerficateFactory.getInstance("X.509");
      ByteArrayInputStream bis = new ByteArrayInputStream(der);
      X509Certificate cert = (X509Certificate)cf.generate(bis);
      bizs.close;
      return cert;
  }

  private X509Certificate loadCertificate(String b64Der) {
  	  CerficateFactory cf = CerficateFactory.getInstance("X.509");
      ByteArrayInputStream bis = new ByteArrayInputStream(Base64.decodeBase64(b64Der));
      X509Certificate cert = (X509Certificate)cf.generate(bis);
      bis.close;
      return cert;
  }

  private boolean verifyAttestationCert(X509Certificate attestationCert, X509Certificate attestationRootCert) {
      try {
          attestationCert.checkValidity();
      } catch (Exception e) {
          return false;
      }
      if (attestationCert.getIssuerDN().equals(attestationRootCert.getSubjectDN())) {
          try {
          	attestationCert.verify(attestationRootCert.getPublicKey());
          } catch (Exception e) {
          	return false;
          }
      } else {
      	return false;
      }

      return true;
  }

  private boolean validateSignature(Tags tags) {
  	byte[] certBytes = tags.getTags().get(TagsEnum.TAG_ATTESTATION_CERT.id).value;
  	Tag krd = tags.getTags().get(TagsEnum.TAG_UAFV1_KRD.id);
	Tag signature = tags.getTags().get(TagsEnum.TAG_SIGNATURE.id);

	byte[] signedBytes = new byte[krd.value.length + 4];
	System.arraycopy(UnsignedUtil.encodeInt(krd.id), 0, signedBytes, 0, 2);
	System.arraycopy(UnsignedUtil.encodeInt(krd.length), 0, signedBytes, 2,
			2);
	System.arraycopy(krd.value, 0, signedBytes, 4, krd.value.length);

	return _certificateValidator.validate(certBytes, signedBytes, signature.value);
  }
}