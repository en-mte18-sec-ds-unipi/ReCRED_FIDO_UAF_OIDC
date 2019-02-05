public class AuthenticationResponseProcessor {
	private Notary _notary;
	private RequestAccountant _requestAccountant;

	private StorageInterface _storageDao;

	private MetadataStatementDao _metadataStatementDao;

	private List<TrustedFacet> _trustedFacets;

	private Gson _gson;

	private String _appId;

	private RegistrationRequest _authenticationRequest;

	public AuthenticationResponseProcessor(Notary notary, RequestAccountant accountant,
			 List<TrustedFacet> trustedFacets, String appId,
			 MetadataStatementDao metadataStatementDao, StorageInterface storageDao) {
		_notary = notary;
		_requestAccountant = accountant;

		_storageDao = storageDao;

		_metadataStatementDao = metadataStatementDao;

		_trustedFacets = trustedFacets;

		_gson = new Gson();

		_appId = appId;
	}

	public void processResponse(AuthenticationResponse respone) {
		if (response.header.upv.major != 1 || response.header.upv.minor != 0)
			//

		checkServerData(response.header.serverData);
		checkFcp(response.fcParams);

		for (AuthenticatorSignAssertion assertion : response.assertions) {
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

			// check authenticator version.
			byte[] _version = Arrays.copyOfRange(tags.getTags().get(TagsEnum.TAG_ASSERTION_INFO.id).value, 0, 2);
			if (metadataStatement.authenticatorVersion > UnsignedUtil.read_UAFV1_UINT16(new ByteInputStream(_version)))
				continue;

			// Retrieve KeyID from assertion.
			String keyID = Base64.encodeBase64URLSafeString(tags.getTags().get(TagsEnum.TAG_KEYID.id).value);

			// Retrieve public key from storage.
			AuthenticatorRecord authRecord = new AuthenticatorRecord();
			authRecord.AAID = aaid;
			authRecord.KeyID = keyID;

			RegistrationRecord regRecord = _storageDao.readRegistrationRecord(authRecord.toString());
			String pubKey = regRecord.PublicKey;

			// verify AAID with the stored one.
			if (!regRecord.authenticator.AAID.equals(aaid))
				continue;

			// retrieve authentication algorithm.
			short authAlg = metadataStatement.authenticationAlgorithm;

			// check sign counter.
			int signCounter = ByteBuffer.wrap(tags.getTags().get(TagsEnum.TAG_COUNTERS.id).value).getInt();
			int recordSingCounter = Integer.parseInt(regRecord.SignCounter);
			if (signCounter == 0 && recordSingCounter == 0) {
				// all good.
			} else if (recordSingCounter < signCounter) {
				// all good.
			} else {
				// cloned authenticator.
				continue;
			}

			// check fcParams.
			String FCHash = SHA.sha256(response.fcParams);
			if (!FCHash.equals(new String(tags.getTags().get(TagsEnum.TAG_FINAL_CHALLANGE.id).value)))
				continue;

			// check if transaction.
			// if (tags.getTags().get(TagsEnum.TAG_ASSERTION_INFO.id).value[2] == 2) {
			// 	byte[] transactionHash = tags.getTags().get(TagsEnum.TAG_TRANSACTION_CONTENT_HASH.id).value;
			// 	found = false;
			// 	for (Transaction trx : _authenticationRequest.transaction) {
			// 		byte[] 
			// 	}
			// }
			
		}
	}

	private void checkServerData(String serverDataB64) {
		getAuthenticationRequest(serverDataB64);

		if (_authenticationRequest == null)
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

	private void getAuthenticationRequest(String serverData) {
		_authenticationRequest = _requestAccountant.getAuthenticationRequest(serverData);
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
	    if (!tags.getTags().containsKey(TagsEnum.TAG_UAFV1_AUTH_ASSERTION.id))
	      return false;
	    if (!tags.getTags().containsKey(TagsEnum.TAG_UAFV1_SIGNED_DATA.id))
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
	    if (!tags.getTags().containsKey(TagsEnum.TAG_SIGNATURE.id))
	      return false;
	    if (!tags.getTags().containsKey(TagsEnum.TAG_ATHENTICATOR_NONCE.id))
	      return false;
	    if (!tags.getTags().containsKey(TagsEnum.TAG_TRANSACTION_CONTENT_HASH.id))
	      return false;

	    return true;
	}

	private boolean verifySignature(Tag signedData, Tag signature,
			String pubKey, AlgAndEncodingEnum algAndEncoding)
			throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchProviderException, SignatureException,
			UnsupportedEncodingException, Exception {

		byte[] dataForSigning = getDataForSigning(signedData);

		logger.info(" : pub 		   : " + pubKey);
		logger.info(" : dataForSigning : "
				+ Base64.encodeBase64URLSafeString(dataForSigning));
		logger.info(" : signature 	   : "
				+ Base64.encodeBase64URLSafeString(signature.value));

		byte[] decodeBase64 = Base64.decodeBase64(pubKey);
		if(algAndEncoding == AlgAndEncodingEnum.UAF_ALG_SIGN_RSASSA_PSS_SHA256_RAW) {
			PublicKey publicKey = KeyCodec.getRSAPublicKey(decodeBase64);
			return RSA.verifyPSS(publicKey, 
					SHA.sha(dataForSigning, "SHA-256"), 
					signature.value);
		} else if(algAndEncoding == AlgAndEncodingEnum.UAF_ALG_SIGN_RSASSA_PSS_SHA256_DER) {
			PublicKey publicKey = KeyCodec.getRSAPublicKey(new DEROctetString(decodeBase64).getOctets());
			return RSA.verifyPSS(publicKey, 
					SHA.sha(dataForSigning, "SHA-256"), 
					new DEROctetString(signature.value).getOctets());
		} else {
			if (algAndEncoding == AlgAndEncodingEnum.UAF_ALG_SIGN_SECP256K1_ECDSA_SHA256_DER) {
				ECPublicKey decodedPub = (ECPublicKey) KeyCodec.getPubKeyFromCurve(
						decodeBase64, "secp256k1");
				return NamedCurve.verifyUsingSecp256k1(
						KeyCodec.getKeyAsRawBytes(decodedPub),
						SHA.sha(dataForSigning, "SHA-256"),
						Asn1.decodeToBigIntegerArray(signature.value));
			}
			if (algAndEncoding == AlgAndEncodingEnum.UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_DER) {
				if (decodeBase64.length>65){
					return NamedCurve.verify(KeyCodec.getKeyAsRawBytes(pubKey),
							SHA.sha(dataForSigning, "SHA-256"),
							Asn1.decodeToBigIntegerArray(signature.value));
				} else {
					ECPublicKey decodedPub = (ECPublicKey) KeyCodec.getPubKeyFromCurve(
							decodeBase64, "secp256r1");
					return NamedCurve.verify(KeyCodec.getKeyAsRawBytes(decodedPub),
								SHA.sha(dataForSigning, "SHA-256"),
								Asn1.decodeToBigIntegerArray(signature.value));
				}
			}
			if (signature.value.length == 64) {
				ECPublicKey decodedPub = (ECPublicKey) KeyCodec.getPubKeyFromCurve(
						decodeBase64, "secp256r1");
				return NamedCurve.verify(KeyCodec.getKeyAsRawBytes(decodedPub),
						SHA.sha(dataForSigning, "SHA-256"),
						Asn1.transformRawSignature(signature.value));
			} else if (65 == decodeBase64.length
					&& AlgAndEncodingEnum.UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_DER == algAndEncoding) {
				ECPublicKey decodedPub = (ECPublicKey) KeyCodec.getPubKeyFromCurve(
						decodeBase64, "secp256r1");
				return NamedCurve.verify(KeyCodec.getKeyAsRawBytes(decodedPub),
						SHA.sha(dataForSigning, "SHA-256"),
						Asn1.decodeToBigIntegerArray(signature.value));
			} else {
				return NamedCurve.verify(KeyCodec.getKeyAsRawBytes(pubKey),
						SHA.sha(dataForSigning, "SHA-256"),
						Asn1.decodeToBigIntegerArray(signature.value));
			}
		}
	}
}