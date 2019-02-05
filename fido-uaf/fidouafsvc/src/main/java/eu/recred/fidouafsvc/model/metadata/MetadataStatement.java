package eu.recred.fidouafsvc.model.metadata;

import eu.recred.fido.uaf.msg.DisplayPNGCharacteristicsDescriptor;

/**
 * Created by sorin.teican on 20-Nov-16.
 */

/**
 * This section is normative. This model contains information for MetadataStatements.
 */

public class MetadataStatement {
	public String aaid;
	public String description;
	public short authenticatorVersion;
	public Version[] upv;
	public String assertionScheme;
	public short authenticationAlgorithm;
	public short publicKeyAlgAndEncoding;
	public short[] attestationTypes;
	public VerificationMethodDescriptor[][] userVerificationDetails;
	public short keyProtection;
	public short matcherProtection;
	public long attachmentHint;
	public boolean isSecondFactoryOnly;
	public short tcDisplay;
	public String tcDisplayContentType;
	public DisplayPNGCharacteristicsDescriptor[] tcDisplayPNGCharacteristics;
	public String[] attestationRootCertificates;
	public String icon;
}
