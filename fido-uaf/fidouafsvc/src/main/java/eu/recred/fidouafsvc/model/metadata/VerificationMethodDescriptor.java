package eu.recred.fidouafsvc.model.metadata;

/**
 * Created by sorin.teican on 20-Nov-16.
 */

/**
 * A descriptor for a specific base user verification method as implemented 
 * by the authenticator. A base user verification method must be chosen 
 * from the list of those described in FIDORegistry.
 */

public class VerificationMethodDescriptor {
	public long userVerification;
	public CodeAccuracyDescriptor caDesc;
	public BiometricAccuracyDescriptor baDesc;
	public PatternAccuracyDescriptor paDesc;
}
