package eu.recred.fidouafsvc.model.metadata;

/**
 * Created by sorin.teican on 20-Nov-16.
 */

/**
 * The BiometricAccuracyDescriptor describes relevant accuracy/complexity 
 * aspects in the case of a biometric user verification method.
 */

public class BiometricAccuracyDescriptor {
	public double FAR;
	public double FRR;
	public double EER;
	public double FAAR;
	public short maxReferenceDataSets;
}
