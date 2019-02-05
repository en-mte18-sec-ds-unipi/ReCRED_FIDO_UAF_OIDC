package eu.recred.fidouafsvc.model.metadata;

/**
 * Created by sorin.teican on 20-Nov-16.
 */

/**
 * The CodeAccuracyDescriptor describes the relevant accuracy/complexity 
 * aspects of passcode user verification methods.
 */

public class CodeAccuracyDescriptor {
	public short base;
	public short minLength;
	public short maxRetries;
	public short blockSlowdown;
}
