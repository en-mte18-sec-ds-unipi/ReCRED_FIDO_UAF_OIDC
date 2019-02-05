package eu.recred.fidouafsvc.model.metadata;

/**
 * Created by sorin.teican on 20-Nov-16.
 */

/**
 * The PatternAccuracyDescriptor describes relevant accuracy/complexity 
 * aspects in the case that a pattern is used as the user verification method.
 */

public class PatternAccuracyDescriptor {
	public long minComplexity;
	public short maxRetries;
	public short blockSlowdown;
}
