package eu.recred.fidouafsvc.dto;

import eu.recred.fido.uaf.msg.OperationHeader;

/**
 * Created by sorin.teican on 16-Nov-16.
 */

/**
 * This class contains a list with authenticators that are
 * are going to be Deregistered.
 */

public class DeregistrationRequest {
	public OperationHeader header;
	public Authenticator[] authenticators;
}
