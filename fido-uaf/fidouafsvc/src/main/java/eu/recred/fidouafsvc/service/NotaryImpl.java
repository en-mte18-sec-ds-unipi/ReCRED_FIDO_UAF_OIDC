package eu.recred.fidouafsvc.service;

/**
 * Created by georgeg on 04/07/16.
 */

/*
 * This class notarize the data.
 */

public interface NotaryImpl {
	String sign(String dataToSign);

	boolean verify(String dataToSign, String signature);
}
