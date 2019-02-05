package eu.recred.fidouafsvc.util;

import eu.recred.fido.uaf.crypto.BCrypt;
import eu.recred.fido.uaf.crypto.Notary;
import eu.recred.fido.uaf.msg.MatchCriteria;
import eu.recred.fido.uaf.msg.Policy;
import org.apache.commons.codec.binary.Base64;
import org.springframework.stereotype.Component;

import javax.imageio.ImageIO;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * Created by sorin.teican on 26-Nov-16.
 */

/*
 * This class contains additional functions that contribute to request creation.
 */

@Component
public class RequestHelper {

	/**
	 * generateChallenge
	 * <p>%%% BEGIN SOURCE CODE %%%
     * {@codesnippet RequestHelper-generateChallenge}
     * %%% END SOURCE CODE %%%
	 * <p>This function creates a challenge
	 * 
	 * <p>REGreq 1.2.1.1.1
	 * <p>AUTHreq 1.2.1.1.1
	 * 
	 * @return
	 */
	public String generateChallenge() {
		// BEGIN: RequestHelper-generateChallenge
		return Base64.encodeBase64URLSafeString(BCrypt.gensalt().getBytes());
		// END: RequestHelper-generateChallenge
	}

	/**
	 * generateServerData
	 * <p>%%% BEGIN SOURCE CODE %%%
     * {@codesnippet RequestHelper-generateServerDataAUTH}
     * %%% END SOURCE CODE %%%
	 * <p>This function generates server data
	 * 
	 * <p>AUTHreq 1.2.1.1.2
	 * 
	 * @param challenge
	 * @param notary
	 * @return
	 */
	public String generateServerData(String challenge, Notary notary) {
		// BEGIN: RequestHelper-generateServerDataAUTH
		String dataToSign = Base64.encodeBase64URLSafeString(("" + System.currentTimeMillis()).getBytes()) + "."
				+ Base64.encodeBase64URLSafeString(challenge.getBytes());
		String signature = notary.sign(dataToSign);

		return Base64.encodeBase64URLSafeString((signature + "." + dataToSign).getBytes());
		// END: RequestHelper-generateServerDataAUTH
	}

	/**
	 * generateServerData
	 * <p>%%% BEGIN SOURCE CODE %%%
     * {@codesnippet RequestHelper-generateServerData}
     * %%% END SOURCE CODE %%%
	 * <p>This function generates server data
	 * 
	 * <p>REGreq 1.2.1.1.2
	 * 
	 * @param username
	 * @param challenge
	 * @param notary
	 * @return
	 */
	public String generateServerData(String username, String challenge, Notary notary) {
		// BEGIN: RequestHelper-generateServerData
		String dataToSign = Base64.encodeBase64URLSafeString(("" + System.currentTimeMillis()).getBytes()) + "."
				+ Base64.encodeBase64URLSafeString(username.getBytes()) + "."
				+ Base64.encodeBase64URLSafeString(challenge.getBytes());
		String signature = notary.sign(dataToSign);

		return Base64.encodeBase64URLSafeString((signature + "." + dataToSign).getBytes());
		// END: RequestHelper-generateServerData
	}

	/**
	 * constructPolicy
	 * <p>%%% BEGIN SOURCE CODE %%%
     * {@codesnippet RequestHelper-constructPolicy}
     * %%% END SOURCE CODE %%%
	 * <p>This function creates the server policy
	 * 
	 * <p>REGreq 1.2.1.1.3
	 * <p>AUTHreq 1.2.1.1.3
	 * @see Policy
	 * @see MatchCriteria
	 * 
	 * @param acceptedAaids
	 * @return
	 */
	public Policy constructPolicy(String[] acceptedAaids) {
		// BEGIN: RequestHelper-constructPolicy
		if (acceptedAaids == null) {
			return null;
		}
		Policy p = new Policy();
		MatchCriteria[][] accepted = new MatchCriteria[acceptedAaids.length][1];
		for (int i = 0; i < accepted.length; i++) {
			MatchCriteria[] a = new MatchCriteria[1];
			MatchCriteria matchCriteria = new MatchCriteria();
			matchCriteria.aaid = new String[1];
			matchCriteria.aaid[0] = acceptedAaids[i];
			a[0] = matchCriteria;
			accepted[i] = a;
		}
		p.accepted = accepted;
		return p;
		// END: RequestHelper-constructPolicy
	}

	public static byte[] generateImage(String text, int width, int height) {
		Font font = new Font("Arial", Font.PLAIN, 48);

		BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);

		Graphics2D graphics2D = image.createGraphics();
		graphics2D.setFont(font);

		FontMetrics fontMetrics = graphics2D.getFontMetrics();
		int strWidth = fontMetrics.stringWidth(text);
		int strHeight = fontMetrics.getHeight();

		graphics2D.setColor(Color.WHITE);
		graphics2D.drawString(text, (width / 2) - (strWidth / 2), (height / 2) - (strHeight / 2));
		graphics2D.dispose();

		try {
			ByteArrayOutputStream os = new ByteArrayOutputStream();
			ImageIO.write(image, "png", os);
			byte[] png = os.toByteArray();
			os.close();

			return png;
		} catch (IOException e) {
			e.printStackTrace();
		}

		return null;
	}
}
