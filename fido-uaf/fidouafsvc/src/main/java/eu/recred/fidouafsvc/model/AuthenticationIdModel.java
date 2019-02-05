package eu.recred.fidouafsvc.model;

import javax.persistence.*;

/**
 * Created by sorin.teican on 8/29/2016.
 */

/**
 * This model handles the AUTHENTICATIONID table in the database.
 */

@Entity
@Table(name = "AUTHENTICATIONID")
public class AuthenticationIdModel {

	///////////////////////////////////////////////////////////////////////////////////////////////

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private int id;

	@Column(unique = true)
	private String authenticationId;

	@Column
	private String username;

	@Column
	private String timestamp;

	///////////////////////////////////////////////////////////////////////////////////////////////

	public void setId(int id) {
		this.id = id;
	}

	public String getAuthenticationId() {
		return authenticationId;
	}

	public void setAuthenticationId(String authenticationId) {
		this.authenticationId = authenticationId;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getTimestamp() {
		return timestamp;
	}

	public void setTimestamp(String timestamp) {
		this.timestamp = timestamp;
	}
}
