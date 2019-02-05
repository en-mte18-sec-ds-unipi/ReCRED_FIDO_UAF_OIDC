package eu.recred.fidouafsvc.model;

import javax.persistence.*;

/**
 * Created by sorin.teican on 8/29/2016.
 */

/**
 * This model handles the REGISTRATIONRECORD table in the database.
 * <p>REGres
 */

@Entity
@Table(name = "REGISTRATIONRECORD")
public class RegistrationRecordModel {

	///////////////////////////////////////////////////////////////////////////////////////////////

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private int id;

	@Column(unique = true)
	private String authenticator;

	@Column(columnDefinition = "TEXT")
	private String record;

	@Column
	private String timestamp;

	///////////////////////////////////////////////////////////////////////////////////////////////

	public void setId(int id) {
		this.id = id;
	}

	public void setTimestamp(String timestamp) {
		this.timestamp = timestamp;
	}

	public String getTimestamp() {
		return timestamp;
	}

	public String getAuthenticator() {
		return authenticator;
	}

	public void setAuthenticator(String authenticator) {
		this.authenticator = authenticator;
	}

	public String getRecord() {
		return record;
	}

	public void setRecord(String record) {
		this.record = record;
	}
}
