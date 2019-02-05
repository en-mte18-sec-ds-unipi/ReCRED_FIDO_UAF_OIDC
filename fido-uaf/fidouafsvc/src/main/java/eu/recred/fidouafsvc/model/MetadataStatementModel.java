package eu.recred.fidouafsvc.model;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

/**
 * This model handles the METADATASTATEMENT table in the database.
 */

@Entity
@Table(name = "METADATASTATEMENT")
public class MetadataStatementModel {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private int id;

	@Column(name = "AAID", unique = true)
	private String aaid;

	@Column(name = "STATEMENT", columnDefinition = "TEXT")
	private String statement;

	public void setId(int id) {
		this.id = id;
	}

	public String getAaid() {
		return aaid;
	}

	public void setAaid(String aaid) {
		this.aaid = aaid;
	}

	public String getStatement() {
		return statement;
	}

	public void setStatement(String statement) {
		this.statement = statement;
	}
}
