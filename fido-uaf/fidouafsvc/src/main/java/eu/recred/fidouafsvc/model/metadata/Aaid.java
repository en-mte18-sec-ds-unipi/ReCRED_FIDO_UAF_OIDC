package eu.recred.fidouafsvc.model.metadata;

import javax.persistence.*;

/**
 * Created by sorin.teican on 29-May-17.
 */

/**
 * This model handles the AAID table in the database.
 */

@Entity
@Table(name = "AAID")
public class Aaid {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private int id;

	@Column(name = "NAME", unique = true)
	private String name;

	public int getId() {
		return id;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}
}
