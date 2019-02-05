package eu.recred.fidouafsvc.util;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.logging.Logger;

/**
 * Created by sorin.teican on 19-Feb-18.
 */

/*
 * This class connects to a radius database and inserts a user.
 */
public class JdbcRadius {
	private Logger logger = Logger.getLogger(this.getClass().getName());

	private final String DB_URL = "jdbc:mariadb://localhost/radius";

	// Database credentials
	private final String USER = "root";
	private final String PASS = "recred";

	public void writeUser(String user, String password) throws SQLException, Exception {
		Connection c = null;
		Statement s = null;

		c = DriverManager.getConnection(DB_URL, USER, PASS);
		s = c.createStatement();

		String sql = "INSERT INTO radcheck(username, attribute, op, value) VALUES ('" + user
				+ "', 'Cleartext-Password', ':=','" + password + "')";
		s.executeUpdate(sql);

		if (s != null)
			s.close();
		if (c != null)
			c.close();
	}
}
