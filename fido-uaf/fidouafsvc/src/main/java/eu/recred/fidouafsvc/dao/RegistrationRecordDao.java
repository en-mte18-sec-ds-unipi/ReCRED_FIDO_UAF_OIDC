package eu.recred.fidouafsvc.dao;

import com.google.gson.Gson;
import eu.recred.fidouafsvc.model.RegistrationRecordModel;
import eu.recred.fidouafsvc.storage.RegistrationRecord;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.logging.Logger;

/**
 * Created by sorin.teican on 8/29/2016.
 */

/*
 * This class stores registrationRecords.
 */

@Repository("registrationRecordDao")
public class RegistrationRecordDao {

	Logger logger = Logger.getLogger(this.getClass().getSimpleName());

	@Autowired
	private SessionFactory sessionFactory;

	private Gson gson = new Gson();

	/**
	 * addRegistrationRecords
	 * <p>%%% BEGIN SOURCE CODE %%%
     * {@codesnippet RegistrationRecordDao-addRegistrationRecords}
     * %%% END SOURCE CODE %%%
	 * <p>This function stores the registration response recod
	 * 
	 * <p>REGres 2.2.2
	 * @see RegistrationRecord
	 * @see RegistrationRecordModel
	 * 
	 * @param records
	 */
	@Transactional
	public void addRegistrationRecords(RegistrationRecord[] records) {
		// BEGIN: RegistrationRecordDao-addRegistrationRecords
		Session session = sessionFactory.getCurrentSession();

		for (RegistrationRecord record : records) {
			RegistrationRecordModel recordModel = new RegistrationRecordModel();
			System.out.println("Authenticator AAID: " + record.authenticator.AAID);
			System.out.println("Authenticator KeyID: " + record.authenticator.KeyID);
			recordModel.setAuthenticator(record.authenticator.toString());
			recordModel.setRecord(gson.toJson(record));
			recordModel.setTimestamp(record.timeStamp);
			session.save(recordModel);
		}
		// END: RegistrationRecordDao-addRegistrationRecords
	}

	@Transactional
	public void update(RegistrationRecord[] records) {
		Session session = sessionFactory.getCurrentSession();

		for (RegistrationRecord record : records) {
			String hql = "from RegistrationRecordModel rr where rr.authenticator = :authenticator";
			List<RegistrationRecordModel> result = sessionFactory.getCurrentSession().createQuery(hql)
					.setString("authenticator", record.authenticator.toString()).list();

			RegistrationRecordModel model = result.get(0);
			RegistrationRecord regRec = gson.fromJson(model.getRecord(), RegistrationRecord.class);
			// regRec.timeStamp = "" + new Date().getTime();
			regRec.SignCounter = record.SignCounter;
			regRec.authenticator.timestamp = "" + new Date().getTime();
			model.setRecord(gson.toJson(regRec));
			session.update(model);
		}
	}

	@Transactional
	public RegistrationRecord getByAuthenticator(String authenticator) {
		// Criteria criteria =
		// sessionFactory.getCurrentSession().createCriteria(RegistrationRecordModel.class);
		// RegistrationRecordModel model = (RegistrationRecordModel)
		// criteria.add(Restrictions.eq("authenticator", authenticator))
		// .uniqueResult();
		//
		// RegistrationRecord record = gson.fromJson(model.getRecord(),
		// RegistrationRecord.class);
		// return record;
		String hql = "from RegistrationRecordModel rr where rr.authenticator = :authenticator";
		List<RegistrationRecordModel> result = sessionFactory.getCurrentSession().createQuery(hql)
				.setString("authenticator", authenticator).list();

		return gson.fromJson(result.get(0).getRecord(), RegistrationRecord.class);
	}

	@Transactional
	public List<RegistrationRecord> getRegistrationRecord(String username) throws Exception {
		String hql = "from RegistrationRecordModel";
		List<RegistrationRecordModel> result = sessionFactory.getCurrentSession().createQuery(hql).list();

		List<RegistrationRecord> records = new ArrayList<>();

		for (RegistrationRecordModel model : result) {
			RegistrationRecord record = gson.fromJson(model.getRecord(), RegistrationRecord.class);
			if (record.username.equals(username)) {
				// logger.log(Level.INFO, "Record: " + gson.toJson(record));
				// logger.log(Level.INFO, "model record: " + model.getRecord());
				records.add(record);
			}
		}

		if (records.isEmpty()) {
			System.out.println("nothing found!");
			// throw new Exception();
		}

		return records;
	}

	@Transactional
	public void deleteRecord(String authenticator) {

		// Criteria criteria =
		// sessionFactory.getCurrentSession().createCriteria(RegistrationRecordModel.class);
		// RegistrationRecordModel model = (RegistrationRecordModel)
		// criteria.add(Restrictions.eq("authenticator", authenticator))
		// .uniqueResult();
		String hql = "delete from RegistrationRecordModel rr where rr.authenticator = :authenticator";
		sessionFactory.getCurrentSession().createQuery(hql).setString("authenticator", authenticator).executeUpdate();
	}
}
