package eu.recred.fidouafsvc.dao;

import eu.recred.fidouafsvc.model.metadata.Aaid;
import org.hibernate.Criteria;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * Created by sorin.teican on 29-May-17.
 */

/*
 * This class stores AAIDs.
 */

@Repository("aaidDao")
public class AaidDao {

	@Autowired
	private SessionFactory sessionFactory;

	@Transactional
	public void addAaid(String name) {
		Session session = sessionFactory.getCurrentSession();

		Aaid a = new Aaid();
		a.setName(name);

		session.save(a);
	}

	@Transactional
	public List<Aaid> listAllTrustedFacets() {
		Criteria criteria = sessionFactory.getCurrentSession().createCriteria(Aaid.class);
		// sessionFactory.getCurrentSession().get()
		return (List<Aaid>) criteria.list();
	}
}
