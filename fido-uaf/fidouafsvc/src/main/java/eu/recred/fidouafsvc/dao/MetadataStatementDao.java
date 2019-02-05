package eu.recred.fidouafsvc.dao;

import com.google.gson.Gson;
import eu.recred.fidouafsvc.model.metadata.MetadataStatement;
import eu.recred.fidouafsvc.model.MetadataStatementModel;
import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import javax.transaction.Transactional;
import java.util.ArrayList;
import java.util.List;

/*
 * This class stores MetadataStatements.
 */

@Repository
public class MetadataStatementDao {

	private Gson gson = new Gson();

	@Autowired
	private SessionFactory sessionFactory;

	@Transactional
	public void addMetadataStatement(MetadataStatementModel[] statements) {

	}

	@Transactional
	public List<MetadataStatement> getStatements() {
		List<MetadataStatement> statements = new ArrayList<>();
		String hql = "from MetadataStatementModel";

		List<MetadataStatementModel> models = sessionFactory.getCurrentSession().createQuery(hql).list();
		System.out.println("Statements retrieved: " + models.size());

		for (MetadataStatementModel model : models) {
			MetadataStatement statement = gson.fromJson(model.getStatement(), MetadataStatement.class);
			statements.add(statement);
		}

		return statements;
	}

	@Transactional
	public MetadataStatement getStatement(String aaid) {
		MetadataStatement statement = null;
		String hql = "from MetadataStatementModel msm where msm.aaid = :aaid";

		List<MetadataStatementModel> result = sessionFactory.getCurrentSession().createQuery(hql)
				.setString("aaid", aaid).list();

		return gson.fromJson(result.get(0).getStatement(), MetadataStatement.class);
	}

}
