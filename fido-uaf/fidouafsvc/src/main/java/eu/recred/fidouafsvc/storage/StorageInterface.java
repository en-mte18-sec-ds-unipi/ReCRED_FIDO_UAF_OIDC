/*
 * Copyright 2015 eBay Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package eu.recred.fidouafsvc.storage;

import eu.recred.fidouafsvc.model.AuthenticationIdModel;
import eu.recred.fidouafsvc.model.metadata.MetadataStatement;

import java.util.List;

/*
 * This class records data.
 */

public interface StorageInterface {

	void storeServerDataString(String username, String serverDataString);

	String getUsername(String serverDataString);

	void store(RegistrationRecord[] records) throws DuplicateKeyException, SystemErrorException;

	RegistrationRecord readRegistrationRecord(String key);

	List<RegistrationRecord> readRegistrationRecordUsername(String username) throws Exception;

	void update(RegistrationRecord[] records);

	void saveAuthenticationId(String id, String username, String timestamp);

	AuthenticationIdModel getAuthenticated(String id);

	void deleteRegistrationRecord(String authenticator);

	List<MetadataStatement> getMetadataStatements();

	MetadataStatement getMetadataStatement(String aaid);

	void deleteAuthenticationId(String id);

	void deleteAuthenticationIdByUsername(String username);
}
