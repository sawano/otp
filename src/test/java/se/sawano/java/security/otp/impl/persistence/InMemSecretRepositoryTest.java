/*
 * Copyright 2017 Daniel Sawano
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package se.sawano.java.security.otp.impl.persistence;

import org.apache.commons.lang3.StringUtils;
import org.junit.Test;
import se.sawano.java.security.otp.ShaAlgorithm;
import se.sawano.java.security.otp.SharedSecret;
import se.sawano.java.security.otp.user.UserId;

import static org.junit.Assert.*;
import static se.sawano.java.security.otp.user.UserId.userId;

public class InMemSecretRepositoryTest {

    private static final SharedSecret SECRET_A = SharedSecret.from(StringUtils.repeat("a", 20), ShaAlgorithm.SHA1);
    private static final SharedSecret SECRET_B = SharedSecret.from(StringUtils.repeat("b", 20), ShaAlgorithm.SHA1);
    private InMemSecretRepository repository;
    private SharedSecret sharedSecret;

    @Test
    public void should_store_secret() throws Exception {
        givenRepository();
        givenSharedSecret(SECRET_A);

        whenStoringSecretFor("john.doe");

        thenSecretInRepositoryFor("john.doe").is(SECRET_A);
    }

    @Test
    public void should_delete_secret() throws Exception {
        givenRepository();
        givenSharedSecretInRepositoryFor("jane").is(SECRET_A);

        whenDeletingSecretFor("jane");

        thenNoSecretExistFor("jane");
    }

    @Test
    public void should_only_delete_secret_for_given_user() throws Exception {
        givenRepository();
        givenSharedSecretInRepositoryFor("john").is(SECRET_A);
        givenSharedSecretInRepositoryFor("jane").is(SECRET_B);

        whenDeletingSecretFor("john");

        thenNoSecretExistFor("john");
        thenSecretInRepositoryFor("jane").is(SECRET_B);
    }

    private void thenNoSecretExistFor(final String userId) {
        assertFalse(repository.secretFor(userId(userId)).isPresent());
    }

    private void whenDeletingSecretFor(final String userId) {
        repository.deleteFor(userId(userId));
    }

    private SecretMap givenSharedSecretInRepositoryFor(final String userId) {
        return new SecretMap(userId(userId));
    }

    private void givenRepository() {
        repository = new InMemSecretRepository();
    }

    private void givenSharedSecret(final SharedSecret secret) {
        sharedSecret = secret;
    }

    private void whenStoringSecretFor(final String userId) {
        repository.save(sharedSecret, userId(userId));
    }

    private Check thenSecretInRepositoryFor(final String userId) {
        final UserId user = userId(userId);
        assertTrue(repository.secretFor(user).isPresent());
        return new Check(user);
    }

    private class SecretMap {
        private final UserId userId;

        private SecretMap(final UserId userId) {
            this.userId = userId;
        }

        public void is(final SharedSecret secret) {
            InMemSecretRepositoryTest.this.repository.save(secret, this.userId);
        }
    }

    private class Check {
        private final UserId userId;

        private Check(final UserId userId) {this.userId = userId;}

        public void is(final SharedSecret expectedSecret) {
            assertEquals(expectedSecret.value(), InMemSecretRepositoryTest.this.repository.secretFor(this.userId).get().value());
        }
    }
}