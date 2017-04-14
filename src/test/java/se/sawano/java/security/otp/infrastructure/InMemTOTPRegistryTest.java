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

package se.sawano.java.security.otp.infrastructure;

import org.junit.Test;
import se.sawano.java.security.otp.TOTP;
import se.sawano.java.security.otp.user.UserId;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static se.sawano.java.security.otp.TOTP.Length.SIX;
import static se.sawano.java.security.otp.TOTP.totp;
import static se.sawano.java.security.otp.user.UserId.userId;

public class InMemTOTPRegistryTest {

    private static final TOTP TOTP_1 = totp(123456, SIX);
    private static final TOTP TOTP_2 = totp(456123, SIX);
    private InMemTOTPRegistry registry;

    @Test
    public void should_mark_totp_as_consumed() throws Exception {
        givenRegistry();

        whenConsuming(TOTP_1).forUser(userId("john"));

        then(TOTP_1).forUser(userId("john")).isConsumed();
    }

    @Test
    public void should_only_mark_given_totp_as_consumed() throws Exception {
        givenRegistry();

        whenConsuming(TOTP_1).forUser(userId("jane"));
        whenConsuming(TOTP_2).forUser(userId("jane"));
        whenConsuming(TOTP_2).forUser(userId("john"));

        then(TOTP_1).forUser(userId("jane")).isConsumed();
        then(TOTP_2).forUser(userId("jane")).isConsumed();
        then(TOTP_1).forUser(userId("john")).isNotConsumed();
        then(TOTP_2).forUser(userId("john")).isConsumed();
    }

    @Test
    public void should_work_even_if_empty() throws Exception {
        givenRegistry();

        then(TOTP_1).forUser(userId("jane")).isNotConsumed();
    }

    private void givenRegistry() {
        registry = new InMemTOTPRegistry();
    }

    private Consume whenConsuming(final TOTP totp) {
        return new Consume(totp);
    }

    private Check then(final TOTP totp) {
        return new Check(totp);
    }

    private class Consume {
        private final TOTP totp;

        private Consume(final TOTP totp) {this.totp = totp;}

        public void forUser(final UserId userId) {
            InMemTOTPRegistryTest.this.registry.markConsumed(totp, userId);
        }

    }

    private class Check {
        private final TOTP totp;
        private UserId userId;

        public Check(final TOTP totp) {this.totp = totp;}

        public Check forUser(final UserId userId) {
            this.userId = userId;
            return this;
        }

        public void isConsumed() {
            assertTrue(InMemTOTPRegistryTest.this.registry.isConsumed(this.totp, this.userId));
        }

        public void isNotConsumed() {
            assertFalse(InMemTOTPRegistryTest.this.registry.isConsumed(this.totp, this.userId));
        }
    }
}