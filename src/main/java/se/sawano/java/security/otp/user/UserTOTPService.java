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

package se.sawano.java.security.otp.user;

import se.sawano.java.security.otp.TOTP;
import se.sawano.java.security.otp.TOTPService;
import se.sawano.java.security.otp.user.persistence.SecretRepository;
import se.sawano.java.security.otp.user.persistence.TOTPRegistry;

import static org.apache.commons.lang3.Validate.notNull;

// TODO javadoc
public class UserTOTPService {

    private final SecretRepository secretRepository;
    private final TOTPService totpService;
    private final TOTPRegistry totpRegistry;

    public UserTOTPService(final SecretRepository secretRepository, final TOTPService totpService, final TOTPRegistry totpRegistry) {
        notNull(secretRepository);
        notNull(totpService);
        notNull(totpRegistry);

        this.secretRepository = secretRepository;
        this.totpService = totpService;
        this.totpRegistry = totpRegistry;
    }

    public TOTP create(UserId userId, TOTP.Length length) {
        // TODO implement
        return null;
    }

    public boolean verify(TOTP totp, UserId userId) {

        notNull(totp);
        notNull(userId);

        if (isConsumed(totp, userId)) {
            return false;
        }

        final Boolean isOk = secretRepository.secretFor(userId)
                                             .map(secret -> totpService.verify(totp, secret))
                                             .orElse(false);
        if (isOk) {
            totpRegistry.markConsumed(totp, userId);
        }

        // TODO resynchronization may take place here
        return isOk;
    }

    private boolean isConsumed(final TOTP totp, final UserId userId) {
        return totpRegistry.isConsumed(totp, userId);
    }

}
