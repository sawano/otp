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

package se.sawano.java.security.otp.application;

import se.sawano.java.security.otp.*;
import se.sawano.java.security.otp.TOTPService;
import se.sawano.java.security.otp.SecretService;
import se.sawano.java.security.otp.user.UserId;
import se.sawano.java.security.otp.user.persistence.SecretRepository;
import se.sawano.java.security.otp.user.persistence.TOTPRegistry;

import static org.apache.commons.lang3.Validate.notNull;
import static se.sawano.java.security.otp.application.Result.Failure.SECRET_ALREADY_EXISTS;

// TODO rename to better name?
public class VerificationService {

    private final TOTPService underlyingService;
    private final SecretService secretService;
    private final TOTPRegistry totpRegistry;
    private final SecretRepository secretRepository;

    public VerificationService(final TOTPService underlyingService,
                               final SecretService secretService,
                               final TOTPRegistry totpRegistry,
                               final SecretRepository secretRepository) {
        notNull(underlyingService);
        notNull(secretService);
        notNull(totpRegistry);
        notNull(secretRepository);

        this.underlyingService = underlyingService;
        this.secretService = secretService;
        this.totpRegistry = totpRegistry;
        this.secretRepository = secretRepository;
    }

    public boolean verify(final TOTP totp, final UserId userId) {
        notNull(totp);
        notNull(userId);

        if (isConsumed(totp, userId)) {
            return false;
        }

        final Boolean isOk = secretRepository.secretFor(userId)
                                             .map(secret -> underlyingService.verify(totp, secret))
                                             .orElse(false);
        if (isOk) {
            totpRegistry.markConsumed(totp, userId);
        }

        return isOk;
    }

    private boolean isConsumed(final TOTP totp, final UserId userId) {
        return totpRegistry.isConsumed(totp, userId);
    }

    public Result createSecretFor(final UserId userId, final ShaAlgorithm shaAlgorithm) {
        if (secretAlreadyExistsForUser(userId)) {
            return Result.failure(SECRET_ALREADY_EXISTS);
        }

        final SharedSecret createdSecret = secretService.generateSharedSecret(shaAlgorithm);
        secretRepository.save(createdSecret, userId); // TODO handle exception

        return Result.success(createdSecret);
    }

    private boolean secretAlreadyExistsForUser(final UserId userId) {
        return secretRepository.secretFor(userId).isPresent(); // TODO handle exception
    }
}
