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

import se.sawano.java.security.otp.SecretService;
import se.sawano.java.security.otp.ShaAlgorithm;
import se.sawano.java.security.otp.SharedSecret;
import se.sawano.java.security.otp.user.persistence.SecretRepository;

import static org.apache.commons.lang3.Validate.notNull;
import static se.sawano.java.security.otp.user.Result.Failure.SECRET_ALREADY_EXISTS;

public class UserSecretService {

    private final SecretRepository secretRepository;
    private final SecretService secretService;

    public UserSecretService(final SecretRepository secretRepository, final SecretService secretService) {
        notNull(secretRepository);
        notNull(secretService);

        this.secretRepository = secretRepository;
        this.secretService = secretService;
    }

    /**
     * Create a new shared secret for the given user.
     *
     * @param userId
     *         the user to create a shared secret for
     * @param algorithm
     *         the algorithm to create a secret for
     *
     * @return the newly generated secret
     */
    public Result generateSharedSecret(final UserId userId, final ShaAlgorithm algorithm) {
        notNull(userId);
        notNull(algorithm);

        if (secretAlreadyExistsForUser(userId)) {
            return Result.failure(SECRET_ALREADY_EXISTS);
        }

        final SharedSecret createdSecret = secretService.generateSharedSecret(algorithm);
        secretRepository.save(createdSecret, userId); // TODO handle exception

        return Result.success(createdSecret);
    }

    private boolean secretAlreadyExistsForUser(final UserId userId) {
        return secretRepository.secretFor(userId).isPresent(); // TODO handle exception
    }

}
