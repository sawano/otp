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

package se.sawano.java.security.otp.impl;

import java.security.SecureRandom;

import static org.apache.commons.lang3.Validate.isTrue;

/**
 * A {@link RandomSupplier} backed by {@link SecureRandom}. The underlying {@link SecureRandom} will be reseeded after a set number of invocations. The {@link SecureRandom} instance used is seeded
 * on creation.
 *
 * <p> This supplier is thread safe. </p>
 */
public class DefaultRandomSupplier implements RandomSupplier {

    /**
     * Maximum number of invocations before reseeding the {@link SecureRandom}.
     */
    public static final int MAX_INVOCATIONS = 500_000;

    private SecureRandom random;
    private final int maxInvocations;
    private int counter = 0;

    public DefaultRandomSupplier() {
        this(MAX_INVOCATIONS);
    }

    public DefaultRandomSupplier(final int maxInvocations) {
        isTrue(maxInvocations > 0, "Max number of invocations must be greater than 0");

        this.maxInvocations = maxInvocations;
        random = createRandom();
    }

    @Override
    public synchronized void nextBytes(final byte[] bytes) {
        if (counter >= maxInvocations) {
            random = createRandom();
        }

        ++counter;
        random.nextBytes(bytes);
    }

    private SecureRandom createRandom() {
        counter = 0;
        final SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(new byte[1]);  // Ensure seeding
        return secureRandom;
    }
}
