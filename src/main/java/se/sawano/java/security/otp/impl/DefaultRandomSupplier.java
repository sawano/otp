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

public class DefaultRandomSupplier implements RandomSupplier {

    private static final int MAX_ITERATIONS = 500_000;
    private SecureRandom random;
    private volatile int counter = 0;

    public DefaultRandomSupplier() {
        random = createRandom();
    }

    @Override
    public synchronized void nextBytes(final byte[] bytes) {
        if (counter >= MAX_ITERATIONS) {
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
