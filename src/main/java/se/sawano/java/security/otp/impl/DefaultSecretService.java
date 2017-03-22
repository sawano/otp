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

import se.sawano.java.security.otp.SecretService;
import se.sawano.java.security.otp.ShaAlgorithm;
import se.sawano.java.security.otp.SharedSecret;

import java.util.HashMap;
import java.util.Map;

import static org.apache.commons.lang3.Validate.notNull;

public class DefaultSecretService implements SecretService {

    private final RandomSupplier random;
    private final Map<ShaAlgorithm, Integer> algorithmToNumberOfBytes = new HashMap<>();

    public DefaultSecretService() {
        this(new DefaultRandomSupplier());
    }

    public DefaultSecretService(final RandomSupplier random) {
        notNull(random);

        this.random = random;
        // TODO consolidate with SharedSecret?
        algorithmToNumberOfBytes.put(ShaAlgorithm.SHA1, 20);
        algorithmToNumberOfBytes.put(ShaAlgorithm.SHA256, 32);
        algorithmToNumberOfBytes.put(ShaAlgorithm.SHA512, 64);
    }

    public SharedSecret generateSharedSecret(final ShaAlgorithm algorithm) {
        final byte[] bytes = new byte[algorithmToNumberOfBytes.get(algorithm)];

        random.nextBytes(bytes);

        return SharedSecret.from(bytes, algorithm);
    }

}
