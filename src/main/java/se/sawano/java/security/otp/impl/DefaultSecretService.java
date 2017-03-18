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

import org.apache.commons.codec.binary.Base64;
import se.sawano.java.security.otp.SecretService;
import se.sawano.java.security.otp.SharedSecret;

import java.security.SecureRandom;
import java.util.Random;

import static org.apache.commons.lang3.Validate.notNull;

public class DefaultSecretService implements SecretService {

    private final Random random;

    public DefaultSecretService() {
        this(new SecureRandom());
    }

    public DefaultSecretService(final Random random) {
        notNull(random);
        this.random = random;
    }

    @Override
    public SharedSecret generateSharedSecret() {
        // TODO implement
        final byte[] bytes = new byte[10];
        random.nextBytes(bytes);
        final String s1 = java.util.Base64.getEncoder().encodeToString(bytes);
        final String s = Base64.encodeBase64String(bytes);
        return null;
    }

}
