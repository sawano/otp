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

package se.sawano.java.security.otp.keyuri;

import se.sawano.java.security.otp.keyuri.parameters.*;

import java.util.Optional;

/**
 * otpauth://TYPE/LABEL?PARAMETERS
 *
 * See https://github.com/google/google-authenticator/wiki/Key-Uri-Format.
 */
public final class KeyUri {

    private final Type type;
    private final Label label;
    private final Secret secret;
    private final Optional<Issuer> issuer;
    private final Optional<Algorithm> algorithm;
    private final Optional<Counter> counter;
    private final Optional<Period> period;

    private KeyUri(final Type type,
                   final Label label,
                   final Secret secret,
                   final Optional<Issuer> issuer,
                   final Optional<Algorithm> algorithm,
                   final Optional<Counter> counter,
                   final Optional<Period> period) {
        this.type = type;
        this.label = label;
        this.secret = secret;
        this.issuer = issuer;
        this.algorithm = algorithm;
        this.counter = counter;
        this.period = period;
    }
}
