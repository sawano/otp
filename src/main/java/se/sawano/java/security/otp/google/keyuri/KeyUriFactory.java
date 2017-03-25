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

package se.sawano.java.security.otp.google.keyuri;

import se.sawano.java.security.otp.ShaAlgorithm;
import se.sawano.java.security.otp.SharedSecret;
import se.sawano.java.security.otp.google.keyuri.parameters.*;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static se.sawano.java.commons.lang.validate.Validate.notNull;

public class KeyUriFactory {

    private static final Map<ShaAlgorithm, Algorithm> ALGORITHM_MAP = new HashMap<>();
    static {
        ALGORITHM_MAP.put(ShaAlgorithm.SHA1, Algorithm.SHA1);
        ALGORITHM_MAP.put(ShaAlgorithm.SHA256, Algorithm.SHA256);
        ALGORITHM_MAP.put(ShaAlgorithm.SHA512, Algorithm.SHA512);
    }

    private KeyUriFactory() {}

    public static KeyUri totpKeyUriFrom(final SharedSecret secret,
                                        final Digits digits,
                                        final Period period,
                                        final Label.AccountName accountName,
                                        final Label.Issuer issuer) {
        notNull(secret);
        notNull(digits);
        notNull(period);
        notNull(accountName);
        notNull(issuer);

        final Parameters parameters = builder(secret, digits, issuer).withPeriod(period)
                                                                     .createFor(Type.TOTP);

        return new KeyUri(Type.TOTP, new Label(accountName, issuer), parameters);
    }

    public static KeyUri hotpKeyUriFrom(final SharedSecret secret,
                                        final Digits digits,
                                        final Counter counter,
                                        final Label.AccountName accountName,
                                        final Label.Issuer issuer) {
        notNull(secret);
        notNull(digits);
        notNull(counter);
        notNull(accountName);
        notNull(issuer);

        final Parameters parameters = builder(secret, digits, issuer).withCounter(counter)
                                                                     .createFor(Type.HOTP);

        return new KeyUri(Type.HOTP, new Label(accountName, issuer), parameters);
    }

    private static Parameters.Builder builder(final SharedSecret secret, final Digits digits, final Label.Issuer issuer) {
        return Parameters.builder()
                         .withDigits(digits)
                         .withIssuer(new Issuer(issuer.value()))
                         .withSecret(new Secret(secret.value()))
                         .withAlgorithm(convert(secret.algorithm()));
    }

    private static Algorithm convert(final ShaAlgorithm algorithm) {
        return Optional.ofNullable(ALGORITHM_MAP.get(algorithm))
                       .orElseThrow(() -> new IllegalArgumentException("Unsupported algorithm: " + algorithm));
    }
}
