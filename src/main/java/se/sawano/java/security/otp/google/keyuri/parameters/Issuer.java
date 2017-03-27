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

package se.sawano.java.security.otp.google.keyuri.parameters;

import se.sawano.java.security.otp.google.keyuri.UriEncoder;

import static org.apache.commons.lang3.Validate.inclusiveBetween;
import static org.apache.commons.lang3.Validate.notBlank;

/**
 * STRONGLY RECOMMENDED: The issuer parameter is a string value indicating the provider or service this account is associated with, URL-encoded according to RFC 3986.
 *
 * <p> See https://github.com/google/google-authenticator/wiki/Key-Uri-Format#issuer </p>
 *
 * <p> This is very similar to {@link se.sawano.java.security.otp.google.keyuri.Label.Issuer}. One difference is that this issuer may contain ':'. Also note that if the {@code Label.Issuer} is
 * present, then this issuer must be equal to the {@code Label.Issuer}. </p>
 */
public final class Issuer implements Parameter {

    /**
     * The max length of an issuer.
     */
    public static final int MAX_LENGTH = 200;

    public static Issuer issuer(final String value) {
        return new Issuer(value);
    }

    private final String value;

    private Issuer(final String value) {
        notBlank(value);
        final String trimmed = value.trim();
        inclusiveBetween(0, MAX_LENGTH, trimmed.length(), "Maximum length of issuer is %d", MAX_LENGTH);

        this.value = value;
    }

    public String value() {
        return value;
    }

    @Override
    public String parameterPair() {
        return "issuer=" + UriEncoder.encode(value);
    }
}
