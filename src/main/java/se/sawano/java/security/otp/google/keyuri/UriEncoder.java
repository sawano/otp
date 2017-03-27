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

import static org.apache.commons.lang3.Validate.notNull;

/**
 * An encoder that performs URI encoding, aka percent-encoding. See also <a href="https://tools.ietf.org/html/rfc3986">RFC 3986</a>.
 */
public class UriEncoder {

    /**
     * Unreserved characters as per RFC 3986. [A-Za-z0-9] are already excluded by the PercentEscaper.
     */
    private static final String UNRESERVED_CHARACTERS = "-._~";

    /**
     * Encodes the given string.
     *
     * @param value
     *         the string to encode
     *
     * @return the URI encoded string
     */
    public static String encode(final String value) {
        notNull(value);

        return new PercentEscaper(UNRESERVED_CHARACTERS, false).escape(value);
    }
}
