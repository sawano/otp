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

import org.apache.commons.codec.binary.Base32;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

import static org.apache.commons.lang3.Validate.notNull;

/**
 * REQUIRED: The secret parameter is an arbitrary key value encoded in Base32 according to RFC 3548.
 *
 * See https://github.com/google/google-authenticator/wiki/Key-Uri-Format#secret
 */
public final class Secret implements Parameter, Externalizable {

    public static Secret secret(final byte[] value) {
        return new Secret(value);
    }

    public static final String BASE32_PADDING = "=";

    private final String value;

    private Secret(final byte[] value) {
        notNull(value);

        this.value = removePadding(base32Encode(value));
    }

    private static String base32Encode(final byte[] value) {
        return new Base32(BASE32_PADDING.getBytes()[0]).encodeToString(value);
    }

    private static String removePadding(final String base32Value) {
        return base32Value.replace(BASE32_PADDING, "");
    }

    public String value() {
        return value;
    }

    @Override
    public String parameterPair() {
        return "secret=" + value;
    }

    @Override
    public void writeExternal(final ObjectOutput out) throws IOException {
        deny();
    }

    @Override
    public void readExternal(final ObjectInput in) throws IOException, ClassNotFoundException {
        deny();
    }

    private static void deny() {
        throw new UnsupportedOperationException("Not allowed");
    }
}
