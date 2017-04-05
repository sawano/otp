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

package se.sawano.java.security.otp;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Hex;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Objects;

import static org.apache.commons.lang3.Validate.isTrue;
import static org.apache.commons.lang3.Validate.notNull;

/**
 * RFC4226 requires a shared secret with minimum length of 128 bits. And recommends the secret to be at leas 160 bits
 * (20 bytes). This class takes an opinionated view and requires the secret to be at least 20 bytes.
 */
// TODO clean up factory methods
public final class SharedSecret implements Externalizable {

    public static SharedSecret from(final String value, final ShaAlgorithm algorithm) {
        return from(value, UTF_8, algorithm);
    }

    public static SharedSecret from(final String value, final Charset charset, final ShaAlgorithm algorithm) {
        notNull(value);
        notNull(charset);

        return fromHex(Hex.encodeHexString(value.getBytes(charset)), algorithm);
    }

    public static SharedSecret fromHex(final String hexString, final ShaAlgorithm algorithm) {
        notNull(hexString);
        notNull(algorithm);

        try {
            final byte[] bytes = Hex.decodeHex(hexString.toCharArray());
            return new SharedSecret(bytes, algorithm);
        } catch (final DecoderException e) {
            throw new RuntimeException(e);
        }
    }

    public static SharedSecret fromBase32(final String base32String, final ShaAlgorithm algorithm) {
        notNull(base32String);
        notNull(algorithm);

        final byte[] bytes = new Base32(false).decode(base32String);
        return from(bytes, algorithm);
    }

    public static SharedSecret from(final byte[] bytes, final ShaAlgorithm algorithm) {
        notNull(bytes);
        notNull(algorithm);

        return new SharedSecret(bytes, algorithm);
    }

    public static final int MINIMUM_NUMBER_OF_BYTES = 20;
    private static final Charset UTF_8 = Charset.forName("UTF8");

    private final byte[] value;
    private final ShaAlgorithm algorithm;

    private SharedSecret(final byte[] value, final ShaAlgorithm algorithm) {
        notNull(value);
        notNull(algorithm);
        isTrue(value.length >= MINIMUM_NUMBER_OF_BYTES, "Minimum length of secret is %d bytes", MINIMUM_NUMBER_OF_BYTES);

        this.value = value;
        this.algorithm = algorithm;
    }

    public byte[] value() {
        return value;
    }

    /**
     * Returns the length of the secret, in number of bytes.
     *
     * @return the number of bytes in this secret
     */
    public int keyLength() {
        return value.length;
    }

    public ShaAlgorithm algorithm() {
        return algorithm;
    }

    public String asHexString() {
        return Hex.encodeHexString(value);
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        final SharedSecret secret = (SharedSecret) o;
        return Arrays.equals(value, secret.value) &&
                algorithm == secret.algorithm;
    }

    @Override
    public int hashCode() {
        return Objects.hash(value, algorithm);
    }

    @Override
    public String toString() {
        return "SharedSecret{value=*****}";
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
