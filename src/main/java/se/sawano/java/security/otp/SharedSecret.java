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

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.util.Arrays;

import static org.apache.commons.lang3.Validate.*;

/**
 * RFC4226 requires a shared secret with minimum length of 128 bits. And recommends the secret to be at leas 160 bits
 * (20 bytes). This class takes an opinionated view and requires the secret to be at least 20 bytes.
 *
 * <p>
 * This value object is a read-once object and it's value can only be read once.
 * </p>
 */
public final class SharedSecret implements Externalizable {

    public static SharedSecret from(final byte[] bytes, final ShaAlgorithm algorithm) {
        notNull(bytes);
        notNull(algorithm);

        return new SharedSecret(bytes, algorithm);
    }

    public static final int MINIMUM_NUMBER_OF_BYTES = 20;

    private final byte[] value;
    private final ShaAlgorithm algorithm;
    private boolean consumed = false;

    private SharedSecret(final byte[] value, final ShaAlgorithm algorithm) {
        notNull(value);
        notNull(algorithm);
        isTrue(value.length >= MINIMUM_NUMBER_OF_BYTES, "Minimum length of secret is %d bytes", MINIMUM_NUMBER_OF_BYTES);

        this.value = value.clone();
        this.algorithm = algorithm;
    }

    public byte[] value() {
        validState(!consumed, "Value has already been consumed");
        final byte[] copy = value.clone();
        Arrays.fill(value, (byte) 0);
        consumed = true;
        return copy;
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

    @Override
    public boolean equals(final Object o) {
        throw deny();
    }

    @Override
    public int hashCode() {
        throw deny();
    }

    @Override
    public String toString() {
        return "SharedSecret{value=*****}";
    }

    @Override
    public void writeExternal(final ObjectOutput out) throws IOException {
        throw deny();
    }

    @Override
    public void readExternal(final ObjectInput in) throws IOException, ClassNotFoundException {
        throw deny();
    }

    private static UnsupportedOperationException deny() {
        return new UnsupportedOperationException("Not allowed");
    }

}
