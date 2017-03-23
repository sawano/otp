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

import se.sawano.java.security.otp.google.keyuri.Type;

import java.util.Optional;

import static org.apache.commons.lang3.Validate.isTrue;
import static org.apache.commons.lang3.Validate.notNull;

public class Parameters {

    public static Builder builder() {
        return new Builder();
    }

    private final Secret secret;
    private final Optional<Issuer> issuer;
    private final Optional<Algorithm> algorithm;
    private final Optional<Counter> counter;
    private final Optional<Period> period;

    private Parameters(final Secret secret,
                       final Optional<Issuer> issuer,
                       final Optional<Algorithm> algorithm,
                       final Optional<Counter> counter,
                       final Optional<Period> period) {
        notNull(secret);
        notNull(issuer);
        notNull(algorithm);
        notNull(counter);
        notNull(period);

        this.secret = secret;
        this.issuer = issuer;
        this.algorithm = algorithm;
        this.counter = counter;
        this.period = period;
    }

    public void validateFor(final Type type) {
        if (Type.HOTP.equals(type)) {
            validateForHOTP();
        }
        else if (Type.TOTP.equals(type)) {
            validateForTOTP();
        }
        else {
            throw new IllegalArgumentException("Unsupported type: " + type);
        }
    }

    private void validateForHOTP() {
        isTrue(counter.isPresent(), "'Counter' is required for type HOTP");
        isTrue(!period.isPresent(), "'Period' is not allowed for type HOTP");
    }

    private void validateForTOTP() {
        isTrue(period.isPresent(), "'Period' is required for type TOTP");
        isTrue(!counter.isPresent(), "'Counter' is not allowed for type TOTP");
    }

    public static class Builder {
        private Secret secret;
        private Issuer issuer;
        private Algorithm algorithm;
        private Counter counter;
        private Period period;

        public Builder withSecret(final Secret secret) {
            this.secret = secret;
            return this;
        }

        public Builder withIssuer(final Issuer issuer) {
            this.issuer = issuer;
            return this;
        }

        public Builder withAlgorithm(final Algorithm algorithm) {
            this.algorithm = algorithm;
            return this;
        }

        public Builder withCounter(final Counter counter) {
            this.counter = counter;
            return this;
        }

        public Builder withPeriod(final Period period) {
            this.period = period;
            return this;
        }

        public Parameters create() {
            return new Parameters(secret, Optional.ofNullable(issuer), Optional.ofNullable(algorithm), Optional.ofNullable(counter), Optional.ofNullable(period));
        }
    }

}
