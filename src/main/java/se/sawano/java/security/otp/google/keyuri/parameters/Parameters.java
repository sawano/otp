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

import se.sawano.java.commons.lang.Optionals;
import se.sawano.java.security.otp.google.keyuri.Type;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Stream;

import static java.util.Optional.of;
import static java.util.stream.Collectors.*;
import static org.apache.commons.lang3.Validate.*;

public final class Parameters {

    public static Builder builder() {
        return new Builder();
    }

    private final Secret secret;
    private final Map<Class<? extends Parameter>, ? extends Parameter> parameters;

    private Parameters(final Secret secret,
                       final List<? extends Parameter> parameters) {
        notNull(secret);
        noNullElements(parameters);

        this.secret = secret;
        this.parameters = toMapAndFailOnDuplicates(parameters);
    }

    private static Map<Class<? extends Parameter>, Parameter> toMapAndFailOnDuplicates(final List<? extends Parameter> parameters) {
        return parameters.stream().collect(toMap(k -> k.getClass(), k -> k));
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
        isTrue(get(Counter.class).isPresent(), "'Counter' is required for type HOTP");
        isTrue(!get(Period.class).isPresent(), "'Period' is not allowed for type HOTP");
    }

    private void validateForTOTP() {
        isTrue(get(Period.class).isPresent(), "'Period' is required for type TOTP");
        isTrue(!get(Counter.class).isPresent(), "'Counter' is not allowed for type TOTP");
    }

    public String asUriString() {
        return Stream.of(of(secret), issuer(), algorithm(), digits(), counter(), period())
                     .flatMap(Optionals::stream)
                     .map(Parameter::parameterPair)
                     .collect(joining("&", "?", ""));
    }

    public Secret secret() {
        return secret;
    }

    public Optional<Issuer> issuer() {
        return get(Issuer.class);
    }

    public Optional<Algorithm> algorithm() {
        return get(Algorithm.class);
    }

    public Optional<Counter> counter() {
        return get(Counter.class);
    }

    public Optional<Period> period() {
        return get(Period.class);
    }

    public Optional<Digits> digits() {
        return get(Digits.class);
    }

    private <T extends Parameter> Optional<T> get(final Class<T> clazz) {
        return Optional.ofNullable(parameters.get(clazz)).map(clazz::cast);
    }

    public static final class Builder {
        private Algorithm algorithm;
        private Counter counter;
        private Digits digits;
        private Issuer issuer;
        private Period period;
        private Secret secret;

        public Builder withAlgorithm(final Algorithm algorithm) {
            this.algorithm = algorithm;
            return this;
        }

        public Builder withCounter(final Counter counter) {
            this.counter = counter;
            return this;
        }

        public Builder withDigits(final Digits digits) {
            this.digits = digits;
            return this;
        }

        public Builder withIssuer(final Issuer issuer) {
            this.issuer = issuer;
            return this;
        }

        public Builder withPeriod(final Period period) {
            this.period = period;
            return this;
        }

        public Builder withSecret(final Secret secret) {
            this.secret = secret;
            return this;
        }

        public Parameters createFor(final Type type) {
            notNull(type);

            final List<Parameter> optionalParameters = Stream.of(algorithm, counter, digits, issuer, period, secret)
                                                             .filter(Objects::nonNull)
                                                             .collect(toList());

            final Parameters parameters = new Parameters(secret, optionalParameters);
            parameters.validateFor(type);

            return parameters;
        }
    }

}
