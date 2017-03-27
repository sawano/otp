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

import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;

import static java.util.stream.Collectors.toList;

public class ParametersBuilder<T extends ParametersBuilder> {

    public static TotpParametersBuilder totpBuilder() {
        return new TotpParametersBuilder();
    }

    public static HotpParametersBuilder hotpBuilder() {
        return new HotpParametersBuilder();
    }

    public static final class TotpParametersBuilder extends ParametersBuilder<TotpParametersBuilder> {

        private Period period;

        private TotpParametersBuilder() {}

        public TotpParametersBuilder withPeriod(final Period period) {
            this.period = period;
            return this;
        }

        public TOTPParameters create() {
            final List<Parameter> optionalParameters = Stream.of(algorithm, digits, issuer, period)
                                                             .filter(Objects::nonNull)
                                                             .collect(toList());

            final GenericParameters parameters = new GenericParameters(secret, optionalParameters);
            return new TOTPParameters(parameters);
        }
    }

    public static final class HotpParametersBuilder extends ParametersBuilder<HotpParametersBuilder> {

        private Counter counter;

        private HotpParametersBuilder() {}

        public HotpParametersBuilder withCounter(final Counter counter) {
            this.counter = counter;
            return this;
        }

        public HOTPParameters create() {
            final List<Parameter> optionalParameters = Stream.of(algorithm, digits, issuer, counter)
                                                             .filter(Objects::nonNull)
                                                             .collect(toList());

            return new HOTPParameters(new GenericParameters(secret, optionalParameters));
        }
    }

    Secret secret;
    Algorithm algorithm;
    Digits digits;
    Issuer issuer;

    private ParametersBuilder() {}

    public T withSecret(final Secret secret) {
        this.secret = secret;
        return (T) this;
    }

    public T withAlgorithm(final Algorithm algorithm) {
        this.algorithm = algorithm;
        return (T) this;
    }

    public T withDigits(final Digits digits) {
        this.digits = digits;
        return (T) this;
    }

    public T withIssuer(final Issuer issuer) {
        this.issuer = issuer;
        return (T) this;
    }

}
