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
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static java.util.stream.Collectors.joining;
import static java.util.stream.Collectors.toMap;
import static java.util.stream.Stream.concat;
import static org.apache.commons.lang3.Validate.*;

final class GenericParameters {

    private final Secret secret;
    private final Map<Class<? extends Parameter>, ? extends Parameter> parameters;

    GenericParameters(final Secret secret,
                      final List<? extends Parameter> parameters) {
        notNull(secret);
        noNullElements(parameters);

        this.secret = secret;
        this.parameters = toMapAndFailOnDuplicates(parameters);
        assertNoSecretInOptionalList();
    }

    private void assertNoSecretInOptionalList() {
        isTrue(!get(Secret.class).isPresent(), "Secret is not allowed as an optional parameter");
    }

    private static Map<Class<? extends Parameter>, Parameter> toMapAndFailOnDuplicates(final List<? extends Parameter> parameters) {
        return parameters.stream().collect(toMap(k -> k.getClass(), k -> k));
    }

    public String asUriString() {
        return concat(Stream.of(secret), parameters.values().stream())
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

    public Optional<Digits> digits() {
        return get(Digits.class);
    }

    public <T extends Parameter> Optional<T> get(final Class<T> clazz) {
        return Optional.ofNullable(parameters.get(clazz)).map(clazz::cast);
    }

}
