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

import java.util.Optional;

import static org.apache.commons.lang3.Validate.isTrue;
import static org.apache.commons.lang3.Validate.notNull;

public class TOTPParameters {

    private final GenericParameters parameters;

    TOTPParameters(final GenericParameters parameters) {
        notNull(parameters);

        this.parameters = parameters;

        validateForTOTP();
    }

    private void validateForTOTP() {
        isTrue(get(Period.class).isPresent(), "'Period' is required for type TOTP");
        isTrue(!get(Counter.class).isPresent(), "'Counter' is not allowed for type TOTP");
    }

    public Optional<Period> period() {
        return get(Period.class);
    }

    public Secret secret() {
        return parameters.secret();
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

    public String asUriString() {
        return parameters.asUriString();
    }

    private <T extends Parameter> Optional<T> get(final Class<T> clazz) {
        return parameters.get(clazz);
    }

}
