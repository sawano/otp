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

import se.sawano.java.security.otp.google.keyuri.parameters.HOTPParameters;
import se.sawano.java.security.otp.google.keyuri.parameters.Issuer;
import se.sawano.java.security.otp.google.keyuri.parameters.TOTPParameters;

import java.net.URI;
import java.util.Optional;
import java.util.function.Consumer;

import static org.apache.commons.lang3.Validate.isTrue;
import static org.apache.commons.lang3.Validate.notNull;

/**
 * otpauth://TYPE/LABEL?PARAMETERS
 * <p>
 * See https://github.com/google/google-authenticator/wiki/Key-Uri-Format.
 * </p>
 * <p>
 * Note: The issuer parameter is a string value indicating the provider or service this account is associated with,
 * URL-encoded according to RFC 3986. If the issuer parameter is absent, issuer information may be taken from the issuer
 * prefix of the label. If both issuer parameter and issuer label prefix are present, they should be equal.
 * </p>
 */
public final class KeyUri {

    private final Type type;
    private final Label label;
    private final Optional<TOTPParameters> totpParameters;
    private final Optional<HOTPParameters> hotpParameters;

    public KeyUri(final Label label, final TOTPParameters parameters) {
        notNull(label);
        notNull(parameters);

        this.type = Type.TOTP;
        this.label = label;
        this.totpParameters = Optional.of(parameters);
        this.hotpParameters = Optional.empty();

        validateIssuer();
    }

    public KeyUri(final Label label, final HOTPParameters parameters) {
        notNull(label);
        notNull(parameters);

        this.type = Type.HOTP;
        this.label = label;
        this.totpParameters = Optional.empty();
        this.hotpParameters = Optional.of(parameters);

        validateIssuer();
    }

    public URI toURI() {
        return URI.create("otpauth://" + type.value() + "/" + label.asUriString() + parametersUriSring());
    }

    private String parametersUriSring() {
        return totpParameters.map(TOTPParameters::asUriString)
                             .orElseGet(() -> hotpParameters.get().asUriString());
    }

    public Optional<TOTPParameters> totpParameters() {
        return totpParameters;
    }

    public Optional<HOTPParameters> hotpParameters() {
        return hotpParameters;
    }

    public Type type() {
        return type;
    }

    public Label label() {
        return label;
    }

    private void validateIssuer() {
        label.issuer()
             .map(labelIssuer -> (Consumer<Issuer>) parameterIssuer -> verifyEqual(labelIssuer, parameterIssuer))
             .ifPresent(issuerConsumer -> issuer().ifPresent(issuerConsumer));
    }

    private Optional<Issuer> issuer() {
        return totpParameters.map(TOTPParameters::issuer)
                             .orElseGet(() -> hotpParameters.get().issuer());
    }

    private void verifyEqual(final Label.Issuer issuer, final Issuer parameterIssuer) {
        isTrue(issuer.value().equals(parameterIssuer.value()), "Issuer must be same in Label and parameters");
    }

}
