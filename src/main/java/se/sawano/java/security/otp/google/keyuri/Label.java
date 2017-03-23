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

import com.google.common.net.PercentEscaper;

import java.util.Optional;

import static org.apache.commons.lang3.Validate.*;

/**
 * The label is used to identify which account a key is associated with.
 *
 * <p>
 * See https://github.com/google/google-authenticator/wiki/Key-Uri-Format#label
 * </p>
 */
// TODO test coverage
public final class Label {

    private final AccountName accountName;
    @SuppressWarnings("OptionalUsedAsFieldOrParameterType")
    private final Optional<Issuer> issuer;

    /**
     * Creates a label with the given account name and without an issuer. Note that it's recommended to always use an issuer.
     *
     * @param accountName
     *         the account name
     *
     * @see #Label(AccountName, Issuer)
     */
    public Label(final AccountName accountName) {
        this(accountName, Optional.empty());
    }

    /**
     * Creates a label with the given account name and issuer.
     *
     * @param accountName
     *         the account name
     * @param issuer
     *         the issuer
     */
    public Label(final AccountName accountName, final Issuer issuer) {
        this(notNull(accountName), Optional.of(notNull(issuer)));
    }

    @SuppressWarnings("OptionalUsedAsFieldOrParameterType")
    private Label(final AccountName accountName, final Optional<Issuer> issuer) {
        notNull(accountName);
        notNull(issuer);

        this.accountName = accountName;
        this.issuer = issuer;
    }

    /**
     * Account name.
     *
     * <p>
     * E.g. "John Doe" or "john.doe@example.com".
     * </p>
     *
     * @return the account name
     */
    public AccountName accountName() {
        return accountName;
    }

    /**
     * The issuer. This identifies the provider or service managing the account ({@link #accountName()}. The issuer helps prevent collisions where multiple services may use the same account name, such
     * as email address. <p> E.g. "My Company" or "My Provider" </p>
     *
     * @return the issuer
     */
    public Optional<Issuer> issuer() {
        return issuer;
    }

    public String value() {
        final String value = accountName.value() + issuer.map(i -> ":" + i.value()).orElse("");
        // TODO find another lib for escaping. Guava is a bit big for just this dependency.
        return new PercentEscaper("-._~" + ".", false).escape(value);
    }

    /**
     * Representation of an account name. An account name may not contain ':'.
     */
    public static final class AccountName {

        /**
         * The max length of an axccount name.
         */
        public static final int MAX_LENGTH = 300;

        private final String value;

        public AccountName(final String value) {
            notBlank(value);
            final String trimmed = value.trim();
            inclusiveBetween(0, MAX_LENGTH, trimmed.length(), "Maximum length of account name is %d", MAX_LENGTH);
            isTrue(!trimmed.contains(":"), "Account name may not contain ':'");

            this.value = trimmed;
        }

        public String value() {
            return value;
        }
    }

    /**
     * Representation of an issuer. An issuer may not contain ':'.
     */
    public static final class Issuer {

        /**
         * The max length of an issuer.
         */
        public static final int MAX_LENGTH = 200;

        private final String value;

        public Issuer(final String value) {
            notBlank(value);
            final String trimmed = value.trim();
            inclusiveBetween(0, MAX_LENGTH, trimmed.length(), "Maximum length of issuer is %d", MAX_LENGTH);
            isTrue(!trimmed.contains(":"), "Issuer may not contain ':'");

            this.value = trimmed;
        }

        public String value() {
            return value;
        }
    }

}
