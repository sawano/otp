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

package se.sawano.java.security.otp.application;

import se.sawano.java.security.otp.SharedSecret;

import java.util.Optional;

import static java.util.Optional.ofNullable;

public final class Result {

    public static Result success(final SharedSecret sharedSecret) {
        return new Result(sharedSecret, null);
    }

    public static Result failure(final Failure failure) {
        return new Result(null, failure);
    }

    public enum Failure {
        SECRET_ALREADY_EXISTS;
    }

    private final SharedSecret secret;
    private final Failure failure;

    private Result(final SharedSecret secret, final Failure failure) {
        this.failure = failure;
        this.secret = secret;
    }

    public boolean isFailure() {
        return failure != null;
    }

    public boolean isSuccess() {
        return secret != null;
    }

    public Optional<SharedSecret> secret() {
        return ofNullable(secret);
    }

    public Optional<Failure> failure() {
        return ofNullable(failure);
    }

}
