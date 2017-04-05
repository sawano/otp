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

interface Parameter {

    /**
     * The URI style parameter string. E.g. secret=ENJDVNXVNESP7N2VIOHSQG5RVID77N7P. The value will be URI encoded as
     * appropriate so there's no need to encode it again.
     *
     * @return the pair
     */
    String parameterPair();

}
