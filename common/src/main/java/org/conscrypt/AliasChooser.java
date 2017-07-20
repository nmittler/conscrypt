/*
 * Copyright (C) 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.conscrypt;

import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;
import javax.security.auth.x500.X500Principal;

/**
 * For abstracting the X509KeyManager calls between
 * {@link X509KeyManager#chooseClientAlias(String[], java.security.Principal[], java.net.Socket)}
 * and {@link X509ExtendedKeyManager#chooseEngineClientAlias(String[], java.security.Principal[],
 * javax.net.ssl.SSLEngine)}
 */
interface AliasChooser {
    String chooseClientAlias(X509KeyManager keyManager, X500Principal[] issuers, String[] keyTypes);

    String chooseServerAlias(X509KeyManager keyManager, String keyType);
}
