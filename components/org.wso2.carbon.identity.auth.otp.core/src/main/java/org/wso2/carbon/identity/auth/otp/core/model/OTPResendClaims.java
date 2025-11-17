/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.auth.otp.core.model;

/**
 * A class to hold OTP resend claim URIs.
 */
public class OTPResendClaims {

    private String resendAttemptClaimUri;
    private String lastResendTimeClaimUri;

    public OTPResendClaims(String resendAttemptClaimUri, String lastResendTimeClaimUri) {

        this.resendAttemptClaimUri = resendAttemptClaimUri;
        this.lastResendTimeClaimUri = lastResendTimeClaimUri;
    }

    public String getResendAttemptClaimUri() {

        return resendAttemptClaimUri;
    }

    public void setResendAttemptClaimUri(String resendAttemptClaimUri) {

        this.resendAttemptClaimUri = resendAttemptClaimUri;
    }

    public String getLastResendTimeClaimUri() {

        return lastResendTimeClaimUri;
    }

    public void setLastResendTimeClaimUri(String lastResendTimeClaimUri) {

        this.lastResendTimeClaimUri = lastResendTimeClaimUri;
    }
}
