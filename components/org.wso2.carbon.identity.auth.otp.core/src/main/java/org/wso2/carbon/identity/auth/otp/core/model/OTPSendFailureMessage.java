/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
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
 * Immutable value object that carries the i18n key and default message an OTP executor uses to
 * render an OTP-sending failure on the OTP page instead of aborting the flow.
 */
public final class OTPSendFailureMessage {

    private final String i18nKey;
    private final String defaultMessage;

    public OTPSendFailureMessage(String i18nKey, String defaultMessage) {

        this.i18nKey = i18nKey;
        this.defaultMessage = defaultMessage;
    }

    public String getI18nKey() {

        return i18nKey;
    }

    public String getDefaultMessage() {

        return defaultMessage;
    }
}
