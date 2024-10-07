/*
 * Copyright (c) 2023-2024, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.auth.otp.core.util;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.owasp.encoder.Encode;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants;
import org.wso2.carbon.identity.auth.otp.core.internal.AuthenticatorDataHolder;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;

import javax.servlet.http.HttpServletRequest;

import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.MULTI_OPTION_URI_PARAM;

/**
 * Utility functions for the authenticator.
 */
public class AuthenticatorUtils {

    /**
     * Get the multi option URI query param.
     *
     * @param request HttpServletRequest.
     * @return Query parameter for the multi option URI.
     */
    @SuppressFBWarnings("UNVALIDATED_REDIRECT")
    public static String getMultiOptionURIQueryString(HttpServletRequest request) {

        String multiOptionURI = "";
        if (request != null) {
            multiOptionURI = request.getParameter("multiOptionURI");
            multiOptionURI = multiOptionURI != null ? MULTI_OPTION_URI_PARAM +
                    Encode.forUriComponent(multiOptionURI) : "";
        }
        return multiOptionURI;
    }

    /**
     * Mask the given value if it is required.
     *
     * @param value Value to be masked.
     * @return Masked/unmasked value.
     */
    public static String maskIfRequired(String value) {

        return LoggerUtils.isLogMaskingEnable ? LoggerUtils.getMaskedContent(value) : value;
    }

    public static Property[] getAccountLockConnectorConfigs(String tenantDomain) throws
            AuthenticationFailedException {

        Property[] connectorConfigs;
        try {
            connectorConfigs = AuthenticatorDataHolder
                    .getIdentityGovernanceService()
                    .getConfiguration(
                            new String[]{
                                    AuthenticatorConstants.PROPERTY_LOGIN_FAIL_TIMEOUT_RATIO,
                                    AuthenticatorConstants.PROPERTY_ACCOUNT_LOCK_ON_FAILURE,
                                    AuthenticatorConstants.PROPERTY_ACCOUNT_LOCK_ON_FAILURE_MAX,
                                    AuthenticatorConstants.PROPERTY_ACCOUNT_LOCK_TIME
                            }, tenantDomain);
        } catch (Exception e) {
            throw new AuthenticationFailedException("Error occurred while retrieving account lock connector " +
                    "configuration", e);
        }
        return connectorConfigs;
    }
}
