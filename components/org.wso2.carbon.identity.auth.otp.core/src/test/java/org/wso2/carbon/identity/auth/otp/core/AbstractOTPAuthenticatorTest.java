/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.auth.otp.core;

import org.mockito.MockedStatic;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.auth.otp.core.model.OTP;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.USERNAME;

/**
 * Unit tests for {@link AbstractOTPAuthenticator}.
 */
public class AbstractOTPAuthenticatorTest {

    private static final String ERROR_CODE_PREFIX = "OTP";

    @Test
    public void testResolveUserFromRequest() throws Exception {

        TestOTPAuthenticator otpAuthenticator = new TestOTPAuthenticator();
        HttpServletRequest request = mock(HttpServletRequest.class);
        AuthenticationContext context = new AuthenticationContext();

        when(request.getParameter(USERNAME)).thenReturn("testUser");

        try (MockedStatic<FrameworkUtils> frameworkUtilsMockedStatic = mockStatic(FrameworkUtils.class);
             MockedStatic<MultitenantUtils> multitenantUtilsMockedStatic = mockStatic(MultitenantUtils.class);
             MockedStatic<UserCoreUtil> userCoreUtilMockedStatic = mockStatic(UserCoreUtil.class)) {

            frameworkUtilsMockedStatic
                    .when(() -> FrameworkUtils.preprocessUsernameWithContextTenantDomain("testUser", context))
                    .thenReturn("PRIMARY/john@foo.com");
            multitenantUtilsMockedStatic
                    .when(() -> MultitenantUtils.getTenantAwareUsername("PRIMARY/john@foo.com"))
                    .thenReturn("john");
            userCoreUtilMockedStatic
                    .when(() -> UserCoreUtil.extractDomainFromName("PRIMARY/john@foo.com"))
                    .thenReturn("PRIMARY");
            multitenantUtilsMockedStatic
                    .when(() -> MultitenantUtils.getTenantDomain("PRIMARY/john@foo.com"))
                    .thenReturn("foo.com");

            Method resolveUserMethod = AbstractOTPAuthenticator.class
                    .getDeclaredMethod("resolveUserFromRequest", HttpServletRequest.class, AuthenticationContext.class);
            resolveUserMethod.setAccessible(true);

            AuthenticatedUser authenticatedUser = (AuthenticatedUser) resolveUserMethod
                    .invoke(otpAuthenticator, request, context);

            Assert.assertEquals(authenticatedUser.getAuthenticatedSubjectIdentifier(), "john");
            Assert.assertEquals(authenticatedUser.getUserName(), "john");
            Assert.assertEquals(authenticatedUser.getUserStoreDomain(), "PRIMARY");
            Assert.assertEquals(authenticatedUser.getTenantDomain(), "foo.com");
        }
    }

    @Test
    public void testResolveUserFromRequestWithEmptyUsername() throws Exception {

        TestOTPAuthenticator otpAuthenticator = new TestOTPAuthenticator();
        HttpServletRequest request = mock(HttpServletRequest.class);
        AuthenticationContext context = new AuthenticationContext();

        when(request.getParameter(USERNAME)).thenReturn("");

        Method resolveUserMethod = AbstractOTPAuthenticator.class
                .getDeclaredMethod("resolveUserFromRequest", HttpServletRequest.class, AuthenticationContext.class);
        resolveUserMethod.setAccessible(true);

        try {
            resolveUserMethod.invoke(otpAuthenticator, request, context);
            Assert.fail("Expected AuthenticationFailedException was not thrown");
        } catch (InvocationTargetException exception) {
            Throwable cause = exception.getCause();
            Assert.assertTrue(cause instanceof AuthenticationFailedException);
            AuthenticationFailedException authenticationFailedException =
                    (AuthenticationFailedException) cause;
            Assert.assertEquals(authenticationFailedException.getErrorCode(), ERROR_CODE_PREFIX + "-65016");
            Assert.assertEquals(authenticationFailedException.getMessage(), "Username can not be empty");
        }
    }

    /**
     * Test implementation of {@link AbstractOTPAuthenticator} with stubbed abstract behaviours.
     */
    private static class TestOTPAuthenticator extends AbstractOTPAuthenticator {

        @Override
        protected String getAuthenticatorErrorPrefix() {

            return ERROR_CODE_PREFIX;
        }

        @Override
        protected void sendOtp(AuthenticatedUser authenticatedUser, OTP otp, boolean isInitialFederationAttempt,
                               HttpServletRequest request, HttpServletResponse response,
                               AuthenticationContext context) {

        }

        @Override
        protected String getMaskedUserClaimValue(AuthenticatedUser authenticatedUser, String tenantDomain,
                                                 boolean isInitialFederationAttempt, AuthenticationContext context) {

            return "masked";
        }

        @Override
        protected void publishPostOTPValidatedEvent(OTP otpInfo, AuthenticatedUser authenticatedUser,
                                                    boolean isAuthenticationPassed, boolean isExpired,
                                                    HttpServletRequest request, AuthenticationContext context) {

        }

        @Override
        protected void publishPostOTPGeneratedEvent(OTP otpInfo, AuthenticatedUser authenticatedUser,
                                                    HttpServletRequest request, AuthenticationContext context) {

        }

        @Override
        protected String getErrorPageURL(AuthenticationContext context) {

            return "error";
        }

        @Override
        protected String getOTPLoginPageURL(AuthenticationContext context) {

            return "otp";
        }

        @Override
        public boolean canHandle(HttpServletRequest httpServletRequest) {

            return false;
        }

        @Override
        public String getContextIdentifier(HttpServletRequest httpServletRequest) {

            return "";
        }

        @Override
        public String getName() {

            return "";
        }

        @Override
        public String getFriendlyName() {

            return "";
        }
    }
}
