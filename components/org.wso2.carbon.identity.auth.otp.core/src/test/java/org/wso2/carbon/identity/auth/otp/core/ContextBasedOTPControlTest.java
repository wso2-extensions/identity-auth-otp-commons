/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants;
import org.wso2.carbon.identity.auth.otp.core.model.OTP;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.Mockito.mockStatic;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.DEFAULT_OTP_RESEND_ATTEMPTS_CONTEXT_PROPERTY_NAME;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.DEFAULT_OTP_RETRY_ATTEMPTS_CONTEXT_PROPERTY_NAME;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.MAXIMUM_ALLOWED_FAILURE_LIMIT;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.MAXIMUM_RESEND_LIMIT;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.SKIP_RESEND_BLOCK_TIME;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.TERMINATE_ON_RESEND_LIMIT_EXCEEDED;

/**
 * Unit tests for context-based OTP resend/retry control in AbstractOTPAuthenticator.
 */
public class ContextBasedOTPControlTest {

    private static final String ERROR_CODE_PREFIX = "OTP";
    private static final String TENANT_DOMAIN = "carbon.super";

    private TestOTPAuthenticator authenticator;
    private MockedStatic<LoggerUtils> loggerUtilsMockedStatic;

    @BeforeMethod
    public void setUp() {

        authenticator = new TestOTPAuthenticator();
        loggerUtilsMockedStatic = mockStatic(LoggerUtils.class);
        loggerUtilsMockedStatic.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(false);
    }

    @AfterMethod
    public void tearDown() {

        if (loggerUtilsMockedStatic != null) {
            loggerUtilsMockedStatic.close();
        }
    }

    @Test(description = "Context-based resend blocking is enabled when MAXIMUM_RESEND_LIMIT param is a non-negative integer")
    public void testIsContextBasedOTPResendBlockingEnabled_WithValidPositiveLimit()
            throws AuthenticationFailedException {

        AuthenticationContext context = createContextWithRuntimeParams(
                MAXIMUM_RESEND_LIMIT, "3");
        Assert.assertTrue(authenticator.isContextBasedOTPResendBlockingEnabled(context));
    }

    @Test(description = "Context-based resend blocking is enabled when MAXIMUM_RESEND_LIMIT param is zero (zero resends allowed)")
    public void testIsContextBasedOTPResendBlockingEnabled_WithZeroLimit()
            throws AuthenticationFailedException {

        AuthenticationContext context = createContextWithRuntimeParams(
                MAXIMUM_RESEND_LIMIT, "0");
        Assert.assertTrue(authenticator.isContextBasedOTPResendBlockingEnabled(context));
    }

    @Test(description = "Context-based resend blocking is disabled when MAXIMUM_RESEND_LIMIT param is negative")
    public void testIsContextBasedOTPResendBlockingEnabled_WithNegativeLimit()
            throws AuthenticationFailedException {

        AuthenticationContext context = createContextWithRuntimeParams(
                MAXIMUM_RESEND_LIMIT, "-1");
        Assert.assertFalse(authenticator.isContextBasedOTPResendBlockingEnabled(context));
    }

    @Test(description = "Context-based resend blocking is disabled when MAXIMUM_RESEND_LIMIT param is absent")
    public void testIsContextBasedOTPResendBlockingEnabled_WithNoParam()
            throws AuthenticationFailedException {

        AuthenticationContext context = createContextWithRuntimeParams(null, null);
        Assert.assertFalse(authenticator.isContextBasedOTPResendBlockingEnabled(context));
    }

    @Test(description = "Context-based resend blocking is disabled when MAXIMUM_RESEND_LIMIT param is non-numeric")
    public void testIsContextBasedOTPResendBlockingEnabled_WithNonNumericLimit()
            throws AuthenticationFailedException {

        AuthenticationContext context = createContextWithRuntimeParams(
                MAXIMUM_RESEND_LIMIT, "invalid");
        // Non-numeric cannot be parsed to int, so OptionalInt is empty → returns false
        Assert.assertFalse(authenticator.isContextBasedOTPResendBlockingEnabled(context));
    }

    @Test(description = "Context-based retry blocking is enabled when MAXIMUM_ALLOWED_FAILURE_LIMIT is a positive integer")
    public void testIsContextBasedRetryBlockingEnabled_WithValidPositiveLimit()
            throws AuthenticationFailedException {

        AuthenticationContext context = createContextWithRuntimeParams(
                MAXIMUM_ALLOWED_FAILURE_LIMIT, "5");
        Assert.assertTrue(authenticator.isContextBasedRetryBlockingEnabled(context));
    }

    @Test(description = "Context-based retry blocking is disabled when MAXIMUM_ALLOWED_FAILURE_LIMIT is zero (must be > 0)")
    public void testIsContextBasedRetryBlockingEnabled_WithZeroLimit()
            throws AuthenticationFailedException {

        AuthenticationContext context = createContextWithRuntimeParams(
                MAXIMUM_ALLOWED_FAILURE_LIMIT, "0");
        Assert.assertFalse(authenticator.isContextBasedRetryBlockingEnabled(context));
    }

    @Test(description = "Context-based retry blocking is disabled when MAXIMUM_ALLOWED_FAILURE_LIMIT is negative")
    public void testIsContextBasedRetryBlockingEnabled_WithNegativeLimit()
            throws AuthenticationFailedException {

        AuthenticationContext context = createContextWithRuntimeParams(
                MAXIMUM_ALLOWED_FAILURE_LIMIT, "-2");
        Assert.assertFalse(authenticator.isContextBasedRetryBlockingEnabled(context));
    }

    @Test(description = "Context-based retry blocking is disabled when MAXIMUM_ALLOWED_FAILURE_LIMIT param is absent")
    public void testIsContextBasedRetryBlockingEnabled_WithNoParam()
            throws AuthenticationFailedException {

        AuthenticationContext context = createContextWithRuntimeParams(null, null);
        Assert.assertFalse(authenticator.isContextBasedRetryBlockingEnabled(context));
    }

    @Test(description = "Context-based retry blocking is disabled when MAXIMUM_ALLOWED_FAILURE_LIMIT is non-numeric")
    public void testIsContextBasedRetryBlockingEnabled_WithNonNumericLimit()
            throws AuthenticationFailedException {

        AuthenticationContext context = createContextWithRuntimeParams(
                MAXIMUM_ALLOWED_FAILURE_LIMIT, "abc");
        Assert.assertFalse(authenticator.isContextBasedRetryBlockingEnabled(context));
    }

    @Test(description = "isTerminateOnResendLimitExceeded returns true when param is 'true'")
    public void testIsTerminateOnResendLimitExceeded_WhenTrue()
            throws AuthenticationFailedException {

        AuthenticationContext context = createContextWithRuntimeParams(
                TERMINATE_ON_RESEND_LIMIT_EXCEEDED, "true");
        Assert.assertTrue(authenticator.isTerminateOnResendLimitExceeded(context));
    }

    @Test(description = "isTerminateOnResendLimitExceeded returns false when param is 'false'")
    public void testIsTerminateOnResendLimitExceeded_WhenFalse()
            throws AuthenticationFailedException {

        AuthenticationContext context = createContextWithRuntimeParams(
                TERMINATE_ON_RESEND_LIMIT_EXCEEDED, "false");
        Assert.assertFalse(authenticator.isTerminateOnResendLimitExceeded(context));
    }

    @Test(description = "isTerminateOnResendLimitExceeded returns false when param is absent")
    public void testIsTerminateOnResendLimitExceeded_WhenAbsent()
            throws AuthenticationFailedException {

        AuthenticationContext context = createContextWithRuntimeParams(null, null);
        Assert.assertFalse(authenticator.isTerminateOnResendLimitExceeded(context));
    }

    @Test(description = "User-based resend blocking is disabled when skipResendBlockTime runtime param is 'true'")
    public void testIsUserBasedOTPResendBlockingEnabled_SkipResendBlockTimeTrue()
            throws AuthenticationFailedException {

        AuthenticationContext context = createContextWithRuntimeParams(
                SKIP_RESEND_BLOCK_TIME, "true");

        // skipResendBlockTimeParam.isPresent() && skipResendBlockTimeParam.get() == true
        // => return !true => false
        Assert.assertFalse(authenticator.isUserBasedOTPResendBlockingEnabled(context));
    }

    @Test(description = "User-based resend blocking is enabled when skipResendBlockTime runtime param is 'false'")
    public void testIsUserBasedOTPResendBlockingEnabled_SkipResendBlockTimeFalse()
            throws AuthenticationFailedException {

        AuthenticationContext context = createContextWithRuntimeParams(
                SKIP_RESEND_BLOCK_TIME, "false");

        // skipResendBlockTimeParam.isPresent() && skipResendBlockTimeParam.get() == false
        // => return !false => true
        Assert.assertFalse(authenticator.isUserBasedOTPResendBlockingEnabled(context));
    }

    @Test(description = "User-based resend blocking falls back to default (false) when skipResendBlockTime is absent")
    public void testIsUserBasedOTPResendBlockingEnabled_NoOverride()
            throws AuthenticationFailedException {

        AuthenticationContext context = createContextWithRuntimeParams(null, null);

        // No override → falls back to isUserBasedOTPResendBlockingEnabled() which returns false by default
        Assert.assertFalse(authenticator.isUserBasedOTPResendBlockingEnabled(context));
    }

    @Test(description = "updateContextOTPResendCount initialises the counter to 1 when not set")
    public void testUpdateContextOTPResendCount_InitialisesToOne() {

        AuthenticationContext context = new AuthenticationContext();
        authenticator.updateContextOTPResendCount(context);
        Assert.assertEquals(context.getProperty(DEFAULT_OTP_RESEND_ATTEMPTS_CONTEXT_PROPERTY_NAME), 1);
    }

    @Test(description = "updateContextOTPResendCount increments existing counter")
    public void testUpdateContextOTPResendCount_Increments() {

        AuthenticationContext context = new AuthenticationContext();
        context.setProperty(DEFAULT_OTP_RESEND_ATTEMPTS_CONTEXT_PROPERTY_NAME, 2);
        authenticator.updateContextOTPResendCount(context);
        Assert.assertEquals(context.getProperty(DEFAULT_OTP_RESEND_ATTEMPTS_CONTEXT_PROPERTY_NAME), 3);
    }

    @Test(description = "updateContextOTPRetryCount initialises the counter to 1 when not set")
    public void testUpdateContextOTPRetryCount_InitialisesToOne() {

        AuthenticationContext context = new AuthenticationContext();
        authenticator.updateContextOTPRetryCount(context);
        Assert.assertEquals(context.getProperty(DEFAULT_OTP_RETRY_ATTEMPTS_CONTEXT_PROPERTY_NAME), 1);
    }

    @Test(description = "updateContextOTPRetryCount increments existing counter")
    public void testUpdateContextOTPRetryCount_Increments() {

        AuthenticationContext context = new AuthenticationContext();
        context.setProperty(DEFAULT_OTP_RETRY_ATTEMPTS_CONTEXT_PROPERTY_NAME, 4);
        authenticator.updateContextOTPRetryCount(context);
        Assert.assertEquals(context.getProperty(DEFAULT_OTP_RETRY_ATTEMPTS_CONTEXT_PROPERTY_NAME), 5);
    }

    @Test(description = "resetContextResendCount sets counter to 0")
    public void testResetContextResendCount() {

        AuthenticationContext context = new AuthenticationContext();
        context.setProperty(DEFAULT_OTP_RESEND_ATTEMPTS_CONTEXT_PROPERTY_NAME, 3);
        authenticator.resetContextResendCount(context);
        Assert.assertEquals(context.getProperty(DEFAULT_OTP_RESEND_ATTEMPTS_CONTEXT_PROPERTY_NAME), 0);
    }

    @Test(description = "resetContextRetryCount sets counter to 0")
    public void testResetContextRetryCount() {

        AuthenticationContext context = new AuthenticationContext();
        context.setProperty(DEFAULT_OTP_RETRY_ATTEMPTS_CONTEXT_PROPERTY_NAME, 7);
        authenticator.resetContextRetryCount(context);
        Assert.assertEquals(context.getProperty(DEFAULT_OTP_RETRY_ATTEMPTS_CONTEXT_PROPERTY_NAME), 0);
    }

    @Test(description = "getCurrentResendAttempt returns 0 when counter is not set")
    public void testGetCurrentResendAttempt_WhenNotSet() {

        AuthenticationContext context = new AuthenticationContext();
        Assert.assertEquals(authenticator.getCurrentResendAttempt(context), 0);
    }

    @Test(description = "getCurrentResendAttempt returns the stored counter value")
    public void testGetCurrentResendAttempt_WhenSet() {

        AuthenticationContext context = new AuthenticationContext();
        context.setProperty(DEFAULT_OTP_RESEND_ATTEMPTS_CONTEXT_PROPERTY_NAME, 2);
        Assert.assertEquals(authenticator.getCurrentResendAttempt(context), 2);
    }

    @Test(description = "getCurrentRetryAttempt returns 0 when counter is not set")
    public void testGetCurrentRetryAttempt_WhenNotSet() {

        AuthenticationContext context = new AuthenticationContext();
        Assert.assertEquals(authenticator.getCurrentRetryAttempt(context), 0);
    }

    @Test(description = "getCurrentRetryAttempt returns the stored counter value")
    public void testGetCurrentRetryAttempt_WhenSet() {

        AuthenticationContext context = new AuthenticationContext();
        context.setProperty(DEFAULT_OTP_RETRY_ATTEMPTS_CONTEXT_PROPERTY_NAME, 3);
        Assert.assertEquals(authenticator.getCurrentRetryAttempt(context), 3);
    }

    @Test(description = "Counter is 0 when the context property is blank string")
    public void testGetCurrentRetryAttempt_WhenBlankString() {

        AuthenticationContext context = new AuthenticationContext();
        context.setProperty(DEFAULT_OTP_RETRY_ATTEMPTS_CONTEXT_PROPERTY_NAME, "");
        Assert.assertEquals(authenticator.getCurrentRetryAttempt(context), 0);
    }

    @Test(description = "updateContextOTPRetryCount initialises to 1 when the property is blank string")
    public void testUpdateContextOTPRetryCount_WhenBlankString() {

        AuthenticationContext context = new AuthenticationContext();
        context.setProperty(DEFAULT_OTP_RETRY_ATTEMPTS_CONTEXT_PROPERTY_NAME, "");
        authenticator.updateContextOTPRetryCount(context);
        Assert.assertEquals(context.getProperty(DEFAULT_OTP_RETRY_ATTEMPTS_CONTEXT_PROPERTY_NAME), 1);
    }

    @Test(description = "getResendAttemptsPropertyKey returns the default context property name")
    public void testGetResendAttemptsPropertyKey() {

        Assert.assertEquals(
                authenticator.getResendAttemptsPropertyKey(),
                DEFAULT_OTP_RESEND_ATTEMPTS_CONTEXT_PROPERTY_NAME);
    }

    @Test(description = "getRetryAttemptsPropertyKey returns the default context property name")
    public void testGetRetryAttemptsPropertyKey() {

        Assert.assertEquals(
                authenticator.getRetryAttemptsPropertyKey(),
                DEFAULT_OTP_RETRY_ATTEMPTS_CONTEXT_PROPERTY_NAME);
    }

    @Test(description = "getMaximumResendAttempts returns context runtime param value when context-based blocking is enabled")
    public void testGetMaximumResendAttempts_WithContextParam()
            throws AuthenticationFailedException {

        AuthenticationContext context = createContextWithRuntimeParams(
                MAXIMUM_RESEND_LIMIT, "7");
        int result = authenticator.getMaximumResendAttempts(TENANT_DOMAIN, context);
        Assert.assertEquals(result, 7);
    }

    @Test(description = "getMaximumResendAttempts falls back to default when context-based blocking is disabled")
    public void testGetMaximumResendAttempts_FallsBackToDefault_WhenContextBlockingDisabled()
            throws AuthenticationFailedException {

        AuthenticationContext context = createContextWithRuntimeParams(null, null);
        int result = authenticator.getMaximumResendAttempts(TENANT_DOMAIN, context);
        Assert.assertEquals(result, AuthenticatorConstants.DEFAULT_OTP_RESEND_ATTEMPTS);
    }

    @Test(description = "getMaximumResendAttempts with negative MAXIMUM_RESEND_LIMIT falls back to default")
    public void testGetMaximumResendAttempts_WithNegativeContextParam_FallsBackToDefault()
            throws AuthenticationFailedException {

        // Negative value means context-based blocking is disabled, so falls back to default.
        AuthenticationContext context = createContextWithRuntimeParams(
                MAXIMUM_RESEND_LIMIT, "-1");
        int result = authenticator.getMaximumResendAttempts(TENANT_DOMAIN, context);
        Assert.assertEquals(result, AuthenticatorConstants.DEFAULT_OTP_RESEND_ATTEMPTS);
    }

    @Test(description = "getMaximumRetryAttempts returns context runtime param value when context-based blocking is enabled")
    public void testGetMaximumRetryAttempts_WithContextParam()
            throws AuthenticationFailedException {

        AuthenticationContext context = createContextWithRuntimeParams(
                MAXIMUM_ALLOWED_FAILURE_LIMIT, "4");
        int result = authenticator.getMaximumRetryAttempts(TENANT_DOMAIN, context);
        Assert.assertEquals(result, 4);
    }

    @Test(description = "getMaximumRetryAttempts returns Integer.MAX_VALUE when context-based blocking is disabled")
    public void testGetMaximumRetryAttempts_FallsBackToMaxInt_WhenContextBlockingDisabled()
            throws AuthenticationFailedException {

        AuthenticationContext context = createContextWithRuntimeParams(null, null);
        int result = authenticator.getMaximumRetryAttempts(TENANT_DOMAIN, context);
        Assert.assertEquals(result, Integer.MAX_VALUE);
    }

    @Test(description = "getMaximumRetryAttempts returns Integer.MAX_VALUE when MAXIMUM_ALLOWED_FAILURE_LIMIT is zero (blocking disabled)")
    public void testGetMaximumRetryAttempts_WithZeroLimit_ReturnsMaxInt()
            throws AuthenticationFailedException {

        // Zero is invalid for retry (must be > 0), so context-based blocking is disabled
        AuthenticationContext context = createContextWithRuntimeParams(
                MAXIMUM_ALLOWED_FAILURE_LIMIT, "0");
        int result = authenticator.getMaximumRetryAttempts(TENANT_DOMAIN, context);
        Assert.assertEquals(result, Integer.MAX_VALUE);
    }

    @Test(description = "handleOTPRetryCountExceededScenario sets SKIP_RETRY_FROM_AUTHENTICATOR=true and AUTH_ERROR_CODE")
    public void testHandleOTPRetryCountExceededScenario_SetsContextProperties() throws Exception {

        AuthenticationContext context = new AuthenticationContext();
        invokePrivateVoidMethod("handleOTPRetryCountExceededScenario",
                new Class[]{AuthenticationContext.class},
                new Object[]{context});
        Assert.assertNotNull(context.getProperty(FrameworkConstants.AUTH_ERROR_CODE));
        Assert.assertEquals(context.getProperty(FrameworkConstants.AUTH_ERROR_CODE),
                FrameworkConstants.ERROR_STATUS_ALLOWED_RETRY_LIMIT_EXCEEDED);
    }

    @Test(description = "handleOTPResendCountExceededScenario with terminateFlow=true sets AUTH_ERROR_CODE and throws")
    public void testHandleOTPResendCountExceededScenario_TerminateFlow_WithUser() throws Exception {

        AuthenticationContext context = new AuthenticationContext();
        context.setRetrying(true);
        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserName("testUser");
        user.setTenantDomain(TENANT_DOMAIN);

        try {
            invokePrivateVoidMethod(
                    "handleOTPResendCountExceededScenario",
                    new Class[]{HttpServletRequest.class, HttpServletResponse.class,
                            AuthenticationContext.class, AuthenticatedUser.class, boolean.class},
                    new Object[]{null, null, context, user, true});
            Assert.fail("Expected AuthenticationFailedException was not thrown");
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            Assert.assertTrue(cause instanceof AuthenticationFailedException,
                    "Expected AuthenticationFailedException but got: " + cause.getClass().getName());
            Assert.assertEquals(context.getProperty(FrameworkConstants.AUTH_ERROR_CODE),
                    FrameworkConstants.ERROR_STATUS_ALLOWED_RESEND_LIMIT_EXCEEDED);
            Assert.assertFalse(context.isRetrying(),
                    "context.isRetrying() should be false after terminate-flow path");
        }
    }

    @Test(description = "handleOTPResendCountExceededScenario with terminateFlow=true and null user throws with UNKNOWN_USER")
    public void testHandleOTPResendCountExceededScenario_TerminateFlow_WithNullUser() throws Exception {

        AuthenticationContext context = new AuthenticationContext();
        context.setRetrying(true);

        try {
            invokePrivateVoidMethod(
                    "handleOTPResendCountExceededScenario",
                    new Class[]{HttpServletRequest.class, HttpServletResponse.class,
                            AuthenticationContext.class, AuthenticatedUser.class, boolean.class},
                    new Object[]{null, null, context, null, true});
            Assert.fail("Expected AuthenticationFailedException was not thrown");
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            Assert.assertTrue(cause instanceof AuthenticationFailedException,
                    "Expected AuthenticationFailedException but got: " + cause.getClass().getName());
            AuthenticationFailedException authEx = (AuthenticationFailedException) cause;
            Assert.assertTrue(authEx.getMessage().contains(AuthenticatorConstants.UNKNOWN_USER),
                    "Error message should reference UNKNOWN_USER. Actual: " + authEx.getMessage());
            Assert.assertEquals(context.getProperty(FrameworkConstants.AUTH_ERROR_CODE),
                    FrameworkConstants.ERROR_STATUS_ALLOWED_RESEND_LIMIT_EXCEEDED);
        }
    }

    @Test(description = "Full resend counter lifecycle: init, increment, read, reset")
    public void testResendCounterFullLifecycle() {

        AuthenticationContext context = new AuthenticationContext();

        // Initially zero
        Assert.assertEquals(authenticator.getCurrentResendAttempt(context), 0);

        // First update → 1
        authenticator.updateContextOTPResendCount(context);
        Assert.assertEquals(authenticator.getCurrentResendAttempt(context), 1);

        // Second update → 2
        authenticator.updateContextOTPResendCount(context);
        Assert.assertEquals(authenticator.getCurrentResendAttempt(context), 2);

        // Third update → 3
        authenticator.updateContextOTPResendCount(context);
        Assert.assertEquals(authenticator.getCurrentResendAttempt(context), 3);

        // Reset → 0
        authenticator.resetContextResendCount(context);
        Assert.assertEquals(authenticator.getCurrentResendAttempt(context), 0);
    }

    @Test(description = "Full retry counter lifecycle: init, increment, read, reset")
    public void testRetryCounterFullLifecycle() {

        AuthenticationContext context = new AuthenticationContext();

        // Initially zero
        Assert.assertEquals(authenticator.getCurrentRetryAttempt(context), 0);

        // First update → 1
        authenticator.updateContextOTPRetryCount(context);
        Assert.assertEquals(authenticator.getCurrentRetryAttempt(context), 1);

        // Second update → 2
        authenticator.updateContextOTPRetryCount(context);
        Assert.assertEquals(authenticator.getCurrentRetryAttempt(context), 2);

        // Reset → 0
        authenticator.resetContextRetryCount(context);
        Assert.assertEquals(authenticator.getCurrentRetryAttempt(context), 0);
    }


    @Test(description = "isOTPResendLimitExceeded returns true when current resend count equals the limit")
    public void testIsOTPResendLimitExceeded_WhenAtLimit() throws Exception {

        AuthenticationContext context = createContextWithRuntimeParams(MAXIMUM_RESEND_LIMIT, "3");
        // Set current resend count to 3 (= limit)
        context.setProperty(DEFAULT_OTP_RESEND_ATTEMPTS_CONTEXT_PROPERTY_NAME, 3);

        boolean result = invokePrivateBooleanMethod(
                "isOTPResendLimitExceeded",
                new Class[]{AuthenticationContext.class, String.class},
                new Object[]{context, TENANT_DOMAIN});

        Assert.assertTrue(result);
    }

    @Test(description = "isOTPResendLimitExceeded returns true when current resend count exceeds the limit")
    public void testIsOTPResendLimitExceeded_WhenExceedsLimit() throws Exception {

        AuthenticationContext context = createContextWithRuntimeParams(MAXIMUM_RESEND_LIMIT, "3");
        context.setProperty(DEFAULT_OTP_RESEND_ATTEMPTS_CONTEXT_PROPERTY_NAME, 5);

        boolean result = invokePrivateBooleanMethod(
                "isOTPResendLimitExceeded",
                new Class[]{AuthenticationContext.class, String.class},
                new Object[]{context, TENANT_DOMAIN});

        Assert.assertTrue(result);
    }

    @Test(description = "isOTPResendLimitExceeded returns false when current resend count is below the limit")
    public void testIsOTPResendLimitExceeded_WhenBelowLimit() throws Exception {

        AuthenticationContext context = createContextWithRuntimeParams(MAXIMUM_RESEND_LIMIT, "3");
        context.setProperty(DEFAULT_OTP_RESEND_ATTEMPTS_CONTEXT_PROPERTY_NAME, 1);
        boolean result = invokePrivateBooleanMethod(
                "isOTPResendLimitExceeded",
                new Class[]{AuthenticationContext.class, String.class},
                new Object[]{context, TENANT_DOMAIN});

        Assert.assertFalse(result);
    }

    @Test(description = "isOTPResendLimitExceeded uses default resend attempts when context-based blocking is off")
    public void testIsOTPResendLimitExceeded_WhenContextBlockingDisabled_UsesDefault() throws Exception {

        // No MAXIMUM_RESEND_LIMIT param → context-based blocking is off → falls back to default (5)
        AuthenticationContext context = createContextWithRuntimeParams(null, null);
        // Set count below default (5)
        context.setProperty(DEFAULT_OTP_RESEND_ATTEMPTS_CONTEXT_PROPERTY_NAME, 2);
        boolean result = invokePrivateBooleanMethod(
                "isOTPResendLimitExceeded",
                new Class[]{AuthenticationContext.class, String.class},
                new Object[]{context, TENANT_DOMAIN});

        Assert.assertFalse(result);
    }

    @Test(description = "handleInvalidOTPLoginAttempt increments retry counter when context-based blocking is enabled")
    public void testHandleInvalidOTPLoginAttempt_IncrementsCounter() throws Exception {

        AuthenticationContext context = createContextWithRuntimeParams(
                MAXIMUM_ALLOWED_FAILURE_LIMIT, "5");
        invokePrivateVoidMethod(
                "handleInvalidOTPLoginAttempt",
                new Class[]{AuthenticationContext.class, String.class},
                new Object[]{context, TENANT_DOMAIN});
        Assert.assertEquals(authenticator.getCurrentRetryAttempt(context), 1);
    }

    @Test(description = "handleInvalidOTPLoginAttempt does NOT increment retry counter when context-based blocking is disabled")
    public void testHandleInvalidOTPLoginAttempt_DoesNotIncrementWhenDisabled() throws Exception {

        AuthenticationContext context = createContextWithRuntimeParams(null, null);
        invokePrivateVoidMethod(
                "handleInvalidOTPLoginAttempt",
                new Class[]{AuthenticationContext.class, String.class},
                new Object[]{context, TENANT_DOMAIN});

        Assert.assertEquals(authenticator.getCurrentRetryAttempt(context), 0);
    }

    @Test(description = "handleInvalidOTPLoginAttempt sets AUTH_ERROR_CODE when retry count reaches the limit")
    public void testHandleInvalidOTPLoginAttempt_SetsErrorCodeWhenLimitReached() throws Exception {

        // Limit = 3, set current = 2 so that after increment it becomes 3 = limit
        AuthenticationContext context = createContextWithRuntimeParams(
                MAXIMUM_ALLOWED_FAILURE_LIMIT, "3");
        context.setProperty(DEFAULT_OTP_RETRY_ATTEMPTS_CONTEXT_PROPERTY_NAME, 2);
        invokePrivateVoidMethod(
                "handleInvalidOTPLoginAttempt",
                new Class[]{AuthenticationContext.class, String.class},
                new Object[]{context, TENANT_DOMAIN});
        Assert.assertEquals(context.getProperty(FrameworkConstants.AUTH_ERROR_CODE),
                FrameworkConstants.ERROR_STATUS_ALLOWED_RETRY_LIMIT_EXCEEDED);
    }

    @Test(description = "handleInvalidOTPLoginAttempt does NOT set AUTH_ERROR_CODE when retry count is below the limit")
    public void testHandleInvalidOTPLoginAttempt_NoErrorCodeWhenBelowLimit() throws Exception {

        // Limit = 5, current = 0 → after increment becomes 1 < 5
        AuthenticationContext context = createContextWithRuntimeParams(
                MAXIMUM_ALLOWED_FAILURE_LIMIT, "5");
        invokePrivateVoidMethod(
                "handleInvalidOTPLoginAttempt",
                new Class[]{AuthenticationContext.class, String.class},
                new Object[]{context, TENANT_DOMAIN});
        Assert.assertNull(context.getProperty(FrameworkConstants.AUTH_ERROR_CODE));
    }

    @Test(description = "getRemainingNumberOfContextBasedRetryAttempts returns correct remaining count")
    public void testGetRemainingNumberOfContextBasedRetryAttempts_Normal() throws Exception {

        // max = 5, current = 2 → remaining = 3
        AuthenticationContext context = createContextWithRuntimeParams(
                MAXIMUM_ALLOWED_FAILURE_LIMIT, "5");
        context.setProperty(DEFAULT_OTP_RETRY_ATTEMPTS_CONTEXT_PROPERTY_NAME, 2);
        context.setTenantDomain(TENANT_DOMAIN);
        int remaining = invokePrivateIntMethod(
                "getRemainingNumberOfContextBasedRetryAttempts",
                new Class[]{String.class, AuthenticationContext.class},
                new Object[]{TENANT_DOMAIN, context});
        Assert.assertEquals(remaining, 3);
    }

    @Test(description = "getRemainingNumberOfContextBasedRetryAttempts returns 0 when current equals max")
    public void testGetRemainingNumberOfContextBasedRetryAttempts_WhenAtMax() throws Exception {

        // max = 3, current = 3 → remaining = 0
        AuthenticationContext context = createContextWithRuntimeParams(
                MAXIMUM_ALLOWED_FAILURE_LIMIT, "3");
        context.setProperty(DEFAULT_OTP_RETRY_ATTEMPTS_CONTEXT_PROPERTY_NAME, 3);
        context.setTenantDomain(TENANT_DOMAIN);
        int remaining = invokePrivateIntMethod(
                "getRemainingNumberOfContextBasedRetryAttempts",
                new Class[]{String.class, AuthenticationContext.class},
                new Object[]{TENANT_DOMAIN, context});
        Assert.assertEquals(remaining, 0);
    }

    @Test(description = "getRemainingNumberOfContextBasedRetryAttempts returns 0 (not negative) when over limit")
    public void testGetRemainingNumberOfContextBasedRetryAttempts_WhenOverMax() throws Exception {

        // max = 3, current = 5 → remaining = max(3-5, 0) = 0
        AuthenticationContext context = createContextWithRuntimeParams(
                MAXIMUM_ALLOWED_FAILURE_LIMIT, "3");
        context.setProperty(DEFAULT_OTP_RETRY_ATTEMPTS_CONTEXT_PROPERTY_NAME, 5);
        context.setTenantDomain(TENANT_DOMAIN);
        int remaining = invokePrivateIntMethod(
                "getRemainingNumberOfContextBasedRetryAttempts",
                new Class[]{String.class, AuthenticationContext.class},
                new Object[]{TENANT_DOMAIN, context});
        Assert.assertEquals(remaining, 0);
    }

    @Test(description = "Both resend and retry limits can be set simultaneously in runtime params")
    public void testBothResendAndRetryLimitsCanCoexist() throws AuthenticationFailedException {

        Map<String, String> params = new HashMap<>();
        params.put(MAXIMUM_RESEND_LIMIT, "3");
        params.put(MAXIMUM_ALLOWED_FAILURE_LIMIT, "5");
        params.put(TERMINATE_ON_RESEND_LIMIT_EXCEEDED, "true");
        AuthenticationContext context = createContextWithMultipleRuntimeParams(params);
        Assert.assertTrue(authenticator.isContextBasedOTPResendBlockingEnabled(context));
        Assert.assertTrue(authenticator.isContextBasedRetryBlockingEnabled(context));
        Assert.assertTrue(authenticator.isTerminateOnResendLimitExceeded(context));
        Assert.assertEquals(authenticator.getMaximumResendAttempts(TENANT_DOMAIN, context), 3);
        Assert.assertEquals(authenticator.getMaximumRetryAttempts(TENANT_DOMAIN, context), 5);
    }

    @Test(description = "skipResendBlockTime=true disables user-based blocking regardless of other params")
    public void testSkipResendBlockTimeOverridesUserBasedBlocking() throws AuthenticationFailedException {

        Map<String, String> params = new HashMap<>();
        params.put(SKIP_RESEND_BLOCK_TIME, "true");
        params.put(MAXIMUM_RESEND_LIMIT, "3");
        AuthenticationContext context = createContextWithMultipleRuntimeParams(params);
        // User-based blocking is skipped
        Assert.assertFalse(authenticator.isUserBasedOTPResendBlockingEnabled(context));
        // Context-based blocking is still enabled independently
        Assert.assertTrue(authenticator.isContextBasedOTPResendBlockingEnabled(context));
    }

    /**
     * Creates an AuthenticationContext with a single runtime parameter injected
     * through the TestOTPAuthenticator's runtime params map.
     */
    private AuthenticationContext createContextWithRuntimeParams(String paramName, String paramValue) {

        AuthenticationContext context = new AuthenticationContext();
        context.setTenantDomain(TENANT_DOMAIN);
        if (paramName != null) {
            Map<String, String> params = new HashMap<>();
            params.put(paramName, paramValue);
            authenticator.setRuntimeParams(params);
        } else {
            authenticator.setRuntimeParams(new HashMap<>());
        }
        return context;
    }

    /**
     * Creates an AuthenticationContext with multiple runtime parameters.
     */
    private AuthenticationContext createContextWithMultipleRuntimeParams(Map<String, String> params) {

        AuthenticationContext context = new AuthenticationContext();
        context.setTenantDomain(TENANT_DOMAIN);
        authenticator.setRuntimeParams(params != null ? params : new HashMap<>());
        return context;
    }

    /**
     * Invokes a private void method on the authenticator via reflection.
     */
    private void invokePrivateVoidMethod(String methodName, Class<?>[] paramTypes, Object[] args) throws Exception {

        Method method = findPrivateMethod(AbstractOTPAuthenticator.class, methodName, paramTypes);
        method.invoke(authenticator, args);
    }

    /**
     * Invokes a private boolean method on the authenticator via reflection.
     */
    private boolean invokePrivateBooleanMethod(String methodName, Class<?>[] paramTypes, Object[] args)
            throws Exception {

        Method method = findPrivateMethod(AbstractOTPAuthenticator.class, methodName, paramTypes);
        return (boolean) method.invoke(authenticator, args);
    }

    /**
     * Invokes a private int method on the authenticator via reflection.
     */
    private int invokePrivateIntMethod(String methodName, Class<?>[] paramTypes, Object[] args)
            throws Exception {

        Method method = findPrivateMethod(AbstractOTPAuthenticator.class, methodName, paramTypes);
        return (int) method.invoke(authenticator, args);
    }

    /**
     * Finds a private/protected method, searching up the class hierarchy.
     */
    private Method findPrivateMethod(Class<?> clazz, String methodName, Class<?>[] paramTypes) throws Exception {

        try {
            Method method = clazz.getDeclaredMethod(methodName, paramTypes);
            method.setAccessible(true);
            return method;
        } catch (NoSuchMethodException e) {
            if (clazz.getSuperclass() != null) {
                return findPrivateMethod(clazz.getSuperclass(), methodName, paramTypes);
            }
            throw e;
        }
    }

    /**
     * Minimal concrete implementation of {@link AbstractOTPAuthenticator} for unit testing.
     * Exposes {@code setRuntimeParams} so tests can inject runtime parameters without
     * needing a full authentication framework context.
     */
    private static class TestOTPAuthenticator extends AbstractOTPAuthenticator {

        private Map<String, String> runtimeParams = new HashMap<>();

        /**
         * Inject runtime parameters that will be returned by {@code getRuntimeParams(context)}.
         */
        public void setRuntimeParams(Map<String, String> params) {

            this.runtimeParams = params;
        }

        @Override
        public Map<String, String> getRuntimeParams(AuthenticationContext context) {

            return runtimeParams;
        }

        @Override
        protected String getAuthenticatorErrorPrefix() {

            return ERROR_CODE_PREFIX;
        }

        @Override
        protected void sendOtp(AuthenticatedUser authenticatedUser, OTP otp, boolean isInitialFederationAttempt,
                               HttpServletRequest request, HttpServletResponse response,
                               AuthenticationContext context) {
            // No-op for testing.
        }

        @Override
        protected String getMaskedUserClaimValue(AuthenticatedUser authenticatedUser, String tenantDomain,
                                                 boolean isInitialFederationAttempt,
                                                 AuthenticationContext context) {

            return "***masked***";
        }

        @Override
        protected void publishPostOTPValidatedEvent(OTP otpInfo, AuthenticatedUser authenticatedUser,
                                                    boolean isAuthenticationPassed, boolean isExpired,
                                                    HttpServletRequest request, AuthenticationContext context) {
            // No-op for testing.
        }

        @Override
        protected void publishPostOTPGeneratedEvent(OTP otpInfo, AuthenticatedUser authenticatedUser,
                                                    HttpServletRequest request, AuthenticationContext context) {
            // No-op for testing.
        }

        @Override
        protected String getErrorPageURL(AuthenticationContext context) {

            return "https://localhost:9443/authenticationendpoint/error.do";
        }

        @Override
        protected String getOTPLoginPageURL(AuthenticationContext context) {

            return "https://localhost:9443/authenticationendpoint/otp.jsp";
        }

        @Override
        public boolean canHandle(HttpServletRequest request) {

            return false;
        }

        @Override
        public String getContextIdentifier(HttpServletRequest request) {

            return "";
        }

        @Override
        public String getName() {

            return "TestOTPAuthenticator";
        }

        @Override
        public String getFriendlyName() {

            return "Test OTP Authenticator";
        }
    }
}

