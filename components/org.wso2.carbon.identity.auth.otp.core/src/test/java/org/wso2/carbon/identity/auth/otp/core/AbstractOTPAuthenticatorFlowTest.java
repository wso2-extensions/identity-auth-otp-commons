/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.auth.otp.core;

import org.mockito.MockedStatic;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ApplicationConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants;
import org.wso2.carbon.identity.auth.otp.core.internal.AuthenticatorDataHolder;
import org.wso2.carbon.identity.auth.otp.core.model.OTP;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.handler.event.account.lock.service.AccountLockService;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.captcha.util.CaptchaUtil;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.CODE;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.DEFAULT_OTP_RESEND_ATTEMPTS_CONTEXT_PROPERTY_NAME;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.DEFAULT_OTP_RETRY_ATTEMPTS_CONTEXT_PROPERTY_NAME;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.MAXIMUM_ALLOWED_FAILURE_LIMIT;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.MAXIMUM_RESEND_LIMIT;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.OTP;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.RESEND;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.USERNAME;

/**
 * Full-flow tests for {@link AbstractOTPAuthenticator}: process(), initiateAuthenticationRequest,
 * processAuthenticationResponse and context-based retry/resend control logic.
 */
public class AbstractOTPAuthenticatorFlowTest {

    private static final String ERROR_CODE_PREFIX = "OTP";
    private static final String TENANT_DOMAIN = "carbon.super";
    private static final String TEST_USER = "testuser";
    private static final String AUTHENTICATOR_NAME = "FlowTestOTPAuthenticator";

    private static final int TEST_TENANT_ID = -1234;

    private FlowTestOTPAuthenticator authenticator;
    private MockedStatic<LoggerUtils> loggerUtilsMockedStatic;
    private MockedStatic<AuthenticatorDataHolder> dataHolderMockedStatic;
    private MockedStatic<FrameworkUtils> frameworkUtilsMockedStatic;
    private MockedStatic<IdentityTenantUtil> identityTenantUtilMockedStatic;
    private MockedStatic<CaptchaUtil> captchaUtilMockedStatic;

    @BeforeMethod
    public void setUp() throws Exception {

        authenticator = new FlowTestOTPAuthenticator();
        loggerUtilsMockedStatic = mockStatic(LoggerUtils.class);
        loggerUtilsMockedStatic.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(false);

        dataHolderMockedStatic = mockStatic(AuthenticatorDataHolder.class);
        AccountLockService accountLockService = mock(AccountLockService.class);
        when(accountLockService.isAccountLocked(anyString(), anyString(), anyString())).thenReturn(false);
        dataHolderMockedStatic.when(AuthenticatorDataHolder::getAccountLockService).thenReturn(accountLockService);

        IdentityEventService identityEventService = mock(IdentityEventService.class);
        doNothing().when(identityEventService).handleEvent(any());
        dataHolderMockedStatic.when(AuthenticatorDataHolder::getIdentityEventService).thenReturn(identityEventService);

        UserRealm userRealm = mock(UserRealm.class);
        UserStoreManager userStoreManager = mock(UserStoreManager.class);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        RealmService realmService = mock(RealmService.class);
        when(realmService.getTenantUserRealm(TEST_TENANT_ID)).thenReturn(userRealm);
        dataHolderMockedStatic.when(AuthenticatorDataHolder::getRealmService).thenReturn(realmService);

        identityTenantUtilMockedStatic = mockStatic(IdentityTenantUtil.class);
        identityTenantUtilMockedStatic.when(() -> IdentityTenantUtil.getTenantId(anyString())).thenReturn(TEST_TENANT_ID);

        frameworkUtilsMockedStatic = mockStatic(FrameworkUtils.class);
        frameworkUtilsMockedStatic.when(() -> FrameworkUtils.getQueryStringWithFrameworkContextId(any(), any(), any()))
                .thenReturn("");
        frameworkUtilsMockedStatic.when(() -> FrameworkUtils.appendQueryParamsStringToUrl(anyString(), anyString()))
                .thenAnswer(inv -> inv.getArgument(0) + "?" + inv.getArgument(1));

        captchaUtilMockedStatic = mockStatic(CaptchaUtil.class);
        captchaUtilMockedStatic.when(CaptchaUtil::isReCaptchaEnabled).thenReturn(false);
    }

    @AfterMethod
    public void tearDown() {

        if (loggerUtilsMockedStatic != null) {
            loggerUtilsMockedStatic.close();
        }
        if (dataHolderMockedStatic != null) {
            dataHolderMockedStatic.close();
        }
        if (frameworkUtilsMockedStatic != null) {
            frameworkUtilsMockedStatic.close();
        }
        if (identityTenantUtilMockedStatic != null) {
            identityTenantUtilMockedStatic.close();
        }
        if (captchaUtilMockedStatic != null) {
            captchaUtilMockedStatic.close();
        }
    }

    @Test(description = "process() with LOGOUT scenario returns SUCCESS_COMPLETED")
    public void testProcess_LogoutScenario_ReturnsSuccessCompleted()
            throws AuthenticationFailedException, org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException {

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        AuthenticationContext context = new AuthenticationContext();
        context.setLogoutRequest(true);

        AuthenticatorFlowStatus status = authenticator.process(request, response, context);

        Assert.assertEquals(status, AuthenticatorFlowStatus.SUCCESS_COMPLETED);
    }

    @Test(description = "process() with INITIAL_OTP scenario returns INCOMPLETE and initiates OTP flow")
    public void testProcess_InitialOtpScenario_ReturnsIncompleteAndSetsOtpInContext()
            throws Exception {

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        when(request.getParameter(CODE)).thenReturn(null);
        when(request.getParameter(RESEND)).thenReturn(null);
        when(request.getParameter(USERNAME)).thenReturn(TEST_USER);
        doNothing().when(response).sendRedirect(anyString());

        AuthenticationContext context = createContextWithAuthenticatedUser(TEST_USER);
        context.setRetrying(false);
        context.setCurrentStep(1);

        AuthenticatorFlowStatus status = authenticator.process(request, response, context);

        Assert.assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
        Assert.assertNotNull(context.getProperty(OTP), "OTP should be set in context after initiateAuthenticationRequest");
    }

    @Test(description = "process() with SUBMIT_OTP and valid OTP returns SUCCESS_COMPLETED and resets retry/resend counts")
    public void testProcess_SubmitOtp_ValidOtp_SuccessCompleted_ResetsCounts()
            throws Exception {

        String otpValue = "123456";
        OTP otp = new OTP(otpValue, System.currentTimeMillis(), 300_000L);

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        when(request.getParameter(CODE)).thenReturn(otpValue);
        when(request.getParameter(RESEND)).thenReturn(null);
        when(request.getAttribute(FrameworkConstants.REQ_ATTR_HANDLED)).thenReturn(null);

        AuthenticationContext context = createContextWithAuthenticatedUser(TEST_USER);
        context.setRetrying(true);
        context.setCurrentStep(1);
        context.setProperty(OTP, otp);
        context.setProperty(DEFAULT_OTP_RETRY_ATTEMPTS_CONTEXT_PROPERTY_NAME, 1);
        context.setProperty(DEFAULT_OTP_RESEND_ATTEMPTS_CONTEXT_PROPERTY_NAME, 1);

        authenticator.setCanHandle(true);

        AuthenticatorFlowStatus status = authenticator.process(request, response, context);

        Assert.assertEquals(status, AuthenticatorFlowStatus.SUCCESS_COMPLETED);
        Assert.assertEquals(context.getProperty(DEFAULT_OTP_RETRY_ATTEMPTS_CONTEXT_PROPERTY_NAME), 0,
                "Retry count should be reset on success");
        Assert.assertEquals(context.getProperty(DEFAULT_OTP_RESEND_ATTEMPTS_CONTEXT_PROPERTY_NAME), 0,
                "Resend count should be reset on success");
    }

    @Test(description = "processAuthenticationResponse with invalid OTP and context-based retry enabled increments retry count (tests same logic as SUBMIT_OTP path)")
    public void testProcess_SubmitOtp_InvalidOtp_ContextRetryEnabled_IncrementsRetryCount()
            throws Exception {

        OTP otp = new OTP("123456", System.currentTimeMillis(), 300_000L);

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        when(request.getParameter(CODE)).thenReturn("wrong");
        when(request.getParameter(RESEND)).thenReturn(null);

        Map<String, String> runtimeParams = new HashMap<>();
        runtimeParams.put(MAXIMUM_ALLOWED_FAILURE_LIMIT, "5");
        authenticator.setRuntimeParams(runtimeParams);

        AuthenticationContext context = createContextWithAuthenticatedUser(TEST_USER);
        context.setProperty(OTP, otp);
        context.setTenantDomain(TENANT_DOMAIN);

        try {
            authenticator.processAuthenticationResponse(request, response, context);
            Assert.fail("Expected AuthenticationFailedException for invalid OTP");
        } catch (AuthenticationFailedException e) {
            // Expected.
        }
        Object retryCountObj = context.getProperty(DEFAULT_OTP_RETRY_ATTEMPTS_CONTEXT_PROPERTY_NAME);
        Assert.assertNotNull(retryCountObj, "Context retry count should be set when context-based retry is enabled");
        Assert.assertEquals(Integer.parseInt(retryCountObj.toString()), 1,
                "Context retry count should be incremented after invalid OTP");
    }

    @Test(description = "processAuthenticationResponse with invalid OTP when retry limit exceeded sets SKIP_RETRY and AUTH_ERROR_CODE (tests same logic as SUBMIT_OTP path)")
    public void testProcess_SubmitOtp_InvalidOtp_RetryLimitExceeded_SkipsRetryAndSetsErrorCode()
            throws Exception {

        OTP otp = new OTP("123456", System.currentTimeMillis(), 300_000L);

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        when(request.getParameter(CODE)).thenReturn("wrong");
        when(request.getParameter(RESEND)).thenReturn(null);

        Map<String, String> runtimeParams = new HashMap<>();
        runtimeParams.put(MAXIMUM_ALLOWED_FAILURE_LIMIT, "2");
        authenticator.setRuntimeParams(runtimeParams);

        AuthenticationContext context = createContextWithAuthenticatedUser(TEST_USER);
        context.setProperty(OTP, otp);
        context.setTenantDomain(TENANT_DOMAIN);
        context.setProperty(DEFAULT_OTP_RETRY_ATTEMPTS_CONTEXT_PROPERTY_NAME, 1);

        try {
            authenticator.processAuthenticationResponse(request, response, context);
            Assert.fail("Expected AuthenticationFailedException for invalid OTP");
        } catch (AuthenticationFailedException e) {
            // Expected.
        }
        Object retryCountObj = context.getProperty(DEFAULT_OTP_RETRY_ATTEMPTS_CONTEXT_PROPERTY_NAME);
        Assert.assertNotNull(retryCountObj);
        Assert.assertEquals(Integer.parseInt(retryCountObj.toString()), 2);
        Assert.assertEquals(context.getProperty(FrameworkConstants.AUTH_ERROR_CODE),
                FrameworkConstants.ERROR_STATUS_ALLOWED_RETRY_LIMIT_EXCEEDED);
        Assert.assertNotNull(context.getProperty(AbstractApplicationAuthenticator.SKIP_RETRY_FROM_AUTHENTICATOR));
    }

    @Test(description = "process() with RESEND_OTP and resend limit not exceeded increments resend count in initiate path")
    public void testProcess_ResendOtp_UnderLimit_IncrementsResendCount()
            throws Exception {

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        when(request.getParameter(CODE)).thenReturn(null);
        when(request.getParameter(RESEND)).thenReturn("true");
        when(request.getParameter(USERNAME)).thenReturn(TEST_USER);
        doNothing().when(response).sendRedirect(anyString());

        Map<String, String> runtimeParams = new HashMap<>();
        runtimeParams.put(MAXIMUM_RESEND_LIMIT, "5");
        authenticator.setRuntimeParams(runtimeParams);

        AuthenticationContext context = createContextWithAuthenticatedUser(TEST_USER);
        context.setRetrying(true);
        context.setCurrentStep(1);
        context.setProperty(DEFAULT_OTP_RESEND_ATTEMPTS_CONTEXT_PROPERTY_NAME, 0);

        Assert.assertEquals(authenticator.process(request, response, context), AuthenticatorFlowStatus.INCOMPLETE);
        Assert.assertEquals(authenticator.getCurrentResendAttempt(context), 1,
                "Resend count should be incremented on RESEND_OTP");
    }

    @Test(description = "process() with RESEND_OTP and resend limit exceeded with terminate=true sets AUTH_ERROR_CODE and throws")
    public void testProcess_ResendOtp_ResendLimitExceeded_Terminate_SetsErrorCodeAndThrows()
            throws Exception {

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        when(request.getParameter(CODE)).thenReturn(null);
        when(request.getParameter(RESEND)).thenReturn("true");
        when(request.getParameter(USERNAME)).thenReturn(TEST_USER);
        doNothing().when(response).sendRedirect(anyString());

        Map<String, String> runtimeParams = new HashMap<>();
        runtimeParams.put(MAXIMUM_RESEND_LIMIT, "2");
        runtimeParams.put(AuthenticatorConstants.TERMINATE_ON_RESEND_LIMIT_EXCEEDED, "true");
        authenticator.setRuntimeParams(runtimeParams);

        AuthenticationContext context = createContextWithAuthenticatedUser(TEST_USER);
        context.setRetrying(true);
        context.setCurrentStep(1);
        context.setProperty(DEFAULT_OTP_RESEND_ATTEMPTS_CONTEXT_PROPERTY_NAME, 2);

        try {
            authenticator.process(request, response, context);
            Assert.fail("Expected AuthenticationFailedException when resend limit exceeded with terminate=true");
        } catch (AuthenticationFailedException e) {
            Assert.assertNotNull(e.getErrorCode());
        }
        Assert.assertEquals(context.getProperty(FrameworkConstants.AUTH_ERROR_CODE),
                FrameworkConstants.ERROR_STATUS_ALLOWED_RESEND_LIMIT_EXCEEDED);
    }

    @Test(description = "initiateAuthenticationRequest sets OTP in context and updates resend count on RESEND_OTP")
    public void testInitiateAuthenticationRequest_ResendOtp_UpdatesResendCount()
            throws Exception {

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        when(request.getParameter(CODE)).thenReturn(null);
        when(request.getParameter(RESEND)).thenReturn("true");
        when(request.getParameter(USERNAME)).thenReturn(TEST_USER);
        doNothing().when(response).sendRedirect(anyString());

        Map<String, String> runtimeParams = new HashMap<>();
        runtimeParams.put(MAXIMUM_RESEND_LIMIT, "5");
        authenticator.setRuntimeParams(runtimeParams);

        AuthenticationContext context = createContextWithAuthenticatedUser(TEST_USER);
        context.setRetrying(true);
        context.setCurrentStep(1);

        authenticator.initiateAuthenticationRequest(request, response, context);

        Assert.assertNotNull(context.getProperty(OTP));
        Assert.assertEquals(authenticator.getCurrentResendAttempt(context), 1);
    }

    @Test(description = "processAuthenticationResponse with invalid OTP calls handleInvalidOTPLoginAttempt and increments retry when enabled")
    public void testProcessAuthenticationResponse_InvalidOtp_IncrementsRetryWhenEnabled()
            throws Exception {

        OTP otp = new OTP("123456", System.currentTimeMillis(), 300_000L);

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        when(request.getParameter(CODE)).thenReturn("wrong");
        when(request.getParameter(RESEND)).thenReturn(null);

        Map<String, String> runtimeParams = new HashMap<>();
        runtimeParams.put(MAXIMUM_ALLOWED_FAILURE_LIMIT, "5");
        authenticator.setRuntimeParams(runtimeParams);

        AuthenticationContext context = createContextWithAuthenticatedUser(TEST_USER);
        context.setProperty(OTP, otp);
        context.setTenantDomain(TENANT_DOMAIN);

        try {
            authenticator.processAuthenticationResponse(request, response, context);
            Assert.fail("Expected AuthenticationFailedException for invalid OTP");
        } catch (AuthenticationFailedException e) {
            Assert.assertTrue(e.getMessage().contains(AuthenticatorConstants.ErrorMessages.ERROR_CODE_OTP_INVALID.getMessage())
                    || e.getErrorCode() != null);
        }
        Assert.assertEquals(authenticator.getCurrentRetryAttempt(context), 1);
    }

    @Test(description = "processAuthenticationResponse with valid OTP resets retry and resend counts")
    public void testProcessAuthenticationResponse_ValidOtp_ResetsCounts()
            throws Exception {

        String otpValue = "123456";
        OTP otp = new OTP(otpValue, System.currentTimeMillis(), 300_000L);

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        when(request.getParameter(CODE)).thenReturn(otpValue);
        when(request.getParameter(RESEND)).thenReturn(null);

        AuthenticationContext context = createContextWithAuthenticatedUser(TEST_USER);
        context.setProperty(OTP, otp);
        context.setTenantDomain(TENANT_DOMAIN);
        context.setProperty(DEFAULT_OTP_RETRY_ATTEMPTS_CONTEXT_PROPERTY_NAME, 2);
        context.setProperty(DEFAULT_OTP_RESEND_ATTEMPTS_CONTEXT_PROPERTY_NAME, 1);

        authenticator.processAuthenticationResponse(request, response, context);
        Assert.assertEquals(authenticator.getCurrentRetryAttempt(context), 0);
        Assert.assertEquals(authenticator.getCurrentResendAttempt(context), 0);
    }

    private AuthenticationContext createContextWithAuthenticatedUser(String username) {

        AuthenticationContext context = new AuthenticationContext();
        context.setTenantDomain(TENANT_DOMAIN);

        SequenceConfig sequenceConfig = new SequenceConfig();
        ApplicationConfig appConfig = mock(ApplicationConfig.class);
        when(appConfig.isSaaSApp()).thenReturn(true);
        sequenceConfig.setApplicationConfig(appConfig);

        StepConfig stepConfig = new StepConfig();
        stepConfig.setOrder(1);
        stepConfig.setSubjectAttributeStep(true);
        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserName(username);
        user.setTenantDomain(TENANT_DOMAIN);
        user.setUserStoreDomain("PRIMARY");
        stepConfig.setAuthenticatedUser(user);
        context.setSubject(user);

        Map<Integer, StepConfig> stepMap = new HashMap<>();
        stepMap.put(1, stepConfig);
        sequenceConfig.setStepMap(stepMap);
        context.setSequenceConfig(sequenceConfig);
        context.setCurrentStep(1);
        context.setProperty(FrameworkConstants.AnalyticsData.DATA_MAP, new HashMap<String, Serializable>());

        return context;
    }

    /**
     * Test authenticator that allows configuring canHandle and runtime params for flow tests.
     */
    private static class FlowTestOTPAuthenticator extends AbstractOTPAuthenticator {

        private Map<String, String> runtimeParams = new HashMap<>();
        private boolean canHandle = false;

        void setRuntimeParams(Map<String, String> params) {

            this.runtimeParams = params != null ? params : new HashMap<>();
        }

        void setCanHandle(boolean canHandle) {

            this.canHandle = canHandle;
        }

        @Override
        public Map<String, String> getRuntimeParams(AuthenticationContext context) {

            return runtimeParams;
        }

        @Override
        public boolean canHandle(HttpServletRequest request) {

            return canHandle;
        }

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

            return "***";
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

            return "https://localhost/error.do";
        }

        @Override
        protected String getOTPLoginPageURL(AuthenticationContext context) {

            return "https://localhost/otp.jsp";
        }

        @Override
        public String getContextIdentifier(HttpServletRequest request) {

            return "ctx1";
        }

        @Override
        public String getName() {

            return AUTHENTICATOR_NAME;
        }

        @Override
        public String getFriendlyName() {

            return "Flow Test OTP";
        }
    }
}
