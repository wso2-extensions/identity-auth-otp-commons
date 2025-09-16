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

import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.auth.otp.core.constant.OTPExecutorConstants;
import org.wso2.carbon.identity.auth.otp.core.internal.AuthenticatorDataHolder;
import org.wso2.carbon.identity.auth.otp.core.model.OTP;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineException;
import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;

import java.util.HashMap;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.wso2.carbon.identity.auth.otp.core.constant.OTPExecutorConstants.OTP_LENGTH;
import static org.wso2.carbon.identity.auth.otp.core.constant.OTPExecutorConstants.OTP_RETRY_COUNT;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.GENERATED_OTP;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.OTP_STATUS;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.OTP_USED_TIME;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_COMPLETE;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_ERROR;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_RETRY;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_USER_ERROR;

/**
 * Abstract OTP executor test class.
 */
public class AbstractOTPExecutorTest {

    private TestOTPExecutor testOTPExecutor;
    private FlowExecutionContext flowExecutionContext;
    private ExecutorResponse response;

    @Mock
    private IdentityEventService identityEventService;
    private MockedStatic<AuthenticatorDataHolder> dataHolderMockedStatic;
    private MockedStatic<LoggerUtils> loggerUtilsMockedStatic;

    private static final String CARBON_SUPER = "carbon.super";

    @BeforeClass
    public void setUp() throws IdentityEventException {

        testOTPExecutor = new TestOTPExecutor();
        dataHolderMockedStatic = mockStatic(AuthenticatorDataHolder.class);
        loggerUtilsMockedStatic = mockStatic(LoggerUtils.class);
        identityEventService = mock(IdentityEventService.class);
        doNothing().when(identityEventService).handleEvent(any());
        dataHolderMockedStatic.when(AuthenticatorDataHolder::getIdentityEventService).thenReturn(identityEventService);
        loggerUtilsMockedStatic.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(false);
    }

    @BeforeMethod
    public void setUpMethod() {

        flowExecutionContext = new FlowExecutionContext();
        flowExecutionContext.setTenantDomain(CARBON_SUPER);
        response = new ExecutorResponse();
        response.setContextProperty(new HashMap<>());
    }

    @AfterClass
    public void tearDown() {

        if (dataHolderMockedStatic != null) {
            dataHolderMockedStatic.close();
        }
        if (loggerUtilsMockedStatic != null) {
            loggerUtilsMockedStatic.close();
        }
    }

    @Test
    public void testExecute() {

    }

    @Test
    public void testIsInitiateRequest() {

        boolean result = testOTPExecutor.isInitiateRequest(flowExecutionContext);
        Assert.assertTrue(result);
        flowExecutionContext.getUserInputData().put(OTPExecutorConstants.OTP, "1234");
        result = testOTPExecutor.isInitiateRequest(flowExecutionContext);
        Assert.assertFalse(result);
    }

    @Test
    public void testInitiateExecution() throws FlowEngineException {

        response.setContextProperty(new HashMap<>());
        testOTPExecutor.initiateExecution(flowExecutionContext, response);
        Assert.assertNotNull(response.getContextProperties().get(OTPExecutorConstants.OTP));
        Assert.assertNotNull(response.getRequiredData().get(0));
        Assert.assertEquals(response.getRequiredData().get(0), OTPExecutorConstants.OTP);
    }

    @Test
    public void testProcessResponse() {

    }

    @Test
    public void testHandleMaxRetryCount() throws FlowEngineException {

        testOTPExecutor.handleMaxRetryCount(flowExecutionContext, response);
        Assert.assertNotEquals(response.getResult(), STATUS_USER_ERROR);
        flowExecutionContext.setProperty(OTP_RETRY_COUNT, 3);
        testOTPExecutor.handleMaxRetryCount(flowExecutionContext, response);
        Assert.assertEquals(response.getResult(), STATUS_USER_ERROR);
    }

    @Test
    public void testHandleRetry() throws FlowEngineException {

        testOTPExecutor.handleRetry(flowExecutionContext, response);
        Assert.assertEquals(response.getContextProperties().get(OTP_RETRY_COUNT), 1);
        response.setResult(STATUS_RETRY);
        testOTPExecutor.handleRetry(flowExecutionContext, response);
        Assert.assertEquals(response.getContextProperties().get(OTP_RETRY_COUNT), 1);
    }

    @Test
    public void testHandleRetryExpiredOTP() throws FlowEngineException {

        response.setResult(STATUS_RETRY);
        flowExecutionContext.setProperty(OTPExecutorConstants.OTP, new OTP("123456", 0, 0));
        testOTPExecutor.handleRetry(flowExecutionContext, response);
        Assert.assertNull(response.getContextProperties().get(OTP_RETRY_COUNT));
    }

    @Test
    public void testGenerateOTP() throws FlowEngineException {

        OTP otp = testOTPExecutor.generateOTP(CARBON_SUPER);
        Assert.assertNotNull(otp);
        Assert.assertEquals(otp.getValue().length(), 6);
    }

    @Test
    public void testTriggerOTP() throws FlowEngineException {

        testOTPExecutor.triggerOTP(OTPExecutorConstants.OTPScenarios.INITIAL_OTP,
                flowExecutionContext, response);
        Assert.assertNotNull(response.getContextProperties().get(OTPExecutorConstants.OTP));
        Assert.assertNotNull(response.getAdditionalInfo().get(OTP_LENGTH));
        Assert.assertEquals(response.getAdditionalInfo().get(OTP_LENGTH), "6");
    }

    @Test
    public void testPublishPostOTPGeneratedEvent() throws IdentityEventException, FlowEngineException {

        ArgumentCaptor<Event> captor = ArgumentCaptor.forClass(Event.class);

        OTP otp = testOTPExecutor.generateOTP(CARBON_SUPER);
        flowExecutionContext.setProperty(OTPExecutorConstants.OTP, otp);
        testOTPExecutor.publishPostOTPGeneratedEvent(OTPExecutorConstants.OTPScenarios.INITIAL_OTP,
                flowExecutionContext, response);
        verify(identityEventService, atLeastOnce()).handleEvent(captor.capture());
        Assert.assertNotNull(captor.getValue());
        Assert.assertNotNull(captor.getValue().getEventProperties());
        Assert.assertEquals(captor.getValue().getEventProperties().get(GENERATED_OTP), otp.getValue());
    }

    @Test
    public void testPublishPostOTPValidationEventSuccess() throws FlowEngineException, IdentityEventException {

        ArgumentCaptor<Event> captor = ArgumentCaptor.forClass(Event.class);
        OTP otp = testOTPExecutor.generateOTP(CARBON_SUPER);
        flowExecutionContext.setProperty(OTPExecutorConstants.OTP, otp);
        testOTPExecutor.publishPostOTPValidationEvent(flowExecutionContext, true, false, response);
        verify(identityEventService, atLeastOnce()).handleEvent(captor.capture());
        Assert.assertNotNull(captor.getValue());
        Assert.assertNotNull(captor.getValue().getEventProperties());
        Assert.assertEquals(captor.getValue().getEventProperties().get(OTP_STATUS),
                OTPExecutorConstants.Status.SUCCESS);
        Assert.assertNotNull(captor.getValue().getEventProperties().get(OTP_USED_TIME));
    }

    @Test
    public void testPublishPostOTPValidationEventAuthFailed() throws FlowEngineException, IdentityEventException {

        ArgumentCaptor<Event> captor = ArgumentCaptor.forClass(Event.class);
        OTP otp = testOTPExecutor.generateOTP(CARBON_SUPER);
        flowExecutionContext.setProperty(OTPExecutorConstants.OTP, otp);
        testOTPExecutor.publishPostOTPValidationEvent(flowExecutionContext, false, false, response);
        verify(identityEventService, atLeastOnce()).handleEvent(captor.capture());
        Assert.assertNotNull(captor.getValue());
        Assert.assertNotNull(captor.getValue().getEventProperties());
        Assert.assertEquals(captor.getValue().getEventProperties().get(OTP_STATUS),
                OTPExecutorConstants.Status.CODE_MISMATCH);
        Assert.assertNotNull(captor.getValue().getEventProperties().get(OTP_USED_TIME));
    }

    @Test
    public void testPublishPostOTPValidationEventExpired() throws FlowEngineException, IdentityEventException {

        ArgumentCaptor<Event> captor = ArgumentCaptor.forClass(Event.class);
        OTP otp = testOTPExecutor.generateOTP(CARBON_SUPER);
        flowExecutionContext.setProperty(OTPExecutorConstants.OTP, otp);
        testOTPExecutor.publishPostOTPValidationEvent(flowExecutionContext, false, true, response);
        verify(identityEventService, atLeastOnce()).handleEvent(captor.capture());
        Assert.assertNotNull(captor.getValue());
        Assert.assertNotNull(captor.getValue().getEventProperties());
        Assert.assertEquals(captor.getValue().getEventProperties().get(OTP_STATUS),
                OTPExecutorConstants.Status.OTP_EXPIRED);
        Assert.assertNotNull(captor.getValue().getEventProperties().get(OTP_USED_TIME));
    }

    @Test
    public void testProcessResponseValidOTP() throws FlowEngineException {

        OTP otp = new OTP("123456", System.currentTimeMillis(), 60000);
        flowExecutionContext.setProperty(OTPExecutorConstants.OTP, otp);
        flowExecutionContext.getUserInputData().put(OTPExecutorConstants.OTP, "123456");
        testOTPExecutor.processResponse(flowExecutionContext, response);
        Assert.assertEquals(response.getResult(), STATUS_COMPLETE);
        Assert.assertNull(response.getContextProperties().get(OTPExecutorConstants.OTP));
    }

    @Test
    public void testProcessResponseBlankOTP() throws FlowEngineException {

        flowExecutionContext.getUserInputData().put(OTPExecutorConstants.OTP, "");
        testOTPExecutor.processResponse(flowExecutionContext, response);
        Assert.assertEquals(response.getResult(), STATUS_RETRY);
    }

    @Test
    public void testProcessResponseOTPMissingInContext() throws FlowEngineException {

        flowExecutionContext.getUserInputData().put(OTPExecutorConstants.OTP, "123456");
        testOTPExecutor.processResponse(flowExecutionContext, response);
        Assert.assertEquals(response.getResult(), STATUS_ERROR);
        Assert.assertEquals(response.getErrorMessage(), "OTP is not generated.");
    }

    @Test
    public void testProcessResponseWithExpiredOTP() throws FlowEngineException {

        OTP otp = new OTP("123456", 0, 1);
        flowExecutionContext.setProperty(OTPExecutorConstants.OTP, otp);
        flowExecutionContext.getUserInputData().put(OTPExecutorConstants.OTP, "123456");
        testOTPExecutor.processResponse(flowExecutionContext, response);
        Assert.assertEquals(response.getResult(), STATUS_RETRY);
    }

    @Test
    public void testProcessResponseWithIncorrectOTP() throws FlowEngineException {

        OTP otp = new OTP("123456", System.currentTimeMillis(), 60000);
        flowExecutionContext.setProperty(OTPExecutorConstants.OTP, otp);
        flowExecutionContext.getUserInputData().put(OTPExecutorConstants.OTP, "654321");
        testOTPExecutor.processResponse(flowExecutionContext, response);
        Assert.assertEquals(response.getResult(), STATUS_RETRY);
    }

    @Test
    public void testPublishPostOTPGeneratedEventNoOTP() throws FlowEngineException, IdentityEventException {

        testOTPExecutor.publishPostOTPGeneratedEvent(OTPExecutorConstants.OTPScenarios.INITIAL_OTP,
                flowExecutionContext, response);
        verify(identityEventService, atLeast(0)).handleEvent(any());
    }

    @Test(expectedExceptions = FlowEngineException.class)
    public void testTriggerOTPEventFailureHandling() throws Exception {

        IdentityEventService faultyService = mock(IdentityEventService.class);
        dataHolderMockedStatic.when(AuthenticatorDataHolder::getIdentityEventService).thenReturn(faultyService);
        doNothing().when(faultyService).handleEvent(any());

        TestOTPExecutor failingExecutor = new TestOTPExecutor() {
            @Override
            protected Event getSendOTPEvent(OTPExecutorConstants.OTPScenarios otpScenario, OTP otp,
                                            FlowExecutionContext context) throws FlowEngineException {

                throw new FlowEngineException("Simulated failure");
            }
        };
        failingExecutor.triggerOTP(OTPExecutorConstants.OTPScenarios.INITIAL_OTP, flowExecutionContext, response);
    }

    @Test
    public void testHandleRetryClearsRetryCountOnSuccess() throws FlowEngineException {

        response.setResult(STATUS_COMPLETE);
        response.getContextProperties().put(OTP_RETRY_COUNT, 2);
        testOTPExecutor.handleRetry(flowExecutionContext, response);
        Assert.assertNull(response.getContextProperties().get(OTP_RETRY_COUNT));
    }

    @Test
    public void testHandleMaxRetryCountExceeded() throws FlowEngineException {

        flowExecutionContext.setProperty(OTP_RETRY_COUNT, 5);
        testOTPExecutor.handleMaxRetryCount(flowExecutionContext, response);
        Assert.assertEquals(response.getResult(), STATUS_USER_ERROR);
        Assert.assertEquals(response.getErrorMessage(), "Maximum retry count exceeded.");
    }

    @Test
    public void testHandleAuthErrorScenarioFallbackMessage() {

        Exception e = new Exception("Test Exception");
        FlowEngineException ex = testOTPExecutor.handleAuthErrorScenario(e);
        Assert.assertTrue(ex.getDescription().contains("Error occurred in TestExecutor"));
    }
}
