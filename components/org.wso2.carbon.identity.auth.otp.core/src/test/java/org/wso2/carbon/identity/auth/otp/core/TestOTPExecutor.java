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

import org.wso2.carbon.identity.auth.otp.core.constant.OTPExecutorConstants;
import org.wso2.carbon.identity.auth.otp.core.model.OTP;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.notification.NotificationConstants;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineException;
import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.CODE;

/**
 * Test implementation of AbstractOTPExecutor.
 */
public class TestOTPExecutor extends AbstractOTPExecutor {

    private static final String DEFAULT_CHARSET = "1234567890";
    private static final int DEFAULT_OTP_LENGTH = 6;
    private static final long DEFAULT_OTP_VALIDITY = 60000L;
    private static final int DEFAULT_MAX_RETRY = 3;


    @Override
    public String getAMRValue() {

        return TestOTPExecutorConstants.TEST_AMR_VALUE;
    }

    @Override
    protected Event getSendOTPEvent(OTPExecutorConstants.OTPScenarios otpScenario, OTP otp, FlowExecutionContext context)
            throws FlowEngineException {

        Map<String, Object> eventProperties = new HashMap<>();
        eventProperties.put(CODE, otp.getValue());
        eventProperties.put(NotificationConstants.TEMPLATE_TYPE, TestOTPExecutorConstants.TEST_TEMPLATE_TYPE);
        String sendTo = context.getFlowUser() != null ?
                (String) context.getFlowUser().getClaim(TestOTPExecutorConstants.TEST_CLAIM)
                : "default@wso2.com";
        eventProperties.put(NotificationConstants.ARBITRARY_SEND_TO, sendTo);
        eventProperties.put(NotificationConstants.TENANT_DOMAIN, context.getTenantDomain());
        return new Event("TEST_EVENT", eventProperties);
    }

    @Override
    protected long getOTPValidityPeriod(String tenantDomain) {

        return DEFAULT_OTP_VALIDITY;
    }

    @Override
    protected int getMaxResendCount(FlowExecutionContext registrationContext) {

        return DEFAULT_MAX_RETRY;
    }

    @Override
    protected int getMaxRetryCount(FlowExecutionContext registrationContext) {

        return DEFAULT_MAX_RETRY;
    }

    @Override
    protected void handleClaimUpdate(FlowExecutionContext registrationContext, ExecutorResponse response) {

        Map<String, Object> claims = new HashMap<>();
        claims.put(TestOTPExecutorConstants.TEST_UPDATING_CLAIM, TestOTPExecutorConstants.TEST_UPDATING_CLAIM_VALUE);
        response.setUpdatedUserClaims(claims);
    }

    @Override
    protected String getDiagnosticLogComponentId() {

        return "test-otp-executor";
    }

    @Override
    protected int getOTPLength(String tenantDomain) {

        return DEFAULT_OTP_LENGTH;
    }

    @Override
    protected String getOTPCharset(String tenantDomain) {

        return DEFAULT_CHARSET;
    }

    @Override
    protected String getPostOTPGeneratedEventName() {

        return TestOTPExecutorConstants.TEST_POST_OTP_GENERATION_EVENT;
    }

    @Override
    protected String getPostOTPValidatedEventName() {

        return TestOTPExecutorConstants.TEST_POST_OTP_VALIDATION_EVENT;
    }

    @Override
    public String getName() {

        return TestOTPExecutorConstants.TEST_EXECUTOR_NAME;
    }

    @Override
    public List<String> getInitiationData() {

        return java.util.Collections.singletonList(TestOTPExecutorConstants.TEST_CLAIM);
    }

    @Override
    public ExecutorResponse rollback(FlowExecutionContext flowExecutionContext) throws FlowEngineException {

        return null;
    }

    @Override
    public String toString() {

        return getName();
    }

    protected boolean validateInitiation(FlowExecutionContext context) {

        return true;
    }
}
