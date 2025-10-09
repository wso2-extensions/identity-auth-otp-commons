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

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.auth.otp.core.constant.OTPExecutorConstants;
import org.wso2.carbon.identity.auth.otp.core.internal.AuthenticatorDataHolder;
import org.wso2.carbon.identity.auth.otp.core.model.OTP;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.notification.NotificationConstants;
import org.wso2.carbon.identity.flow.execution.engine.Constants;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineException;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineServerException;
import org.wso2.carbon.identity.flow.execution.engine.graph.AuthenticationExecutor;
import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.utils.DiagnosticLog;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.wso2.carbon.identity.auth.otp.core.constant.OTPExecutorConstants.LogConstants.ActionID.SEND_OTP;
import static org.wso2.carbon.identity.auth.otp.core.constant.OTPExecutorConstants.OTP;
import static org.wso2.carbon.identity.auth.otp.core.constant.OTPExecutorConstants.OTP_RETRY_COUNT;
import static org.wso2.carbon.identity.event.handler.notification.NotificationConstants.FLOW_TYPE;
import static org.wso2.carbon.identity.event.handler.notification.NotificationConstants.REGISTRATION_FLOW;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_COMPLETE;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_RETRY;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_USER_ERROR;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_USER_INPUT_REQUIRED;

/**
 * Abstract class for OTP executors.
 * This class provides the common functionality for OTP executors.
 */
public abstract class AbstractOTPExecutor extends AuthenticationExecutor {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private static final Log LOG = LogFactory.getLog(AbstractOTPExecutor.class);

    @Override
    public ExecutorResponse execute(FlowExecutionContext flowExecutionContext) {

        ExecutorResponse response = new ExecutorResponse();
        response.setContextProperty(new HashMap<>());
        try {
            handleMaxRetryCount(flowExecutionContext, response);
            if (STATUS_USER_ERROR.equals(response.getResult())) {
                return response;
            }

            if (isInitiateRequest(flowExecutionContext)) {
                if (validateInitiation(flowExecutionContext)) {
                    initiateExecution(flowExecutionContext, response);
                } else {
                    response.setResult(STATUS_USER_INPUT_REQUIRED);
                }
            } else {
                if (isResendRequest(flowExecutionContext)) {
                    handleResend(flowExecutionContext, response);
                    return response;
                }
                processResponse(flowExecutionContext, response);
            }
            handleRetry(flowExecutionContext, response);
            return response;
        } catch (FlowEngineException e) {
            logDiagnostic("Error occurred while executing the flow in " + getName(),
                    DiagnosticLog.ResultStatus.FAILED, OTPExecutorConstants.LogConstants.ActionID.PROCESS_OTP);
            response.setResult(Constants.ExecutorStatus.STATUS_ERROR);
            response.setErrorMessage(e.getMessage());
            return response;
        }
    }

    /**
     * This method is used to check whether the request is an initiate request or not.
     *
     * @param flowExecutionContext Registration context.
     * @return true if it is an initiate request, false otherwise.
     */
    protected boolean isInitiateRequest(FlowExecutionContext flowExecutionContext) {

        return flowExecutionContext.getUserInputData().get(OTP) == null &&
                flowExecutionContext.getProperty(OTP_RETRY_COUNT) == null;
    }

    /**
     * Checks whether the request is for resending the OTP.
     *
     * @param flowExecutionContext Flow execution context.
     * @return {@code true} if the request is a resend request, {@code false} otherwise.
     */
    protected boolean isResendRequest(FlowExecutionContext flowExecutionContext) {

        Map<String, String> userInputData = flowExecutionContext.getUserInputData();
        if (userInputData == null || userInputData.isEmpty()) {
            return false;
        }

        String resendParameter = userInputData.get(OTPExecutorConstants.RESEND);
        if (StringUtils.isNotBlank(resendParameter)) {
            return Boolean.parseBoolean(resendParameter);
        }
        return false;
    }

    /**
     * This method is used to initiate the OTP execution.
     *
     * @param flowExecutionContext Registration context.
     * @param response             Executor response.
     * @throws FlowEngineException if an error occurs while initiating the execution.
     */
    protected void initiateExecution(FlowExecutionContext flowExecutionContext, ExecutorResponse response)
            throws FlowEngineException {

        response.setResult(STATUS_USER_INPUT_REQUIRED);
        List<String> data = new ArrayList<>();
        data.add(OTPExecutorConstants.OTP);
        data.add(OTPExecutorConstants.RESEND);
        response.setOptionalData(data);
        triggerOTP(OTPExecutorConstants.OTPScenarios.INITIAL_OTP, flowExecutionContext, response);
    }

    /**
     * Handles OTP resend requests by triggering the resend flow.
     *
     * @param flowExecutionContext Flow execution context.
     * @param response             Executor response.
     * @throws FlowEngineException If an error occurs while handling the resend request.
     */
    protected void handleResend(FlowExecutionContext flowExecutionContext, ExecutorResponse response)
            throws FlowEngineException {

        handleMaxResendCount(flowExecutionContext, response);
        if (STATUS_USER_ERROR.equals(response.getResult())) {
            return;
        }

        response.setResult(STATUS_USER_INPUT_REQUIRED);
        List<String> data = new ArrayList<>();
        data.add(OTPExecutorConstants.OTP);
        data.add(OTPExecutorConstants.RESEND);
        response.setOptionalData(data);
        triggerOTP(OTPExecutorConstants.OTPScenarios.RESEND_OTP, flowExecutionContext, response);
        updateResendCount(flowExecutionContext, response);
    }

    /**
     * This method is used to process the response of the OTP execution.
     *
     * @param flowExecutionContext Registration context.
     * @param response             Executor response.
     * @throws FlowEngineException if an error occurs while processing the response.
     */
    protected void processResponse(FlowExecutionContext flowExecutionContext, ExecutorResponse response)
            throws FlowEngineException {

        String inputOTP = flowExecutionContext.getUserInputData().get(OTP);
            if (StringUtils.isBlank(inputOTP)) {
                response.setResult(STATUS_RETRY);
                return;
            }

            OTP otp = getOTPFromContext(flowExecutionContext, response);
            if (otp == null) return;

            if (inputOTP.equals(otp.getValue())) {
                if (otp.isExpired()) {
                    response.setResult(STATUS_RETRY);
                    publishPostOTPValidationEvent(flowExecutionContext, false, true, response);
                } else {
                    response.setResult(STATUS_COMPLETE);
                    Map<String, Object> contextProps = response.getContextProperties();
                    contextProps.put(OTP, null);
                    flowExecutionContext.getUserInputData().remove(OTP);
                    handleClaimUpdate(flowExecutionContext, response);
                    publishPostOTPValidationEvent(flowExecutionContext, true, false, response);
                }
            } else {
                response.setResult(STATUS_RETRY);
                publishPostOTPValidationEvent(flowExecutionContext, false, false, response);
            }
    }

    private static OTP getOTPFromContext(FlowExecutionContext flowExecutionContext, ExecutorResponse response) {

        Object value = flowExecutionContext.getProperty(OTP);
        HashMap<String, Object> contextOTP = OBJECT_MAPPER.convertValue(value,
                new TypeReference<HashMap<String, Object>>() {
                });
        if (contextOTP == null) {
            response.setResult(Constants.ExecutorStatus.STATUS_ERROR);
            response.setErrorMessage("{{otp.not.generated.error.message}}");
            return null;
        }

        Long validityPeriodInMillis;
        if (contextOTP.get(OTPExecutorConstants.OTPData.VALIDITY_PERIOD_IN_MILLIS) instanceof Integer){
            validityPeriodInMillis =
                    ((Integer) contextOTP.get(OTPExecutorConstants.OTPData.VALIDITY_PERIOD_IN_MILLIS)).longValue();
        } else if (contextOTP.get(OTPExecutorConstants.OTPData.VALIDITY_PERIOD_IN_MILLIS) instanceof Long) {
            validityPeriodInMillis = (Long) contextOTP.get(OTPExecutorConstants.OTPData.VALIDITY_PERIOD_IN_MILLIS);
        } else {
            response.setResult(Constants.ExecutorStatus.STATUS_ERROR);
            response.setErrorMessage("{{otp.error.message}}");
            return null;
        }

        return new OTP(
                (String) contextOTP.get(OTPExecutorConstants.OTPData.VALUE),
                (Long) contextOTP.get(OTPExecutorConstants.OTPData.GENERATED_TIME_IN_MILLIS),
                validityPeriodInMillis
        );
    }

    /**
     * This method is used to handle the maximum retry count.
     *
     * @param context  Registration context.
     * @param response Executor response.
     * @throws FlowEngineException if an error occurs while handling the maximum retry count.
     */
    protected void handleMaxRetryCount(FlowExecutionContext context, ExecutorResponse response)
            throws FlowEngineException {

        if (getCurrentRetryCount(context) >= getMaxRetryCount(context)) {
            response.setResult(STATUS_USER_ERROR);
            response.setErrorMessage("{{otp.max.retry.error.message}}");
        }
    }

    /**
     * This method is used to handle the maximum resend count.
     *
     * @param context  Flow execution context.
     * @param response Executor response.
     * @throws FlowEngineException if an error occurs while handling the maximum resend count.
     */
    protected void handleMaxResendCount(FlowExecutionContext context, ExecutorResponse response)
            throws FlowEngineException {

        if (getCurrentResendCount(context) >= getMaxResendCount(context)) {
            response.setResult(STATUS_USER_ERROR);
            response.setErrorMessage("{{otp.max.resend.error.message}}");
        }
    }

    /**
     * This method is used to handle the retry count.
     *
     * @param flowExecutionContext Registration context.
     * @param response             Executor response.
     * @throws FlowEngineException if an error occurs while handling the retry count.
     */
    protected void handleRetry(FlowExecutionContext flowExecutionContext, ExecutorResponse response)
            throws FlowEngineException {

        String result = response.getResult();
        if (STATUS_RETRY.equals(result)) {
            response.setErrorMessage("{{otp.error.message}}");
            OTP otp = getOTPFromContext(flowExecutionContext, response);
            if (otp != null && otp.isExpired()) {
                handleMaxResendCount(flowExecutionContext, response);
                if (STATUS_USER_ERROR.equals(response.getResult())) {
                    return;
                }
                triggerOTP(OTPExecutorConstants.OTPScenarios.RESEND_OTP, flowExecutionContext, response);
                updateResendCount(flowExecutionContext, response);
                return;
            }
        } else if (STATUS_COMPLETE.equals(result)) {
            flowExecutionContext.setProperty(OTP_RETRY_COUNT, null);
            response.getContextProperties().remove(OTP_RETRY_COUNT);
            flowExecutionContext.setProperty(OTPExecutorConstants.OTP_RESEND_COUNT, null);
            response.getContextProperties().remove(OTPExecutorConstants.OTP_RESEND_COUNT);
            return;
        }
        response.getContextProperties().put(OTP_RETRY_COUNT, getCurrentRetryCount(flowExecutionContext) + 1);
        List<String> data = new ArrayList<>();
        data.add(OTPExecutorConstants.OTP);
        data.add(OTPExecutorConstants.RESEND);
        response.setOptionalData(data);
    }

    /**
     * This method is used to generate the OTP.
     *
     * @param tenantDomain Tenant domain.
     * @return Generated OTP.
     * @throws FlowEngineException if an error occurs while generating the OTP.
     */
    protected OTP generateOTP(String tenantDomain) throws FlowEngineException {

        final char[] chars = getOTPCharset(tenantDomain).toCharArray();
        final int otpLength = getOTPLength(tenantDomain);
        SecureRandom secureRandom = new SecureRandom();
        StringBuilder tokenBuilder = new StringBuilder(otpLength);

        for (int i = 0; i < otpLength; i++) {
            tokenBuilder.append(chars[secureRandom.nextInt(chars.length)]);
        }
        return new OTP(tokenBuilder.toString(), System.currentTimeMillis(), getOTPValidityPeriod(tenantDomain));
    }

    /**
     * This method is used to trigger the OTP.
     *
     * @param scenario Scenario.
     * @param context  Registration context.
     * @param response Executor response.
     * @throws FlowEngineException if an error occurs while triggering the OTP.
     */
    protected void triggerOTP(OTPExecutorConstants.OTPScenarios scenario, FlowExecutionContext context,
                              ExecutorResponse response) throws FlowEngineException {

        // Do not send OTP if the credentials are not managed locally or the account is locked/disabled.
        if (!context.getFlowUser().isCredentialsManagedLocally() || context.getFlowUser().isAccountLocked() ||
                context.getFlowUser().isAccountDisabled()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Skipping OTP sending as the user account is either locked/disabled or the credentials " +
                        "are not managed locally.");
            }
            logDiagnostic("Skipping OTP sending as the user account is either locked/disabled or the " +
                            "credentials are not managed locally.",
                    DiagnosticLog.ResultStatus.SUCCESS, SEND_OTP);
            return;
        }
        OTP otp = generateOTP(context.getTenantDomain());
        Map<String, Object> contextProperties = response.getContextProperties();

        HashMap<String, Object> otpData = new HashMap<>();
        otpData.put(OTPExecutorConstants.OTPData.VALUE, otp.getValue());
        otpData.put(OTPExecutorConstants.OTPData.GENERATED_TIME_IN_MILLIS, otp.getGeneratedTimeInMillis());
        otpData.put(OTPExecutorConstants.OTPData.VALIDITY_PERIOD_IN_MILLIS, otp.getValidityPeriodInMillis());
        otpData.put(OTPExecutorConstants.OTPData.EXPIRY_TIME_IN_MILLIS, otp.getExpiryTimeInMillis());

        contextProperties.put(OTP, otpData);
        publishPostOTPGeneratedEvent(scenario, context, response);

        Map<String, String> info = new HashMap<>();
        info.put(OTPExecutorConstants.OTP_LENGTH, String.valueOf(getOTPLength(context.getTenantDomain())));
        response.setAdditionalInfo(info);

        try {
            Event otpEvent = getSendOTPEvent(scenario, otp, context);
            String flowType = context.getFlowType();
            otpEvent.addEventProperty(FLOW_TYPE, flowType);
            AuthenticatorDataHolder.getIdentityEventService().handleEvent(otpEvent);
        } catch (IdentityEventException e) {
            logDiagnostic("Error occurred while sending the OTP in " + getName(),
                    DiagnosticLog.ResultStatus.FAILED, SEND_OTP);
            throw handleAuthErrorScenario(e, "Error occurred while sending the OTP in " + getName() + ".");
        }
    }

    private void logDiagnostic(String message, DiagnosticLog.ResultStatus status, String actionId) {

        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            LoggerUtils.triggerDiagnosticLogEvent(
                    new DiagnosticLog.DiagnosticLogBuilder(getDiagnosticLogComponentId(), actionId)
                            .resultMessage(message)
                            .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                            .resultStatus(status)
            );
        }
    }

    /**
     * This method is used to handle the authentication error scenario.
     *
     * @param throwable Exception thrown.
     * @param data      Additional data.
     * @return RegistrationEngineServerException.
     */
    @SuppressFBWarnings("FORMAT_STRING_MANIPULATION")
    protected FlowEngineServerException handleAuthErrorScenario(Throwable throwable, Object... data) {

        String detailMessage = (data != null && data.length > 0 && data[0] instanceof String)
                ? (String) data[0]
                : "Error occurred in " + getName() + ".";
        return new FlowEngineServerException(Constants.ErrorMessages.ERROR_CODE_EXECUTOR_FAILURE.getCode(),
                Constants.ErrorMessages.ERROR_CODE_EXECUTOR_FAILURE.getMessage(), detailMessage, throwable);
    }

    /**
     * This method is used to publish the post OTP generated event.
     *
     * @param scenario Scenario.
     * @param context  Registration context.
     * @throws FlowEngineException if an error occurs while publishing the event.
     */
    protected void publishPostOTPGeneratedEvent(OTPExecutorConstants.OTPScenarios scenario, FlowExecutionContext context,
                                                ExecutorResponse response)
            throws FlowEngineException {

        try {
            Object value = response.getContextProperties().get(OTP);
            HashMap<String, Object> otpMap = OBJECT_MAPPER.convertValue(value,
                    new TypeReference<HashMap<String, Object>>() {
                    });
            if (otpMap != null) {
                Map<String, Object> eventProperties = new HashMap<>();
                eventProperties.put(IdentityEventConstants.EventProperty.CORRELATION_ID, context.getCorrelationId());
                eventProperties.put(IdentityEventConstants.EventProperty.RESEND_CODE,
                        OTPExecutorConstants.OTPScenarios.RESEND_OTP.equals(scenario));
                eventProperties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, context.getTenantDomain());
                eventProperties.put(NotificationConstants.FLOW_TYPE, REGISTRATION_FLOW);
                eventProperties.put(IdentityEventConstants.EventProperty.GENERATED_OTP,
                        otpMap.get(OTPExecutorConstants.OTPData.VALUE));
                eventProperties.put(IdentityEventConstants.EventProperty.OTP_GENERATED_TIME,
                        otpMap.get(OTPExecutorConstants.OTPData.GENERATED_TIME_IN_MILLIS));
                eventProperties.put(IdentityEventConstants.EventProperty.OTP_EXPIRY_TIME,
                        (Long) otpMap.get(OTPExecutorConstants.OTPData.GENERATED_TIME_IN_MILLIS)
                        + getOTPValidityPeriod(context.getTenantDomain()));
                AuthenticatorDataHolder.getIdentityEventService().handleEvent(new Event(getPostOTPGeneratedEventName(),
                        eventProperties));
            }
        } catch (IdentityEventException e) {
            logDiagnostic("Error occurred while publishing post OTP generated event.",
                    DiagnosticLog.ResultStatus.FAILED, SEND_OTP);
            throw handleAuthErrorScenario(e, "Error occurred while publishing post OTP generated event.");
        }
    }

    /**
     * This method is used to publish the post OTP validation event.
     *
     * @param context                Registration context.
     * @param isAuthenticationPassed true if the authentication is passed, false otherwise.
     * @param isExpired              true if the OTP is expired, false otherwise.
     * @throws FlowEngineException if an error occurs while publishing the event.
     */
    protected void publishPostOTPValidationEvent(FlowExecutionContext context, boolean isAuthenticationPassed,
                                                 boolean isExpired, ExecutorResponse response)
            throws FlowEngineException {

        try {
            Map<String, Object> eventProperties = new HashMap<>();
            eventProperties.put(IdentityEventConstants.EventProperty.CORRELATION_ID, context.getCorrelationId());
            eventProperties.put(IdentityEventConstants.EventProperty.USER_INPUT_OTP,
                    context.getUserInputData().get(OTP));
            eventProperties.put(IdentityEventConstants.EventProperty.OTP_USED_TIME, System.currentTimeMillis());
            eventProperties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, context.getTenantDomain());
            eventProperties.put(NotificationConstants.FLOW_TYPE, REGISTRATION_FLOW);
            if (isAuthenticationPassed) {
                eventProperties.put(IdentityEventConstants.EventProperty.OTP_STATUS, OTPExecutorConstants.Status.SUCCESS);
                eventProperties.put(IdentityEventConstants.EventProperty.GENERATED_OTP,
                        context.getUserInputData().get(OTP));
                logDiagnostic("OTP validation successful",
                        DiagnosticLog.ResultStatus.SUCCESS, OTPExecutorConstants.LogConstants.ActionID.VERIFY_OTP);
            } else if (isExpired) {
                eventProperties.put(IdentityEventConstants.EventProperty.OTP_STATUS,
                        OTPExecutorConstants.Status.OTP_EXPIRED);
                OTP otp = getOTPFromContext(context, response);
                if (otp != null) {
                    eventProperties.put(IdentityEventConstants.EventProperty.OTP_GENERATED_TIME,
                            otp.getGeneratedTimeInMillis());
                    eventProperties.put(IdentityEventConstants.EventProperty.OTP_EXPIRY_TIME, otp.getGeneratedTimeInMillis()
                            + getOTPValidityPeriod(context.getTenantDomain()));
                }
                logDiagnostic("Provided OTP is expired",
                        DiagnosticLog.ResultStatus.FAILED, OTPExecutorConstants.LogConstants.ActionID.VERIFY_OTP);
            } else {
                eventProperties.put(IdentityEventConstants.EventProperty.OTP_STATUS,
                        OTPExecutorConstants.Status.CODE_MISMATCH);
            }
            AuthenticatorDataHolder.getIdentityEventService().handleEvent(new Event(getPostOTPValidatedEventName(),
                    eventProperties));
        } catch (IdentityEventException e) {
            throw handleAuthErrorScenario(e, "Error occurred while publishing post OTP validation event.");
        }
    }

    abstract protected boolean validateInitiation(FlowExecutionContext context);

    private int getCurrentRetryCount(FlowExecutionContext context) {

        return Optional.ofNullable((Integer) context.getProperty(OTP_RETRY_COUNT)).orElse(0);
    }

    private int getCurrentResendCount(FlowExecutionContext context) {

        return Optional.ofNullable((Integer) context.getProperty(OTPExecutorConstants.OTP_RESEND_COUNT)).orElse(0);
    }

    private void updateResendCount(FlowExecutionContext context, ExecutorResponse response) {

        int resendCount = getCurrentResendCount(context) + 1;
        context.setProperty(OTPExecutorConstants.OTP_RESEND_COUNT, resendCount);
        response.getContextProperties().put(OTPExecutorConstants.OTP_RESEND_COUNT, resendCount);
    }

    abstract protected Event getSendOTPEvent(OTPExecutorConstants.OTPScenarios otpScenario, OTP otp,
                                             FlowExecutionContext context) throws FlowEngineException;

    abstract protected long getOTPValidityPeriod(String tenantDomain) throws FlowEngineException;

    abstract protected int getMaxResendCount(FlowExecutionContext flowExecutionContext)
            throws FlowEngineException;

    abstract protected int getMaxRetryCount(FlowExecutionContext flowExecutionContext) throws FlowEngineException;

    abstract protected void handleClaimUpdate(FlowExecutionContext flowExecutionContext,
                                              ExecutorResponse response) throws FlowEngineException;

    abstract protected String getDiagnosticLogComponentId();

    abstract protected int getOTPLength(String tenantDomain) throws FlowEngineException;

    abstract protected String getOTPCharset(String tenantDomain) throws FlowEngineException;

    abstract protected String getPostOTPGeneratedEventName();

    abstract protected String getPostOTPValidatedEventName();
}
