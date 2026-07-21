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
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.wso2.carbon.identity.auth.otp.core.constant.OTPExecutorConstants.OTP_LENGTH;
import static org.wso2.carbon.identity.auth.otp.core.constant.OTPExecutorConstants.OTP_RETRY_COUNT;
import static org.wso2.carbon.identity.auth.otp.core.constant.OTPExecutorConstants.OTP_RESEND_COUNT;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.GENERATED_OTP;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.OTP_STATUS;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.OTP_USED_TIME;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_COMPLETE;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_ERROR;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_RETRY;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_USER_INPUT_REQUIRED;
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
    public void testIsResendRequest() {

        Assert.assertFalse(testOTPExecutor.isResendRequest(flowExecutionContext));

        flowExecutionContext.getUserInputData().put(OTPExecutorConstants.RESEND, "true");
        Assert.assertTrue(testOTPExecutor.isResendRequest(flowExecutionContext));
    }

    @Test
    public void testInitiateExecution() throws FlowEngineException {

        response.setContextProperty(new HashMap<>());
        testOTPExecutor.initiateExecution(flowExecutionContext, response);
        Assert.assertNotNull(response.getContextProperties().get(OTPExecutorConstants.OTP));
    }

    @Test
    public void testHandleResendRequestFlow() {

        flowExecutionContext.setProperty(OTP_RETRY_COUNT, 1);
        flowExecutionContext.getUserInputData().put(OTPExecutorConstants.RESEND, "true");

        ExecutorResponse executorResponse = testOTPExecutor.execute(flowExecutionContext);
        Assert.assertEquals(executorResponse.getResult(), STATUS_USER_INPUT_REQUIRED);
        Assert.assertEquals(executorResponse.getContextProperties().get(OTP_RESEND_COUNT), 1);
    }

    @Test
    public void testHandleResendRequestMaxExceeded() {

        flowExecutionContext.setProperty(OTP_RETRY_COUNT, 2);
        flowExecutionContext.setProperty(OTP_RESEND_COUNT,
                testOTPExecutor.getMaxResendCount(flowExecutionContext));
        flowExecutionContext.getUserInputData().put(OTPExecutorConstants.RESEND, "true");

        ExecutorResponse executorResponse = testOTPExecutor.execute(flowExecutionContext);
        Assert.assertEquals(executorResponse.getResult(), STATUS_USER_ERROR);
        Assert.assertEquals(executorResponse.getErrorMessage(), "{{otp.max.resend.error.message}}");
    }

    @Test
    public void testProcessResponse() {

    }

    /**
     * A resend request whose initiation cannot be validated (no such user / no configured channel)
     * must mirror the valid-user resend shape: STATUS_USER_INPUT_REQUIRED, optionalData [OTP, RESEND],
     * and an incremented resend counter tracked on the session context — but with NO OTP generated
     * (no valid recipient). This is what closes the enumeration oracle (issue #3335 / HK010, #3336 / HK011).
     */
    @Test
    public void testHandleInvalidResendTracksCountAndSetsInputRequired() throws FlowEngineException {

        testOTPExecutor.handleInvalidResend(flowExecutionContext, response);
        Assert.assertEquals(response.getResult(), STATUS_USER_INPUT_REQUIRED);
        Assert.assertNotNull(response.getOptionalData());
        Assert.assertTrue(response.getOptionalData().contains(OTPExecutorConstants.OTP));
        Assert.assertTrue(response.getOptionalData().contains(OTPExecutorConstants.RESEND));
        Assert.assertEquals(response.getContextProperties().get(OTP_RESEND_COUNT), 1);
        Assert.assertEquals(flowExecutionContext.getProperty(OTP_RESEND_COUNT), 1);
        // No OTP should be generated/dispatched, since there is no valid recipient.
        Assert.assertNull(response.getContextProperties().get(OTPExecutorConstants.OTP));
    }

    /**
     * Once the resend ceiling is reached, the invalid-initiation path must produce the SAME terminal
     * error as a fully-provisioned user (see {@link #testHandleResendRequestMaxExceeded}).
     */
    @Test
    public void testHandleInvalidResendMaxExceeded() throws FlowEngineException {

        flowExecutionContext.setProperty(OTP_RESEND_COUNT,
                testOTPExecutor.getMaxResendCount(flowExecutionContext));
        testOTPExecutor.handleInvalidResend(flowExecutionContext, response);
        Assert.assertEquals(response.getResult(), STATUS_USER_ERROR);
        Assert.assertEquals(response.getErrorMessage(), "{{otp.max.resend.error.message}}");
    }

    /**
     * End-to-end via execute(): a resend request with validateInitiation()==false must now route
     * through handleInvalidResend() and yield the identical result status, optionalData, and resend
     * counter as the valid-user resend path ({@link #testHandleResendRequestFlow}) — no longer the
     * bare STATUS_USER_INPUT_REQUIRED short-circuit that produced the distinguishable
     * "Invalid user inputs." oracle.
     */
    @Test
    public void testExecuteResendWithInvalidInitiationClosesOracle() {

        TestOTPExecutor invalidInitiationExecutor = new TestOTPExecutor() {
            @Override
            protected boolean validateInitiation(FlowExecutionContext context) {
                return false;
            }
        };
        flowExecutionContext.setProperty(OTP_RETRY_COUNT, 1);
        flowExecutionContext.getUserInputData().put(OTPExecutorConstants.RESEND, "true");

        ExecutorResponse executorResponse = invalidInitiationExecutor.execute(flowExecutionContext);
        Assert.assertEquals(executorResponse.getResult(), STATUS_USER_INPUT_REQUIRED);
        Assert.assertEquals(executorResponse.getContextProperties().get(OTP_RESEND_COUNT), 1);
        Assert.assertNotNull(executorResponse.getOptionalData());
        Assert.assertTrue(executorResponse.getOptionalData().contains(OTPExecutorConstants.OTP));
        Assert.assertTrue(executorResponse.getOptionalData().contains(OTPExecutorConstants.RESEND));
    }

    /**
     * End-to-end via execute(): an invalid-initiation resend that hits the ceiling must terminate with
     * the SAME error as a valid user hitting the ceiling ({@link #testHandleResendRequestMaxExceeded}).
     */
    @Test
    public void testExecuteResendInvalidInitiationMaxExceeded() {

        TestOTPExecutor invalidInitiationExecutor = new TestOTPExecutor() {
            @Override
            protected boolean validateInitiation(FlowExecutionContext context) {
                return false;
            }
        };
        flowExecutionContext.setProperty(OTP_RETRY_COUNT, 1);
        flowExecutionContext.setProperty(OTP_RESEND_COUNT,
                invalidInitiationExecutor.getMaxResendCount(flowExecutionContext));
        flowExecutionContext.getUserInputData().put(OTPExecutorConstants.RESEND, "true");

        ExecutorResponse executorResponse = invalidInitiationExecutor.execute(flowExecutionContext);
        Assert.assertEquals(executorResponse.getResult(), STATUS_USER_ERROR);
        Assert.assertEquals(executorResponse.getErrorMessage(), "{{otp.max.resend.error.message}}");
    }

    /**
     * Regression for the enumeration oracle (#3335 / HK010, #3336 / HK011): the reproduction observed
     * that an invalid-initiation user (no channel / non-existent) terminated after only 2 resend clicks
     * with a distinct message, while a fully-provisioned user tolerated more clicks (4) before the
     * shared terminal error. This drives repeated resend requests through a SINGLE reused flow context
     * with {@code validateInitiation()==false} and asserts the invalid path is now counted exactly like
     * the valid path — the resend counter increments monotonically (1, 2, ...) and the flow only
     * terminates once the SAME ceiling ({@code getMaxResendCount}) is reached, with the SAME terminal
     * error as a valid user ({@link #testHandleResendRequestMaxExceeded}). Complements the fixer's
     * single-call {@link #testHandleInvalidResendMaxExceeded} by verifying the multi-click progression /
     * N-vs-(N+1) boundary across context reuse, plus the exact optionalData shape.
     */
    @Test
    public void testInvalidResendCountProgressesAndTerminatesAtSameCeilingAsValidUser() {

        TestOTPExecutor invalidInitiationExecutor = new TestOTPExecutor() {
            @Override
            protected boolean validateInitiation(FlowExecutionContext context) {
                return false;
            }
        };
        int maxResend = invalidInitiationExecutor.getMaxResendCount(flowExecutionContext);
        flowExecutionContext.setProperty(OTP_RETRY_COUNT, 1);
        flowExecutionContext.getUserInputData().put(OTPExecutorConstants.RESEND, "true");

        // Each successive resend click on the reused context must increment the counter, never
        // short-circuit early, up to (but not past) the ceiling.
        for (int expectedCount = 1; expectedCount <= maxResend; expectedCount++) {
            ExecutorResponse executorResponse = invalidInitiationExecutor.execute(flowExecutionContext);
            Assert.assertEquals(executorResponse.getResult(), STATUS_USER_INPUT_REQUIRED,
                    "Invalid-initiation resend #" + expectedCount + " must stay in the counted input-required "
                            + "path, not short-circuit to a distinguishable terminal state.");
            Assert.assertEquals(executorResponse.getContextProperties().get(OTP_RESEND_COUNT), expectedCount);
            // Exact optionalData shape must match the valid resend path: [OTP, RESEND], in that order.
            Assert.assertEquals(executorResponse.getOptionalData().size(), 2);
            Assert.assertEquals(executorResponse.getOptionalData().get(0), OTPExecutorConstants.OTP);
            Assert.assertEquals(executorResponse.getOptionalData().get(1), OTPExecutorConstants.RESEND);
            // No OTP is ever generated on the invalid path, no matter how many times it is retried.
            Assert.assertNull(executorResponse.getContextProperties().get(OTPExecutorConstants.OTP));
        }

        // The (ceiling + 1)-th click terminates with the SAME error a valid user gets at the ceiling.
        ExecutorResponse terminal = invalidInitiationExecutor.execute(flowExecutionContext);
        Assert.assertEquals(terminal.getResult(), STATUS_USER_ERROR);
        Assert.assertEquals(terminal.getErrorMessage(), "{{otp.max.resend.error.message}}");
    }

    /**
     * The crux of the fix stated as a direct side-by-side: from IDENTICAL starting contexts, a resend
     * with {@code validateInitiation()==true} (real user + channel) and a resend with
     * {@code validateInitiation()==false} (no user / no channel) must produce a byte-for-byte identical
     * externally-observable response — same result status, same optionalData, same resend counter, and
     * same (absent) error message. This is exactly the signal an anonymous caller sees; if the two are
     * equal the enumeration oracle is closed. None of the fixer's four tests assert the two paths against
     * EACH OTHER; they each assert against constants. This locks the invariant that the branches are
     * indistinguishable.
     */
    @Test
    public void testValidAndInvalidResendProduceIdenticalObservableResponse() {

        TestOTPExecutor validExecutor = new TestOTPExecutor();                 // validateInitiation() == true
        TestOTPExecutor invalidExecutor = new TestOTPExecutor() {              // validateInitiation() == false
            @Override
            protected boolean validateInitiation(FlowExecutionContext context) {
                return false;
            }
        };

        FlowExecutionContext validContext = new FlowExecutionContext();
        validContext.setTenantDomain(CARBON_SUPER);
        validContext.setProperty(OTP_RETRY_COUNT, 1);
        validContext.getUserInputData().put(OTPExecutorConstants.RESEND, "true");

        FlowExecutionContext invalidContext = new FlowExecutionContext();
        invalidContext.setTenantDomain(CARBON_SUPER);
        invalidContext.setProperty(OTP_RETRY_COUNT, 1);
        invalidContext.getUserInputData().put(OTPExecutorConstants.RESEND, "true");

        ExecutorResponse validResponse = validExecutor.execute(validContext);
        ExecutorResponse invalidResponse = invalidExecutor.execute(invalidContext);

        Assert.assertEquals(invalidResponse.getResult(), validResponse.getResult());
        Assert.assertEquals(invalidResponse.getOptionalData(), validResponse.getOptionalData());
        Assert.assertEquals(invalidResponse.getContextProperties().get(OTP_RESEND_COUNT),
                validResponse.getContextProperties().get(OTP_RESEND_COUNT));
        Assert.assertEquals(invalidResponse.getErrorMessage(), validResponse.getErrorMessage());
    }

    /**
     * The invalid-initiation resend path must never generate or dispatch an OTP notification — there is
     * no valid recipient, and sending (or the observable side effects of a send) would itself re-open the
     * oracle. This asserts, against a fresh event-service mock, that {@code handleInvalidResend} publishes
     * ZERO identity events (no post-OTP-generated event, no send event) and sets neither the OTP context
     * property nor the send-time additionalInfo (both of which are only ever populated by
     * {@code triggerOTP}). The fixer's tests assert the OTP context property is null; this additionally
     * pins that the notification event itself is never fired.
     */
    @Test
    public void testHandleInvalidResendPublishesNoOtpNotificationEvent()
            throws FlowEngineException, IdentityEventException {

        IdentityEventService freshEventService = mock(IdentityEventService.class);
        dataHolderMockedStatic.when(AuthenticatorDataHolder::getIdentityEventService)
                .thenReturn(freshEventService);
        try {
            testOTPExecutor.handleInvalidResend(flowExecutionContext, response);

            // No notification/OTP event of any kind is published on the invalid path.
            verify(freshEventService, never()).handleEvent(any());
            // triggerOTP was never entered: neither the generated OTP nor its additionalInfo is present.
            Assert.assertNull(response.getContextProperties().get(OTPExecutorConstants.OTP));
            Assert.assertNull(response.getAdditionalInfo());
        } finally {
            // Restore the shared stub for subsequent tests in the class.
            dataHolderMockedStatic.when(AuthenticatorDataHolder::getIdentityEventService)
                    .thenReturn(identityEventService);
        }
    }

    /**
     * Channel-agnostic generalization guard (issue #3336 / HK011 — SMSOTP, which shares this base
     * class but whose source is not available to test directly). The #3335 (EmailOTP) regression tests
     * all exercise a single {@link TestOTPExecutor} whose ceiling is the default 2, so they cannot catch
     * a regression that accidentally hardcodes the convergence ceiling to one subclass's value. Here a
     * SECOND executor double is configured with a DIFFERENT {@code getMaxResendCount()} (5 — matching
     * SMSOTP's default {@code MaxResendAttempts}) and {@code validateInitiation()==false}. The invalid
     * path must stay in the counted input-required state for exactly this subclass's own ceiling and
     * only terminate on the (ceiling+1)-th click with the shared terminal error — proving the base-class
     * fix converges at whatever ceiling the subclass declares, so a single shared change genuinely covers
     * SMSOTP (ceiling 5) as well as EmailOTP (ceiling 2) without being pinned to either.
     */
    @Test
    public void testInvalidResendConvergenceFollowsSubclassMaxResendCountNotHardcoded() {

        final int smsLikeCeiling = 5;
        TestOTPExecutor differentCeilingInvalidExecutor = new TestOTPExecutor() {
            @Override
            protected boolean validateInitiation(FlowExecutionContext context) {
                return false;
            }
            @Override
            protected int getMaxResendCount(FlowExecutionContext context) {
                return smsLikeCeiling;
            }
        };
        Assert.assertNotEquals(smsLikeCeiling, testOTPExecutor.getMaxResendCount(flowExecutionContext),
                "Pre-condition: this double must use a ceiling different from the #3335 tests' default (2), "
                        + "otherwise it would not prove generalization across differing subclass configs.");
        flowExecutionContext.setProperty(OTP_RETRY_COUNT, 1);
        flowExecutionContext.getUserInputData().put(OTPExecutorConstants.RESEND, "true");

        for (int expectedCount = 1; expectedCount <= smsLikeCeiling; expectedCount++) {
            ExecutorResponse executorResponse = differentCeilingInvalidExecutor.execute(flowExecutionContext);
            Assert.assertEquals(executorResponse.getResult(), STATUS_USER_INPUT_REQUIRED,
                    "Invalid-initiation resend #" + expectedCount + " must stay counted up to THIS subclass's own "
                            + "ceiling (" + smsLikeCeiling + "), not terminate early at another subclass's ceiling.");
            Assert.assertEquals(executorResponse.getContextProperties().get(OTP_RESEND_COUNT), expectedCount);
        }

        // The (ceiling + 1)-th click terminates with the same shared terminal error — at this subclass's ceiling.
        ExecutorResponse terminal = differentCeilingInvalidExecutor.execute(flowExecutionContext);
        Assert.assertEquals(terminal.getResult(), STATUS_USER_ERROR);
        Assert.assertEquals(terminal.getErrorMessage(), "{{otp.max.resend.error.message}}");
    }

    /**
     * Cross-config parity (channel-agnostic, for #3336 / HK011): the #3335 side-by-side parity test
     * ({@link #testValidAndInvalidResendProduceIdenticalObservableResponse}) compares valid vs invalid
     * for a SINGLE click at the default ceiling (2). This generalizes that invariant to a DIFFERENT
     * subclass ceiling (5) AND across the full multi-click walk: from identical fresh contexts, a valid
     * ({@code validateInitiation()==true}) and an invalid ({@code false}) executor sharing the same
     * non-default ceiling must produce byte-for-byte identical externally observable resend-gating
     * signals at EVERY click — same result status, same optionalData, same resend counter, same error
     * message — right through to the shared terminal error on the (ceiling+1)-th click. This is the
     * property that lets one base-class fix close the oracle for any {@code AbstractOTPExecutor} subclass
     * (SMSOTP included), regardless of its configured ceiling.
     */
    @Test
    public void testValidAndInvalidResendConvergeIdenticallyForDifferingSubclassCeiling() {

        final int ceiling = 5;
        TestOTPExecutor validExecutor = new TestOTPExecutor() {
            @Override
            protected int getMaxResendCount(FlowExecutionContext context) {
                return ceiling;
            }
        };
        TestOTPExecutor invalidExecutor = new TestOTPExecutor() {
            @Override
            protected boolean validateInitiation(FlowExecutionContext context) {
                return false;
            }
            @Override
            protected int getMaxResendCount(FlowExecutionContext context) {
                return ceiling;
            }
        };

        FlowExecutionContext validContext = newResendContext();
        FlowExecutionContext invalidContext = newResendContext();

        for (int click = 1; click <= ceiling + 1; click++) {
            ExecutorResponse validResponse = validExecutor.execute(validContext);
            ExecutorResponse invalidResponse = invalidExecutor.execute(invalidContext);
            Assert.assertEquals(invalidResponse.getResult(), validResponse.getResult(),
                    "Click #" + click + ": valid and invalid resend must share the same result status.");
            Assert.assertEquals(invalidResponse.getOptionalData(), validResponse.getOptionalData(),
                    "Click #" + click + ": optionalData shape must be identical.");
            Assert.assertEquals(invalidResponse.getContextProperties().get(OTP_RESEND_COUNT),
                    validResponse.getContextProperties().get(OTP_RESEND_COUNT),
                    "Click #" + click + ": resend counter must advance identically.");
            Assert.assertEquals(invalidResponse.getErrorMessage(), validResponse.getErrorMessage(),
                    "Click #" + click + ": error message must be identical.");
        }

        // Sanity: the final (ceiling+1)-th click above is the shared terminal error for BOTH paths.
        ExecutorResponse validTerminal = validExecutor.execute(newResendContext());
        FlowExecutionContext exhausted = newResendContext();
        exhausted.setProperty(OTP_RESEND_COUNT, ceiling);
        ExecutorResponse invalidTerminal = invalidExecutor.execute(exhausted);
        Assert.assertEquals(invalidTerminal.getResult(), STATUS_USER_ERROR);
        Assert.assertEquals(invalidTerminal.getErrorMessage(), "{{otp.max.resend.error.message}}");
        // validTerminal is a fresh session (count 0) -> still counted, not terminal — asserts the ceiling
        // is per-session state, not a sticky global flag.
        Assert.assertEquals(validTerminal.getResult(), STATUS_USER_INPUT_REQUIRED);
    }

    /**
     * Session-scoping mechanism (the exact reason the fix works for a NON-EXISTENT username — #3336 /
     * HK011 scenario c). The resend counter lives on the {@link FlowExecutionContext} (a per-flow session
     * property {@code OTP_RESEND_COUNT}), not on any user record — so a username that resolves to no user
     * at all is still counted and rate-limited identically to a real one. This drives the invalid path on
     * two INDEPENDENT flow sessions (each an anonymous recovery attempt with {@code validateInitiation()
     * ==false}) and asserts: (a) each fresh session starts its own counter at 1 — the count is NOT
     * accumulated globally, per executor instance, or per user identity; (b) the count is carried on the
     * FlowExecutionContext itself; (c) re-driving one session advances only that session's counter, the
     * other is untouched. No existing test exercises two separate contexts to pin this per-session
     * (not per-user) scoping.
     */
    @Test
    public void testResendCounterIsFlowContextScopedNotUserScoped() {

        TestOTPExecutor invalidExecutor = new TestOTPExecutor() {
            @Override
            protected boolean validateInitiation(FlowExecutionContext context) {
                return false;
            }
        };

        FlowExecutionContext sessionA = newResendContext();
        FlowExecutionContext sessionB = newResendContext();

        ExecutorResponse a1 = invalidExecutor.execute(sessionA);
        ExecutorResponse b1 = invalidExecutor.execute(sessionB);

        // Each fresh session independently starts its counter at 1 (not 2) — no global/per-instance/per-user
        // accumulation. For a non-existent username there is no user record to key a counter on, so this
        // per-session scoping is precisely what lets the invalid path be counted at all.
        Assert.assertEquals(a1.getContextProperties().get(OTP_RESEND_COUNT), 1);
        Assert.assertEquals(b1.getContextProperties().get(OTP_RESEND_COUNT), 1);

        // The authoritative counter is stored on the FlowExecutionContext (the session), not elsewhere.
        Assert.assertEquals(sessionA.getProperty(OTP_RESEND_COUNT), 1);
        Assert.assertEquals(sessionB.getProperty(OTP_RESEND_COUNT), 1);

        // Re-driving session A advances ONLY A's counter; session B is unaffected — state is per-session.
        ExecutorResponse a2 = invalidExecutor.execute(sessionA);
        Assert.assertEquals(a2.getContextProperties().get(OTP_RESEND_COUNT), 2);
        Assert.assertEquals(sessionA.getProperty(OTP_RESEND_COUNT), 2);
        Assert.assertEquals(sessionB.getProperty(OTP_RESEND_COUNT), 1);
    }

    /**
     * Builds a fresh flow-execution context primed to route straight into the resend branch of
     * {@code execute()} (OTP_RETRY_COUNT set so it is not treated as an initiate request, and the RESEND
     * user input present). Each call returns an independent session.
     */
    private FlowExecutionContext newResendContext() {

        FlowExecutionContext context = new FlowExecutionContext();
        context.setTenantDomain(CARBON_SUPER);
        context.setProperty(OTP_RETRY_COUNT, 1);
        context.getUserInputData().put(OTPExecutorConstants.RESEND, "true");
        return context;
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
        Assert.assertEquals(response.getContextProperties().get(OTP_RESEND_COUNT), 1);
        Assert.assertEquals(flowExecutionContext.getProperty(OTP_RESEND_COUNT), 1);
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
        Map<String, Object> contextProperties = response.getContextProperties();
        contextProperties.put(OTPExecutorConstants.OTP, otp);
        response.setContextProperty(contextProperties);
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
        Assert.assertEquals(response.getResult(), STATUS_RETRY);
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
        response.getContextProperties().put(OTP_RESEND_COUNT, 1);
        flowExecutionContext.setProperty(OTP_RESEND_COUNT, 1);
        testOTPExecutor.handleRetry(flowExecutionContext, response);
        Assert.assertNull(response.getContextProperties().get(OTP_RETRY_COUNT));
        Assert.assertNull(response.getContextProperties().get(OTP_RESEND_COUNT));
        Assert.assertNull(flowExecutionContext.getProperty(OTP_RESEND_COUNT));
    }

    @Test
    public void testHandleMaxRetryCountExceeded() throws FlowEngineException {

        flowExecutionContext.setProperty(OTP_RETRY_COUNT, 5);
        testOTPExecutor.handleMaxRetryCount(flowExecutionContext, response);
        Assert.assertEquals(response.getResult(), STATUS_USER_ERROR);
        Assert.assertEquals(response.getErrorMessage(), "{{otp.max.retry.error.message}}");
    }

    @Test
    public void testHandleAuthErrorScenarioFallbackMessage() {

        Exception e = new Exception("Test Exception");
        FlowEngineException ex = testOTPExecutor.handleAuthErrorScenario(e);
        Assert.assertTrue(ex.getDescription().contains("Error occurred in TestExecutor"));
    }
}
