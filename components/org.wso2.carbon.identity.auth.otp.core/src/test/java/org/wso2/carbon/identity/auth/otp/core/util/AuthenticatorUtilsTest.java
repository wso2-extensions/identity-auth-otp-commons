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

package org.wso2.carbon.identity.auth.otp.core.util;

import org.mockito.MockedStatic;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.utils.DiagnosticLog;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;

/**
 * Unit tests for AuthenticatorUtils.
 */
public class AuthenticatorUtilsTest {

    private static final String PARAM_NAME = "testParam";

    private MockedStatic<LoggerUtils> loggerUtilsMock;

    @BeforeMethod
    public void setUp() {

        loggerUtilsMock = mockStatic(LoggerUtils.class);
        // Disable diagnostic logging by default; individual tests override this where needed.
        loggerUtilsMock.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(false);
    }

    @AfterMethod
    public void tearDown() {

        if (loggerUtilsMock != null) {
            loggerUtilsMock.close();
        }
    }

    @Test(description = "Returns the value when the param exists in the map")
    public void testGetOptionalParam_WhenParamExists() {

        Map<String, String> params = new HashMap<>();
        params.put(PARAM_NAME, "hello");

        Optional<String> result = AuthenticatorUtils.getOptionalParamFromRuntimeParams(params, PARAM_NAME);

        Assert.assertTrue(result.isPresent());
        Assert.assertEquals(result.get(), "hello");
    }

    @Test(description = "Returns empty when the param key is absent from the map")
    public void testGetOptionalParam_WhenParamAbsent() {

        Map<String, String> params = new HashMap<>();
        params.put("otherParam", "value");

        Optional<String> result = AuthenticatorUtils.getOptionalParamFromRuntimeParams(params, PARAM_NAME);

        Assert.assertFalse(result.isPresent());
    }

    @Test(description = "Returns empty when the runtime params map is null")
    public void testGetOptionalParam_WhenMapIsNull() {

        Optional<String> result = AuthenticatorUtils.getOptionalParamFromRuntimeParams(null, PARAM_NAME);

        Assert.assertFalse(result.isPresent());
    }

    @Test(description = "Returns empty when the runtime params map is empty")
    public void testGetOptionalParam_WhenMapIsEmpty() {

        Optional<String> result = AuthenticatorUtils.getOptionalParamFromRuntimeParams(
                Collections.emptyMap(), PARAM_NAME);

        Assert.assertFalse(result.isPresent());
    }

    @Test(description = "Returns the value when it is a blank string (blank is a valid value)")
    public void testGetOptionalParam_WhenValueIsBlankString() {

        Map<String, String> params = new HashMap<>();
        params.put(PARAM_NAME, "");

        Optional<String> result = AuthenticatorUtils.getOptionalParamFromRuntimeParams(params, PARAM_NAME);

        Assert.assertTrue(result.isPresent());
        Assert.assertEquals(result.get(), "");
    }

    @Test(description = "Returns empty when the param value stored in the map is null")
    public void testGetOptionalParam_WhenValueIsNull() {

        Map<String, String> params = new HashMap<>();
        params.put(PARAM_NAME, null);

        Optional<String> result = AuthenticatorUtils.getOptionalParamFromRuntimeParams(params, PARAM_NAME);

        Assert.assertFalse(result.isPresent());
    }

    @Test(description = "Returns Optional.of(true) when the param value is 'true'")
    public void testGetOptionalBooleanParam_WhenValueIsTrue() {

        Map<String, String> params = new HashMap<>();
        params.put(PARAM_NAME, "true");

        Optional<Boolean> result =
                AuthenticatorUtils.getOptionalBooleanParamFromRuntimeParams(params, PARAM_NAME);

        Assert.assertTrue(result.isPresent());
        Assert.assertTrue(result.get());
    }

    @Test(description = "Returns Optional.of(false) when the param value is 'false'")
    public void testGetOptionalBooleanParam_WhenValueIsFalse() {

        Map<String, String> params = new HashMap<>();
        params.put(PARAM_NAME, "false");

        Optional<Boolean> result =
                AuthenticatorUtils.getOptionalBooleanParamFromRuntimeParams(params, PARAM_NAME);

        Assert.assertTrue(result.isPresent());
        Assert.assertFalse(result.get());
    }

    @Test(description = "Returns Optional.of(true) for 'TRUE' (case-insensitive)")
    public void testGetOptionalBooleanParam_WhenValueIsTrueUpperCase() {

        Map<String, String> params = new HashMap<>();
        params.put(PARAM_NAME, "TRUE");

        Optional<Boolean> result =
                AuthenticatorUtils.getOptionalBooleanParamFromRuntimeParams(params, PARAM_NAME);

        Assert.assertTrue(result.isPresent());
        Assert.assertTrue(result.get());
    }

    @Test(description = "Returns Optional.of(false) when the param value is a non-boolean string")
    public void testGetOptionalBooleanParam_WhenValueIsNonBoolean() {

        Map<String, String> params = new HashMap<>();
        params.put(PARAM_NAME, "yes");

        // Boolean.parseBoolean("yes") → false
        Optional<Boolean> result =
                AuthenticatorUtils.getOptionalBooleanParamFromRuntimeParams(params, PARAM_NAME);

        Assert.assertTrue(result.isPresent());
        Assert.assertFalse(result.get());
    }

    @Test(description = "Returns empty when the runtime params map is null")
    public void testGetOptionalBooleanParam_WhenMapIsNull() {

        Optional<Boolean> result =
                AuthenticatorUtils.getOptionalBooleanParamFromRuntimeParams(null, PARAM_NAME);

        Assert.assertFalse(result.isPresent());
    }

    @Test(description = "Returns empty when the runtime params map is empty")
    public void testGetOptionalBooleanParam_WhenMapIsEmpty() {

        Optional<Boolean> result =
                AuthenticatorUtils.getOptionalBooleanParamFromRuntimeParams(
                        Collections.emptyMap(), PARAM_NAME);

        Assert.assertFalse(result.isPresent());
    }

    @Test(description = "Returns empty when the param key is absent")
    public void testGetOptionalBooleanParam_WhenParamAbsent() {

        Map<String, String> params = new HashMap<>();
        params.put("otherParam", "true");

        Optional<Boolean> result =
                AuthenticatorUtils.getOptionalBooleanParamFromRuntimeParams(params, PARAM_NAME);

        Assert.assertFalse(result.isPresent());
    }

    @Test(description = "Returns the parsed integer when the param value is a valid integer string")
    public void testGetOptionalIntParam_WhenValueIsValidInt() {

        Map<String, String> params = new HashMap<>();
        params.put(PARAM_NAME, "42");

        OptionalInt result = AuthenticatorUtils.getOptionalIntParamFromRuntimeParams(params, PARAM_NAME);

        Assert.assertTrue(result.isPresent());
        Assert.assertEquals(result.getAsInt(), 42);
    }

    @Test(description = "Returns the parsed integer for a zero value")
    public void testGetOptionalIntParam_WhenValueIsZero() {

        Map<String, String> params = new HashMap<>();
        params.put(PARAM_NAME, "0");

        OptionalInt result = AuthenticatorUtils.getOptionalIntParamFromRuntimeParams(params, PARAM_NAME);

        Assert.assertTrue(result.isPresent());
        Assert.assertEquals(result.getAsInt(), 0);
    }

    @Test(description = "Returns the parsed integer for a negative value")
    public void testGetOptionalIntParam_WhenValueIsNegative() {

        Map<String, String> params = new HashMap<>();
        params.put(PARAM_NAME, "-5");

        OptionalInt result = AuthenticatorUtils.getOptionalIntParamFromRuntimeParams(params, PARAM_NAME);

        Assert.assertTrue(result.isPresent());
        Assert.assertEquals(result.getAsInt(), -5);
    }

    @Test(description = "Returns empty and does NOT throw when the param value is non-numeric")
    public void testGetOptionalIntParam_WhenValueIsNonNumeric() {

        Map<String, String> params = new HashMap<>();
        params.put(PARAM_NAME, "notAnInt");

        OptionalInt result = AuthenticatorUtils.getOptionalIntParamFromRuntimeParams(params, PARAM_NAME);

        Assert.assertFalse(result.isPresent());
    }

    @Test(description = "Returns empty and does NOT throw when the param value is a decimal string")
    public void testGetOptionalIntParam_WhenValueIsDecimal() {

        Map<String, String> params = new HashMap<>();
        params.put(PARAM_NAME, "3.14");

        OptionalInt result = AuthenticatorUtils.getOptionalIntParamFromRuntimeParams(params, PARAM_NAME);

        Assert.assertFalse(result.isPresent());
    }

    @Test(description = "Returns empty when the runtime params map is null")
    public void testGetOptionalIntParam_WhenMapIsNull() {

        OptionalInt result = AuthenticatorUtils.getOptionalIntParamFromRuntimeParams(null, PARAM_NAME);

        Assert.assertFalse(result.isPresent());
    }

    @Test(description = "Returns empty when the runtime params map is empty")
    public void testGetOptionalIntParam_WhenMapIsEmpty() {

        OptionalInt result = AuthenticatorUtils.getOptionalIntParamFromRuntimeParams(
                Collections.emptyMap(), PARAM_NAME);

        Assert.assertFalse(result.isPresent());
    }

    @Test(description = "Returns empty when the param key is absent from the map")
    public void testGetOptionalIntParam_WhenParamAbsent() {

        Map<String, String> params = new HashMap<>();
        params.put("otherParam", "10");

        OptionalInt result = AuthenticatorUtils.getOptionalIntParamFromRuntimeParams(params, PARAM_NAME);

        Assert.assertFalse(result.isPresent());
    }

    @Test(description = "Returns empty when the param value stored in the map is null")
    public void testGetOptionalIntParam_WhenValueIsNull() {

        Map<String, String> params = new HashMap<>();
        params.put(PARAM_NAME, null);

        OptionalInt result = AuthenticatorUtils.getOptionalIntParamFromRuntimeParams(params, PARAM_NAME);

        Assert.assertFalse(result.isPresent());
    }

    @Test(description = "Triggers a diagnostic log event for non-numeric values when diagnostic logging is enabled")
    public void testGetOptionalIntParam_NonNumeric_TriggersDiagnosticLog_WhenEnabled() {

        loggerUtilsMock.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(true);
        loggerUtilsMock.when(() -> LoggerUtils.triggerDiagnosticLogEvent(any())).thenAnswer(inv -> null);

        Map<String, String> params = new HashMap<>();
        params.put(PARAM_NAME, "bad_value");

        OptionalInt result = AuthenticatorUtils.getOptionalIntParamFromRuntimeParams(params, PARAM_NAME);

        Assert.assertFalse(result.isPresent());
        loggerUtilsMock.verify(() -> LoggerUtils.triggerDiagnosticLogEvent(any()), times(1));
    }

    @Test(description = "Does NOT trigger a diagnostic log event for non-numeric values when diagnostic logging is disabled")
    public void testGetOptionalIntParam_NonNumeric_NoDiagnosticLog_WhenDisabled() {

        // isDiagnosticLogsEnabled already returns false from setUp().
        Map<String, String> params = new HashMap<>();
        params.put(PARAM_NAME, "bad_value");

        AuthenticatorUtils.getOptionalIntParamFromRuntimeParams(params, PARAM_NAME);

        loggerUtilsMock.verify(() -> LoggerUtils.triggerDiagnosticLogEvent(any()), never());
    }

    // =========================================================================
    // logDiagnostic
    // =========================================================================

    @Test(description = "triggerDiagnosticLogEvent is called when diagnostic logging is enabled")
    public void testLogDiagnostic_WhenEnabled_CallsTrigger() {

        loggerUtilsMock.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(true);
        loggerUtilsMock.when(() -> LoggerUtils.triggerDiagnosticLogEvent(any())).thenAnswer(inv -> null);

        AuthenticatorUtils.logDiagnostic(
                "componentId",
                "actionId",
                "test message",
                DiagnosticLog.ResultStatus.SUCCESS,
                DiagnosticLog.LogDetailLevel.APPLICATION);

        loggerUtilsMock.verify(() -> LoggerUtils.triggerDiagnosticLogEvent(any()), times(1));
    }

    @Test(description = "triggerDiagnosticLogEvent is NOT called when diagnostic logging is disabled")
    public void testLogDiagnostic_WhenDisabled_DoesNotCallTrigger() {

        // isDiagnosticLogsEnabled returns false from setUp().
        AuthenticatorUtils.logDiagnostic(
                "componentId",
                "actionId",
                "test message",
                DiagnosticLog.ResultStatus.FAILED,
                DiagnosticLog.LogDetailLevel.APPLICATION);

        loggerUtilsMock.verify(() -> LoggerUtils.triggerDiagnosticLogEvent(any()), never());
    }

    @Test(description = "logDiagnostic does not throw for any ResultStatus value")
    public void testLogDiagnostic_AllResultStatuses_NoException() {

        loggerUtilsMock.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(true);
        loggerUtilsMock.when(() -> LoggerUtils.triggerDiagnosticLogEvent(any())).thenAnswer(inv -> null);

        // Should not throw for any status value.
        for (DiagnosticLog.ResultStatus status : DiagnosticLog.ResultStatus.values()) {
            AuthenticatorUtils.logDiagnostic("c", "a", "msg", status,
                    DiagnosticLog.LogDetailLevel.APPLICATION);
        }
    }

    @Test(description = "logDiagnostic does not throw for any LogDetailLevel value")
    public void testLogDiagnostic_AllLogDetailLevels_NoException() {

        loggerUtilsMock.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(true);
        loggerUtilsMock.when(() -> LoggerUtils.triggerDiagnosticLogEvent(any())).thenAnswer(inv -> null);

        for (DiagnosticLog.LogDetailLevel level : DiagnosticLog.LogDetailLevel.values()) {
            AuthenticatorUtils.logDiagnostic("c", "a", "msg",
                    DiagnosticLog.ResultStatus.SUCCESS, level);
        }
    }
}

