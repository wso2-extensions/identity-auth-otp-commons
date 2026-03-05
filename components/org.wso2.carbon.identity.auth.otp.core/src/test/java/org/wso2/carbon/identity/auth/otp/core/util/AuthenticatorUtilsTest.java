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

    @DataProvider(name = "getStringRuntimeParamByNameData")
    public Object[][] getStringRuntimeParamByNameData() {

        Map<String, String> presentParam = new HashMap<>();
        presentParam.put(PARAM_NAME, "hello");

        Map<String, String> otherParam = new HashMap<>();
        otherParam.put("otherParam", "value");

        Map<String, String> blankValue = new HashMap<>();
        blankValue.put(PARAM_NAME, "");

        Map<String, String> nullValue = new HashMap<>();
        nullValue.put(PARAM_NAME, null);

        return new Object[][] {
                {"Returns the value when the param exists in the map",
                        presentParam, true, "hello"},
                {"Returns empty when the param key is absent from the map",
                        otherParam, false, null},
                {"Returns empty when the runtime params map is null",
                        null, false, null},
                {"Returns empty when the runtime params map is empty",
                        Collections.emptyMap(), false, null},
                {"Returns empty when the param value is a blank string",
                        blankValue, false, null},
                {"Returns empty when the param value stored in the map is null",
                        nullValue, false, null},
        };
    }

    @Test(dataProvider = "getStringRuntimeParamByNameData",
            description = "getStringRuntimeParamByName returns expected Optional for various inputs")
    public void testGetStringRuntimeParamByName(String scenario, Map<String, String> params,
                                                boolean expectPresent, String expectedValue) {

        Optional<String> result = AuthenticatorUtils.getStringRuntimeParamByName(params, PARAM_NAME);
        Assert.assertEquals(result.isPresent(), expectPresent, scenario);
        if (expectPresent) {
            Assert.assertEquals(result.get(), expectedValue, scenario);
        }
    }

    @DataProvider(name = "getBooleanRuntimeParamByNameData")
    public Object[][] getBooleanRuntimeParamByNameData() {

        Map<String, String> trueParam = new HashMap<>();
        trueParam.put(PARAM_NAME, "true");

        Map<String, String> falseParam = new HashMap<>();
        falseParam.put(PARAM_NAME, "false");

        Map<String, String> upperCaseTrueParam = new HashMap<>();
        upperCaseTrueParam.put(PARAM_NAME, "TRUE");

        Map<String, String> nonBooleanParam = new HashMap<>();
        nonBooleanParam.put(PARAM_NAME, "yes");

        Map<String, String> otherParam = new HashMap<>();
        otherParam.put("otherParam", "true");

        return new Object[][] {
                {"Returns Optional.of(true) when the param value is 'true'",
                        trueParam, true, Boolean.TRUE},
                {"Returns Optional.of(false) when the param value is 'false'",
                        falseParam, true, Boolean.FALSE},
                {"Returns Optional.of(true) for 'TRUE' (case-insensitive)",
                        upperCaseTrueParam, true, Boolean.TRUE},
                {"Returns Optional.of(false) when the param value is a non-boolean string",
                        nonBooleanParam, true, Boolean.FALSE},
                {"Returns empty when the runtime params map is null",
                        null, false, null},
                {"Returns empty when the runtime params map is empty",
                        Collections.emptyMap(), false, null},
                {"Returns empty when the param key is absent",
                        otherParam, false, null},
        };
    }

    @Test(dataProvider = "getBooleanRuntimeParamByNameData",
            description = "getBooleanRuntimeParamByName returns expected Optional for various inputs")
    public void testGetBooleanRuntimeParamByName(String scenario, Map<String, String> params,
                                                 boolean expectPresent, Boolean expectedValue) {

        Optional<Boolean> result = AuthenticatorUtils.getBooleanRuntimeParamByName(params, PARAM_NAME);
        Assert.assertEquals(result.isPresent(), expectPresent, scenario);
        if (expectPresent) {
            Assert.assertEquals(result.get(), expectedValue, scenario);
        }
    }

    @DataProvider(name = "getIntRuntimeParamByNameData")
    public Object[][] getIntRuntimeParamByNameData() {

        Map<String, String> validIntParam = new HashMap<>();
        validIntParam.put(PARAM_NAME, "42");

        Map<String, String> zeroParam = new HashMap<>();
        zeroParam.put(PARAM_NAME, "0");

        Map<String, String> negativeParam = new HashMap<>();
        negativeParam.put(PARAM_NAME, "-5");

        Map<String, String> nonNumericParam = new HashMap<>();
        nonNumericParam.put(PARAM_NAME, "notAnInt");

        Map<String, String> decimalParam = new HashMap<>();
        decimalParam.put(PARAM_NAME, "3.14");

        Map<String, String> nullValueParam = new HashMap<>();
        nullValueParam.put(PARAM_NAME, null);

        Map<String, String> otherParam = new HashMap<>();
        otherParam.put("otherParam", "10");

        return new Object[][] {
                {"Returns the parsed integer when the param value is a valid integer string",
                        validIntParam, true, 42},
                {"Returns the parsed integer for a zero value",
                        zeroParam, true, 0},
                {"Returns the parsed integer for a negative value",
                        negativeParam, true, -5},
                {"Returns empty for a non-numeric value",
                        nonNumericParam, false, 0},
                {"Returns empty for a decimal string value",
                        decimalParam, false, 0},
                {"Returns empty when the runtime params map is null",
                        null, false, 0},
                {"Returns empty when the runtime params map is empty",
                        Collections.emptyMap(), false, 0},
                {"Returns empty when the param key is absent from the map",
                        otherParam, false, 0},
                {"Returns empty when the param value stored in the map is null",
                        nullValueParam, false, 0},
        };
    }

    @Test(dataProvider = "getIntRuntimeParamByNameData",
            description = "getIntRuntimeParamByName returns expected OptionalInt for various inputs")
    public void testGetIntRuntimeParamByName(String scenario, Map<String, String> params,
                                             boolean expectPresent, int expectedValue) {

        OptionalInt result = AuthenticatorUtils.getIntRuntimeParamByName(params, PARAM_NAME);
        Assert.assertEquals(result.isPresent(), expectPresent, scenario);
        if (expectPresent) {
            Assert.assertEquals(result.getAsInt(), expectedValue, scenario);
        }
    }

    @Test(description = "Triggers a diagnostic log event for non-numeric values when diagnostic logging is enabled")
    public void testGetIntRuntimeParamByNameNonNumericTriggersDiagnosticLogWhenEnabled() {

        loggerUtilsMock.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(true);
        loggerUtilsMock.when(() -> LoggerUtils.triggerDiagnosticLogEvent(any())).thenAnswer(inv -> null);
        Map<String, String> params = new HashMap<>();
        params.put(PARAM_NAME, "bad_value");
        OptionalInt result = AuthenticatorUtils.getIntRuntimeParamByName(params, PARAM_NAME);
        Assert.assertFalse(result.isPresent());
        loggerUtilsMock.verify(() -> LoggerUtils.triggerDiagnosticLogEvent(any()), times(1));
    }

    @Test(description = "Does NOT trigger a diagnostic log event for non-numeric values when diagnostic logging is disabled")
    public void testGetIntRuntimeParamByNameNonNumericNoDiagnosticLogWhenDisabled() {

        // isDiagnosticLogsEnabled already returns false from setUp().
        Map<String, String> params = new HashMap<>();
        params.put(PARAM_NAME, "bad_value");
        AuthenticatorUtils.getIntRuntimeParamByName(params, PARAM_NAME);
        loggerUtilsMock.verify(() -> LoggerUtils.triggerDiagnosticLogEvent(any()), never());
    }

    @DataProvider(name = "triggerDiagnosticLogData")
    public Object[][] triggerDiagnosticLogData() {

        return new Object[][] {
                {"triggerDiagnosticLogEvent is called when diagnostic logging is enabled",
                        true, DiagnosticLog.ResultStatus.SUCCESS, 1},
                {"triggerDiagnosticLogEvent is NOT called when diagnostic logging is disabled",
                        false, DiagnosticLog.ResultStatus.FAILED, 0},
        };
    }

    @Test(dataProvider = "triggerDiagnosticLogData",
            description = "triggerDiagnosticLog conditionally calls triggerDiagnosticLogEvent based on logging status")
    public void testTriggerDiagnosticLog(String scenario, boolean loggingEnabled,
                                         DiagnosticLog.ResultStatus status, int expectedInvocations) {

        loggerUtilsMock.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(loggingEnabled);
        loggerUtilsMock.when(() -> LoggerUtils.triggerDiagnosticLogEvent(any())).thenAnswer(inv -> null);
        AuthenticatorUtils.triggerDiagnosticLog(
                "componentId",
                "actionId",
                "test message",
                status,
                DiagnosticLog.LogDetailLevel.APPLICATION);
        loggerUtilsMock.verify(() -> LoggerUtils.triggerDiagnosticLogEvent(any()), times(expectedInvocations));
    }

    @Test(description = "triggerDiagnosticLog does not throw for any ResultStatus value")
    public void testTriggerDiagnosticLogAllResultStatusesNoException() {

        loggerUtilsMock.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(true);
        loggerUtilsMock.when(() -> LoggerUtils.triggerDiagnosticLogEvent(any())).thenAnswer(inv -> null);
        for (DiagnosticLog.ResultStatus status : DiagnosticLog.ResultStatus.values()) {
            AuthenticatorUtils.triggerDiagnosticLog("c", "a", "msg", status,
                    DiagnosticLog.LogDetailLevel.APPLICATION);
        }
    }

    @Test(description = "triggerDiagnosticLog does not throw for any LogDetailLevel value")
    public void testTriggerDiagnosticLogAllLogDetailLevelsNoException() {

        loggerUtilsMock.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(true);
        loggerUtilsMock.when(() -> LoggerUtils.triggerDiagnosticLogEvent(any())).thenAnswer(inv -> null);
        for (DiagnosticLog.LogDetailLevel level : DiagnosticLog.LogDetailLevel.values()) {
            AuthenticatorUtils.triggerDiagnosticLog("c", "a", "msg",
                    DiagnosticLog.ResultStatus.SUCCESS, level);
        }
    }
}
