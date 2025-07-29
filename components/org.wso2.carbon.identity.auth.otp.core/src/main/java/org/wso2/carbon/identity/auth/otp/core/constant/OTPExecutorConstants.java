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

package org.wso2.carbon.identity.auth.otp.core.constant;

/**
 * Constants for OTP executor.
 */
public class OTPExecutorConstants {

    private OTPExecutorConstants() {

    }

    public static final String OTP = "otp";
    public static final String OTP_RETRY_COUNT = "otpRetryCount";
    public static final String OTP_LENGTH = "otpLength";

    public enum OTPScenarios {

        INITIAL_OTP,
        RESEND_OTP
    }

    /**
     * Status codes for OTP executor.
     */
    public static class Status {

        public static final String SUCCESS = "success";
        public static final String OTP_EXPIRED = "otpExpired";
        public static final String CODE_MISMATCH = "codeMismatch";
    }

    /**
     * Logging constants for OTP executor.
     */
    public static class LogConstants {

        public static class ActionID {

            public static final String SEND_OTP = "send-otp";
            // process-otp
            public static final String PROCESS_OTP = "process-otp";
            public static final String VERIFY_OTP = "verify-otp";

        }
    }

    public static class OTPData {

        public static final String VALUE = "value";
        public static final String GENERATED_TIME_IN_MILLIS = "generatedTimeInMillis";
        public static final String VALIDITY_PERIOD_IN_MILLIS = "validityPeriodInMillis";
        public static final String EXPIRY_TIME_IN_MILLIS = "expiryTimeInMillis";
    }
}
