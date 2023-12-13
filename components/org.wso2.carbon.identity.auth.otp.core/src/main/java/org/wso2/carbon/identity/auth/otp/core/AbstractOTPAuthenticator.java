/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com).
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

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.extension.identity.helper.FederatedAuthenticatorUtil;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticationFlowHandler;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedIdPData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.JustInTimeProvisioningConfig;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants;
import org.wso2.carbon.identity.auth.otp.core.internal.AuthenticatorDataHolder;
import org.wso2.carbon.identity.auth.otp.core.model.OTP;
import org.wso2.carbon.identity.auth.otp.core.util.AuthenticatorUtils;
import org.wso2.carbon.identity.captcha.connector.recaptcha.SSOLoginReCaptchaConfig;
import org.wso2.carbon.identity.captcha.util.CaptchaConstants;
import org.wso2.carbon.identity.captcha.util.CaptchaUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.handler.event.account.lock.exception.AccountLockServiceException;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.User;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.RequestParams.IS_IDF_INITIATED_FROM_AUTHENTICATOR;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.AUTHENTICATORS;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.AUTHENTICATORS_QUERY_PARAM;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.AuthenticationScenarios.INITIAL_OTP;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.AuthenticationScenarios.LOGOUT;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.AuthenticationScenarios.RESEND_OTP;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.AuthenticationScenarios.SUBMIT_OTP;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.CODE;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.Claims.ACCOUNT_UNLOCK_TIME_CLAIM;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.DEFAULT_OTP_LENGTH;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.DEFAULT_OTP_RESEND_ATTEMPTS;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.DEFAULT_OTP_VALIDITY_IN_MILLIS;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ERROR_USER_ACCOUNT_LOCKED_QUERY_PARAMS;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ERROR_USER_CLAIM_NOT_FOUND_QUERY_PARAMS;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ERROR_USER_RESEND_COUNT_EXCEEDED_QUERY_PARAMS;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_EMPTY_OTP_CODE;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_EMPTY_USERNAME;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_ACCOUNT_UNLOCK_TIME;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_FEDERATED_AUTHENTICATOR;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_USER_CLAIM;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_USER_REALM;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_USER_STORE_MANAGER;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_REDIRECTING_TO_ERROR_PAGE;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_REDIRECTING_TO_IDF_PAGE;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_REDIRECTING_TO_LOGIN_PAGE;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_TRIGGERING_EVENT;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_GETTING_ACCOUNT_STATE;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_INVALID_FEDERATED_AUTHENTICATOR;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_NO_FEDERATED_USER;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_NO_USER_FOUND;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_OTP_EXPIRED;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_OTP_INVALID;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_RETRYING_OTP_RESEND;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_USER_ACCOUNT_LOCKED;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.FAILED_LOGIN_ATTEMPTS_CLAIM_URI;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.IDF_HANDLER_NAME;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.INVALID_USERNAME;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.IS_LOGIN_ATTEMPT_BY_INVALID_USER;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.LOCAL_AUTHENTICATOR;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.OTP;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.OTP_ALPHA_NUMERIC_CHAR_SET;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.OTP_NUMERIC_CHAR_SET;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.OTP_RESEND_ATTEMPTS;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.RECAPTCHA_PARAM;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.RESEND;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.RETRY_QUERY_PARAMS;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.SCREEN_VALUE_QUERY_PARAM;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.UNLOCK_QUERY_PARAM;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.USERNAME;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.USERNAME_PARAM;
import static org.wso2.carbon.identity.event.IdentityEventConstants.Event.POST_NON_BASIC_AUTHENTICATION;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.AUTHENTICATOR_NAME;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.OPERATION_STATUS;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.PROPERTY_FAILED_LOGIN_ATTEMPTS_CLAIM;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.USER_STORE_MANAGER;
import static org.wso2.carbon.user.core.UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME;

/**
 * This class contains the implementation of abstract OTP authenticator.
 */
public abstract class AbstractOTPAuthenticator extends AbstractApplicationAuthenticator {

    private static final Log LOG = LogFactory.getLog(AbstractOTPAuthenticator.class);

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {

        AuthenticatorConstants.AuthenticationScenarios scenario = resolveScenario(request, context);
        switch (scenario) {
            case LOGOUT:
                return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
            case INITIAL_OTP:
                initiateAuthenticationRequest(request, response, context);
                return AuthenticatorFlowStatus.INCOMPLETE;
            default:
                // Resend OTP and Submit OTP processing will be handled from here.
                return super.process(request, response, context);
        }
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        AuthenticatedUser authenticatedUserFromContext = getAuthenticatedUserFromContext(context);
        String applicationTenantDomain = context.getTenantDomain();

        /*
         * If an invalid user has attempted to log in by submitting an OTP code, or if an invalid user has requested
         * to resend the OTP code, they should be redirected to the OTP login page. This is only valid when OTP is
         * set as the first step of the authentication flow because in other cases, there will always be a valid user in
         * the context.
         */
        if (isLoginAttemptByInvalidUser(context, authenticatedUserFromContext)) {
            AuthenticatedUser invalidUser = new AuthenticatedUser();
            invalidUser.setUserName((String) context.getProperty(INVALID_USERNAME));
            redirectToOTPLoginPage(invalidUser, applicationTenantDomain, false,
                    response, request, context);
            return;
        }
        if (this instanceof PasswordlessOTPAuthenticator && isAuthenticatorEnabledForFirstFactor()) {
            if (authenticatedUserFromContext == null) {
                /*
                 * If there is no authenticated user, and the request is not returned from the Identifier First page,
                 * redirect the user to the Identifier First page to retrieve the username.
                 */
                if (!isUserRedirectedFromIDF(request)) {
                    redirectUserToIDF(request, response, context);
                    context.setProperty(IS_IDF_INITIATED_FROM_AUTHENTICATOR, true);
                    return;
                }
                // If the request is returned from the Identifier First page, resolve the user and set them in context.
                context.removeProperty(IS_IDF_INITIATED_FROM_AUTHENTICATOR);
                AuthenticatedUser authenticatedUser = resolveUserFromRequest(request, context);
                authenticatedUserFromContext = resolveUserFromUserStore(authenticatedUser);
                setResolvedUserInContext(context, authenticatedUserFromContext);
            } else if (isPreviousIdPAuthenticationFlowHandler(context)) {
                /*
                 * If the previous authentication has only been done by AuthenticationFlowHandlers, need to check if the
                 * user exists in the database.
                 */
                authenticatedUserFromContext = resolveUserFromUserStore(authenticatedUserFromContext);
                setResolvedUserInContext(context, authenticatedUserFromContext);
            }
             // If the authenticated user is still null at this point, then an invalid user is trying to log in.
            if (authenticatedUserFromContext == null) {
                AuthenticatedUser invalidUser = new AuthenticatedUser();
                invalidUser.setUserName(request.getParameter(USERNAME));
                context.setProperty(IS_LOGIN_ATTEMPT_BY_INVALID_USER, true);
                context.setProperty(INVALID_USERNAME, request.getParameter(USERNAME));
                redirectToOTPLoginPage(invalidUser, applicationTenantDomain, false,
                        response, request, context);
                return;
            }
        }

        /*
         * If we reach this point, a valid user is trying to log in.
         */
        context.removeProperty(IS_LOGIN_ATTEMPT_BY_INVALID_USER);
        context.removeProperty(INVALID_USERNAME);

        /*
         * We need to identify the username that the server is using to identify the user. This is needed to handle
         * federated scenarios, since for federated users, the username in the authentication context is not same as the
         * username when the user is provisioned to the server.
         */
        String mappedLocalUsername = getMappedLocalUsername(authenticatedUserFromContext, context);
        /*
         * If the mappedLocalUsername is blank, that means this is an initial login attempt by a non-provisioned
         * federated user.
         */
        boolean isInitialFederationAttempt = StringUtils.isBlank(mappedLocalUsername);
        AuthenticatedUser authenticatingUser = resolveAuthenticatingUser(authenticatedUserFromContext,
                mappedLocalUsername, applicationTenantDomain, isInitialFederationAttempt);
        try {
            if (!isInitialFederationAttempt
                && AuthenticatorDataHolder.getAccountLockService().isAccountLocked(
                    authenticatingUser.getUserName(),
                    authenticatingUser.getTenantDomain(),
                    authenticatingUser.getUserStoreDomain())
            ) {
                handleOTPForLockedUser(authenticatingUser, request, response, context);
                return;
            }
        } catch (AccountLockServiceException e) {
            String error = String.format(
                    ERROR_CODE_GETTING_ACCOUNT_STATE.getMessage(), authenticatingUser.getUserName());
            throw new AuthenticationFailedException(ERROR_CODE_GETTING_ACCOUNT_STATE.getCode(), error, e);
        }
        AuthenticatorConstants.AuthenticationScenarios scenario = resolveScenario(request, context);
        if (scenario == INITIAL_OTP || scenario == RESEND_OTP) {
            if (scenario == RESEND_OTP && context.getProperty(OTP_RESEND_ATTEMPTS) != null) {
                if (!StringUtils.isBlank(context.getProperty(OTP_RESEND_ATTEMPTS).toString())) {
                    int allowedResendAttemptsCount = getMaximumResendAttempts(applicationTenantDomain);
                    if ((int) context.getProperty(OTP_RESEND_ATTEMPTS) >= allowedResendAttemptsCount) {
                        handleOTPResendCountExceededScenario(request, response, context);
                        return;
                    }
                }
            }
            OTP otp = generateOTP(applicationTenantDomain);
            context.setProperty(OTP, otp);

            /*
             * Here we need to pass the authenticated user as the authenticated user from context since the events needs
             * to triggered against the context user.
             */
            try {
                sendOtp(authenticatedUserFromContext, otp, isInitialFederationAttempt, request, response, context);
                LOG.debug("OTP code was sent successfully.");
            } catch (AuthenticationFailedException exception) {
                String errorGettingUserClaimErrorCode = getAuthenticatorErrorPrefix() + "-"
                        + ERROR_CODE_ERROR_GETTING_USER_CLAIM.getCode();
                if (errorGettingUserClaimErrorCode.equals(exception.getErrorCode())) {
                    if (isOTPAsFirstFactor(context)) {
                        redirectToOTPLoginPage(authenticatedUserFromContext, applicationTenantDomain,
                                isInitialFederationAttempt, response, request, context);
                    } else {
                        String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(
                                context.getQueryParams(), context.getCallerSessionKey(),
                                context.getContextIdentifier());
                        redirectToErrorPage(request, response, context, queryParams,
                                ERROR_USER_CLAIM_NOT_FOUND_QUERY_PARAMS);
                    }
                    return;
                } else {
                    throw exception;
                }
            }

            if (scenario == RESEND_OTP) {
                updateResendCount(context);
            }
            publishPostOTPGeneratedEvent(otp, authenticatedUserFromContext, request, context);
        }
        redirectToOTPLoginPage(authenticatedUserFromContext, applicationTenantDomain, isInitialFederationAttempt,
                response, request, context);
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        AuthenticatedUser authenticatedUserFromContext = getAuthenticatedUserFromContext(context);
        if (authenticatedUserFromContext == null) {
            throw handleAuthErrorScenario(ERROR_CODE_NO_USER_FOUND);
        }
        String applicationTenantDomain = context.getTenantDomain();
        /*
         * We need to identify the username that the server is using to identify the user. This is needed to handle
         * federated scenarios, since for federated users, the username in the authentication context is not same as the
         * username when the user is provisioned to the server.
         */
        String mappedLocalUsername = getMappedLocalUsername(authenticatedUserFromContext, context);
        /*
         * If the mappedLocalUsername is blank, that means this is an initial login attempt by a non-provisioned
         * federated user.
         */
        boolean isInitialFederationAttempt = StringUtils.isBlank(mappedLocalUsername);
        AuthenticatedUser authenticatingUser = resolveAuthenticatingUser(authenticatedUserFromContext,
                mappedLocalUsername, applicationTenantDomain, isInitialFederationAttempt);
        try {
            if (!isInitialFederationAttempt
                    && AuthenticatorDataHolder.getAccountLockService().isAccountLocked(
                    authenticatingUser.getUserName(), authenticatingUser.getTenantDomain(),
                    authenticatingUser.getUserStoreDomain())) {
                throw handleAuthErrorScenario(ERROR_CODE_USER_ACCOUNT_LOCKED, authenticatingUser.getUserName());
            }
        } catch (AccountLockServiceException e) {
            throw handleAuthErrorScenario(ERROR_CODE_GETTING_ACCOUNT_STATE, e);
        }

        /* If user requests a resend, throw error */
        if (Boolean.parseBoolean(request.getParameter(RESEND))) {
            throw handleInvalidCredentialsScenario(ERROR_CODE_RETRYING_OTP_RESEND,
                    authenticatedUserFromContext.getUserName());
        }
        /* If an empty code is received, throw error. */
        if (StringUtils.isBlank(request.getParameter(CODE))) {
            throw handleInvalidCredentialsScenario(ERROR_CODE_EMPTY_OTP_CODE,
                    authenticatedUserFromContext.getUserName());
        }
        boolean isSuccessfulAttempt = isSuccessfulAuthAttempt(request.getParameter(CODE), authenticatingUser, context);
        OTP otpInContext = (OTP) context.getParameter(OTP);
        if (isSuccessfulAttempt) {
            // It reached here means the authentication was successful.
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("User: %s authenticated successfully via OTP",
                        authenticatedUserFromContext.getUserName()));
            }
            if (!isInitialFederationAttempt) {
                // A mapped user is not available for isInitialFederationAttempt true scenario.
                resetOtpFailedAttempts(authenticatingUser);
            }
            publishPostOTPValidatedEvent(otpInContext, authenticatedUserFromContext, true, false, request, context);
            return;
        }
        /*
         * Handle when the OTP is unsuccessful. At this point user account is not locked. Locked scenario is
         * handled from the above steps.
         */
        if (!isInitialFederationAttempt) {
            // A mapped user is not available for isInitialFederationAttempt true scenario.
            handleOtpVerificationFail(authenticatingUser);
        }
        if (otpInContext != null && otpInContext.isExpired()) {
            publishPostOTPValidatedEvent(otpInContext, authenticatedUserFromContext, false,
                    true, request, context);
            throw handleAuthErrorScenario(ERROR_CODE_OTP_EXPIRED, authenticatedUserFromContext.getUserName());
        } else {
            publishPostOTPValidatedEvent(otpInContext, authenticatedUserFromContext, false,
                    false, request, context);
            throw handleAuthErrorScenario(ERROR_CODE_OTP_INVALID, authenticatedUserFromContext.getUserName());
        }
    }

    /**
     * Handle OTP for account locked users.
     *
     * @param authenticatedUser Authenticated user provisioned in the server.
     * @param response          HttpServletResponse.
     * @param context           AuthenticationContext.
     * @throws AuthenticationFailedException If an error occurred.
     */
    private void handleOTPForLockedUser(AuthenticatedUser authenticatedUser, HttpServletRequest request,
                                        HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                context.getCallerSessionKey(), context.getContextIdentifier());
        // By default, we are showing the authentication failure reason here.
        long unlockTime = getUnlockTimeInMilliSeconds(authenticatedUser);
        long timeToUnlock = unlockTime - System.currentTimeMillis();
        if (timeToUnlock > 0) {
            queryParams += UNLOCK_QUERY_PARAM + Math.round((double) timeToUnlock / 1000 / 60);
        }
        redirectToErrorPage(request, response, context, queryParams, ERROR_USER_ACCOUNT_LOCKED_QUERY_PARAMS);
    }

    /**
     * Get user account unlock time in milliseconds. If no value configured for unlock time user claim, return 0.
     *
     * @param authenticatedUser The authenticated user.
     * @return User account unlock time in milliseconds. If no value is configured return 0.
     * @throws AuthenticationFailedException If an error occurred while getting the user unlock time.
     */
    private long getUnlockTimeInMilliSeconds(AuthenticatedUser authenticatedUser) throws AuthenticationFailedException {

        String username = authenticatedUser.toFullQualifiedUsername();
        String accountLockedTime = getUserClaimValueFromUserStore(ACCOUNT_UNLOCK_TIME_CLAIM, authenticatedUser,
                ERROR_CODE_ERROR_GETTING_ACCOUNT_UNLOCK_TIME);
        if (StringUtils.isBlank(accountLockedTime)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("No value configured for claim: %s for user: %s", ACCOUNT_UNLOCK_TIME_CLAIM,
                        username));
            }
            return 0;
        }
        return Long.parseLong(accountLockedTime);
    }

    /**
     * Get user claim value.
     *
     * @param claimUri          Claim uri.
     * @param authenticatedUser AuthenticatedUser.
     * @param error             Error associated with the claim retrieval.
     * @return User claim value.
     * @throws AuthenticationFailedException If an error occurred while getting the claim value.
     */
    protected String getUserClaimValueFromUserStore(String claimUri, AuthenticatedUser authenticatedUser,
                                                    AuthenticatorConstants.ErrorMessages error)
            throws AuthenticationFailedException {

        UserStoreManager userStoreManager = getUserStoreManager(authenticatedUser);
        try {
            Map<String, String> claimValues =
                    userStoreManager.getUserClaimValues(MultitenantUtils.getTenantAwareUsername(
                            authenticatedUser.toFullQualifiedUsername()), new String[]{claimUri}, null);
            return claimValues.get(claimUri);
        } catch (UserStoreException e) {
            throw handleAuthErrorScenario(error, e, authenticatedUser.getUserName());
        }
    }

    /**
     * Get UserStoreManager for the given user.
     *
     * @param authenticatedUser AuthenticatedUser.
     * @return UserStoreManager.
     * @throws AuthenticationFailedException If an error occurred while getting the UserStoreManager.
     */
    private UserStoreManager getUserStoreManager(AuthenticatedUser authenticatedUser)
            throws AuthenticationFailedException {

        UserRealm userRealm = getTenantUserRealm(authenticatedUser.getTenantDomain());
        String username = MultitenantUtils.getTenantAwareUsername(authenticatedUser.toFullQualifiedUsername());
        String userStoreDomain = authenticatedUser.getUserStoreDomain();
        try {
            UserStoreManager userStoreManager = userRealm.getUserStoreManager();
            if (userStoreManager == null) {
                throw handleAuthErrorScenario(ERROR_CODE_ERROR_GETTING_USER_STORE_MANAGER, username);
            }
            if (StringUtils.isBlank(userStoreDomain) || PRIMARY_DEFAULT_DOMAIN_NAME.equals(userStoreDomain)) {
                return userStoreManager;
            }
            return ((AbstractUserStoreManager) userStoreManager).getSecondaryUserStoreManager(userStoreDomain);
        } catch (UserStoreException e) {
            throw handleAuthErrorScenario(ERROR_CODE_ERROR_GETTING_USER_STORE_MANAGER, e, username);
        }
    }

    /**
     * Get the UserRealm for the user given user.
     *
     * @param tenantDomain Tenant domain.
     * @return UserRealm.
     * @throws AuthenticationFailedException If an error occurred while getting the UserRealm.
     */
    private UserRealm getTenantUserRealm(String tenantDomain) throws AuthenticationFailedException {

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        UserRealm userRealm;
        try {
            userRealm = (AuthenticatorDataHolder.getRealmService()).getTenantUserRealm(tenantId);
        } catch (UserStoreException e) {
            throw handleAuthErrorScenario(ERROR_CODE_ERROR_GETTING_USER_REALM, e, tenantDomain);
        }
        if (userRealm == null) {
            throw handleAuthErrorScenario(ERROR_CODE_ERROR_GETTING_USER_REALM, tenantDomain);
        }
        return userRealm;
    }

    /**
     * Retrieve the provisioned username of the authenticated user. If this is a federated scenario, the
     * authenticated username will be same as the username in context. If the flow is for a JIT provisioned user, the
     * provisioned username will be returned.
     *
     * @param authenticatedUser AuthenticatedUser.
     * @param context           AuthenticationContext.
     * @return Provisioned username
     * @throws AuthenticationFailedException If an error occurred while getting the provisioned username.
     */
    private String getMappedLocalUsername(AuthenticatedUser authenticatedUser, AuthenticationContext context)
            throws AuthenticationFailedException {

        if (!authenticatedUser.isFederatedUser()) {
            return authenticatedUser.getUserName();
        }
        // If the user is federated, we need to check whether the user is already provisioned to the organization.
        String federatedUsername = FederatedAuthenticatorUtil.getLoggedInFederatedUser(context);
        if (StringUtils.isBlank(federatedUsername)) {
            throw handleAuthErrorScenario(ERROR_CODE_NO_FEDERATED_USER);
        }
        String associatedLocalUsername =
                FederatedAuthenticatorUtil.getLocalUsernameAssociatedWithFederatedUser(MultitenantUtils.
                        getTenantAwareUsername(federatedUsername), context);
        if (StringUtils.isNotBlank(associatedLocalUsername)) {
            return associatedLocalUsername;
        }
        return null;
    }

    /**
     * Identify the AuthenticatedUser that the authenticator trying to authenticate. This needs to be done to
     * identify the locally mapped user for federated authentication scenarios.
     *
     * @param authenticatedUserInContext AuthenticatedUser retrieved from context.
     * @param mappedLocalUsername        Mapped local username if available.
     * @param tenantDomain               Application tenant domain.
     * @param isInitialFederationAttempt Whether auth attempt by a not JIT provisioned federated user.
     * @return AuthenticatedUser that the authenticator trying to authenticate.
     * @throws AuthenticationFailedException If an error occurred.
     */
    private AuthenticatedUser resolveAuthenticatingUser(AuthenticatedUser authenticatedUserInContext,
                                                        String mappedLocalUsername,
                                                        String tenantDomain, boolean isInitialFederationAttempt)
            throws AuthenticationFailedException {

        // This is a federated initial authentication scenario.
        if (isInitialFederationAttempt) {
            return authenticatedUserInContext;
        }
        // Handle local users.
        if (!authenticatedUserInContext.isFederatedUser()) {
            return authenticatedUserInContext;
        }
        /*
         * At this point, the authenticating user is in our system but has a different mapped username compared to the
         * identifier that is in the authentication context. Therefore, we need to have a new AuthenticatedUser object
         * with the mapped local username to identify the user.
         */
        AuthenticatedUser authenticatingUser = new AuthenticatedUser(authenticatedUserInContext);
        authenticatingUser.setUserName(mappedLocalUsername);
        authenticatingUser.setUserStoreDomain(getFederatedUserStoreDomain(authenticatedUserInContext, tenantDomain));
        return authenticatingUser;
    }

    /**
     * Get the authenticated user by iterating though auth steps.
     *
     * @param context AuthenticationContext.
     * @return AuthenticatedUser.
     * @throws AuthenticationFailedException If no authenticated user was found.
     */
    private AuthenticatedUser getAuthenticatedUserFromContext(AuthenticationContext context)
            throws AuthenticationFailedException {

        Map<Integer, StepConfig> stepConfigMap = context.getSequenceConfig().getStepMap();
        for (StepConfig stepConfig : stepConfigMap.values()) {
            AuthenticatedUser user = stepConfig.getAuthenticatedUser();
            if (stepConfig.isSubjectAttributeStep() && user != null) {
                AuthenticatedUser authenticatedUser = new AuthenticatedUser(user);
                if (StringUtils.isBlank(authenticatedUser.toFullQualifiedUsername())) {
                    LOG.debug("Username can not be empty");
                    throw handleAuthErrorScenario(ERROR_CODE_EMPTY_USERNAME);
                }
                return authenticatedUser;
            }
        }

        StepConfig currentStepConfig = stepConfigMap.get(context.getCurrentStep());
        if (currentStepConfig.isSubjectAttributeStep()) {
            return null;
        }

        // If authenticated user cannot be found from the previous steps.
        throw handleAuthErrorScenario(ERROR_CODE_NO_USER_FOUND);
    }

    protected AuthenticationFailedException handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages error) {

        return handleAuthErrorScenario(error, (Object) null);
    }

    protected AuthenticationFailedException handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages error,
                                                                    Object... data) {

        return handleAuthErrorScenario(error, null, data);
    }

    /**
     * Handle the scenario by returning AuthenticationFailedException which has the details of the error scenario.
     *
     * @param error     {@link AuthenticatorConstants.ErrorMessages} error message.
     * @param throwable Throwable.
     * @param data      Additional data related to the scenario.
     * @return AuthenticationFailedException.
     */
    protected AuthenticationFailedException handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages error,
                                                                    Throwable throwable, Object... data) {

        String message = error.getMessage();
        if (data != null) {
            message = String.format(message, data);
        }
        String errorCode = getAuthenticatorErrorPrefix() + "-" + error.getCode();
        if (throwable == null) {
            return new AuthenticationFailedException(errorCode, message);
        }
        return new AuthenticationFailedException(errorCode, message, throwable);
    }

    /**
     * To redirect flow to error page with specific condition.
     *
     * @param response    The httpServletResponse.
     * @param context     The AuthenticationContext.
     * @param queryParams The query params.
     * @param retryParam  The retry param.
     * @throws AuthenticationFailedException If an error occurred.
     */
    private void redirectToErrorPage(HttpServletRequest request, HttpServletResponse response,
                                     AuthenticationContext context, String queryParams, String retryParam)
            throws AuthenticationFailedException {

        try {
            String multiOptionURIQueryString = AuthenticatorUtils.getMultiOptionURIQueryString(request);
            String queryString = queryParams + AUTHENTICATORS_QUERY_PARAM + getName() +
                    USERNAME_PARAM + context.getLastAuthenticatedUser().getUserName() + retryParam
                    + multiOptionURIQueryString;
            String errorPage = getErrorPageURL(context);
            String url = FrameworkUtils.appendQueryParamsStringToUrl(errorPage, queryString);
            response.sendRedirect(url);
        } catch (IOException e) {
            throw handleAuthErrorScenario(ERROR_CODE_ERROR_REDIRECTING_TO_ERROR_PAGE, e, (Object) null);
        }
    }

    /**
     * Handle OTP resend attempts count exceeded scenarios.
     *
     * @param request  HttpServletRequest.
     * @param response HttpServletResponse.
     * @param context  AuthenticationContext.
     * @throws AuthenticationFailedException If an error occurred.
     */
    private void handleOTPResendCountExceededScenario(HttpServletRequest request,
                                                      HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                context.getCallerSessionKey(), context.getContextIdentifier());
        redirectToErrorPage(request, response, context, queryParams, ERROR_USER_RESEND_COUNT_EXCEEDED_QUERY_PARAMS);
    }

    protected AuthenticatorConstants.AuthenticationScenarios resolveScenario(HttpServletRequest request,
                                                                             AuthenticationContext context) {

        if (context.isLogoutRequest()) {
            return LOGOUT;
        } else if (!context.isRetrying() && StringUtils.isBlank(request.getParameter(CODE)) &&
                StringUtils.isBlank(request.getParameter(RESEND))) {
            return INITIAL_OTP;
        } else if (context.isRetrying() && StringUtils.isNotBlank(request.getParameter(RESEND)) &&
                Boolean.parseBoolean(request.getParameter(RESEND))) {
            return RESEND_OTP;
        }
        return SUBMIT_OTP;
    }

    /**
     * To redirect the flow to otp login page to enter an OTP.
     *
     * @param response      HttpServletResponse.
     * @param request       HttpServletRequest.
     * @param context       AuthenticationContext.
     * @throws AuthenticationFailedException If an error occurred while redirecting to otp login page.
     */
    protected void redirectToOTPLoginPage(AuthenticatedUser authenticatedUser, String tenantDomain,
                                          boolean isInitialFederationAttempt, HttpServletResponse response,
                                          HttpServletRequest request, AuthenticationContext context)
            throws AuthenticationFailedException {

        String username = authenticatedUser.getUserName();
        StringBuilder queryParamsBuilder = new StringBuilder();
        String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                context.getCallerSessionKey(), context.getContextIdentifier());
        String multiOptionURI = AuthenticatorUtils.getMultiOptionURIQueryString(request);
        queryParamsBuilder.append(queryParams)
                .append(AUTHENTICATORS_QUERY_PARAM).append(getName())
                .append(USERNAME_PARAM).append(username)
                .append(multiOptionURI);

        if (!isOTPAsFirstFactor(context)) {
            String maskedUserClaimValue = getMaskedUserClaimValue(authenticatedUser, tenantDomain,
                    isInitialFederationAttempt, context);
            if (!StringUtils.isBlank(maskedUserClaimValue)) {
                String screenValueQueryParam = SCREEN_VALUE_QUERY_PARAM
                        + getMaskedUserClaimValue(authenticatedUser, tenantDomain,
                        isInitialFederationAttempt, context);
                queryParamsBuilder.append(screenValueQueryParam);
            }
        }
        if (context.isRetrying() && !Boolean.parseBoolean(request.getParameter(RESEND))) {
            queryParamsBuilder.append(RETRY_QUERY_PARAMS);
        }
        if (isOTPAsFirstFactor(context)) {
            String captchaParams = getCaptchaParams(context, tenantDomain, authenticatedUser);
            queryParamsBuilder.append(captchaParams);
        }
        try {
            String otpLoginPage = getOTPLoginPageURL(context);
            String url = FrameworkUtils.appendQueryParamsStringToUrl(otpLoginPage, queryParamsBuilder.toString());
            response.sendRedirect(url);
        } catch (IOException e) {
            throw handleAuthErrorScenario(ERROR_CODE_ERROR_REDIRECTING_TO_LOGIN_PAGE, e, (Object) null);
        }
    }

    /**
     * Get the JIT provisioning user store domain of the authenticated user.
     *
     * @param user         AuthenticatedUser.
     * @param tenantDomain Tenant domain.
     * @return JIT provisioning user store domain.
     * @throws AuthenticationFailedException If an error occurred.
     */
    private String getFederatedUserStoreDomain(AuthenticatedUser user, String tenantDomain)
            throws AuthenticationFailedException {

        String federatedIdp = user.getFederatedIdPName();
        IdentityProvider idp = getIdentityProvider(federatedIdp, tenantDomain);
        JustInTimeProvisioningConfig provisioningConfig = idp.getJustInTimeProvisioningConfig();
        if (provisioningConfig == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("No JIT provisioning configs for idp: %s in tenant: %s", federatedIdp,
                        tenantDomain));
            }
            return null;
        }
        String provisionedUserStore = provisioningConfig.getProvisioningUserStore();
        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("Setting user store: %s as the provisioning user store for user: %s in tenant: %s",
                    provisionedUserStore, user.getUserName(), tenantDomain));
        }
        return provisionedUserStore;
    }

    private IdentityProvider getIdentityProvider(String idpName, String tenantDomain) throws
            AuthenticationFailedException {

        try {
            IdentityProvider idp = AuthenticatorDataHolder.getIdpManager().getIdPByName(idpName, tenantDomain);
            if (idp == null) {
                throw handleAuthErrorScenario(ERROR_CODE_INVALID_FEDERATED_AUTHENTICATOR, idpName, tenantDomain);
            }
            return idp;
        } catch (IdentityProviderManagementException e) {
            throw handleAuthErrorScenario(ERROR_CODE_ERROR_GETTING_FEDERATED_AUTHENTICATOR, idpName, tenantDomain);
        }
    }

    private InvalidCredentialsException handleInvalidCredentialsScenario(AuthenticatorConstants.ErrorMessages error,
                                                                         String... data) {

        String message = error.getMessage();
        if (data != null) {
            message = String.format(message, (Object) data);
        }
        LOG.debug(message);
        return new InvalidCredentialsException(error.getCode(), message);
    }

    /**
     * Check whether the given OTP value is valid.
     *
     * @param userToken    User given otp.
     * @param user         AuthenticatedUser.
     * @param context      AuthenticationContext.
     * @return True if the OTP is valid.
     * @throws AuthenticationFailedException If error occurred while validating the OTP.
     */
    private boolean isSuccessfulAuthAttempt(String userToken, AuthenticatedUser user, AuthenticationContext context)
            throws AuthenticationFailedException {

        OTP otpInfoInContext = (OTP) context.getProperty(OTP);
        if (StringUtils.isBlank(userToken)) {
            throw handleAuthErrorScenario(ERROR_CODE_EMPTY_OTP_CODE, user.getUserName());
        }
        if (otpInfoInContext == null || StringUtils.isBlank(otpInfoInContext.getValue())) {
            return false;
        }
        boolean isExpired = otpInfoInContext.isExpired();
        if (userToken.equals(otpInfoInContext.getValue())) {
            if (isExpired) {
                return false;
            } else {
                context.setProperty(OTP, null);
                context.setSubject(user);
                return true;
            }
        }  else {
            // This is the OTP mismatched scenario.
            if (LOG.isDebugEnabled()) {
                LOG.debug("Invalid OTP given by the user: " + user.getUserName());
            }
            return false;
        }
    }

    /**
     * Generate the OTP according to the configuration parameters.
     *
     * @param tenantDomain Tenant domain.
     * @return Generated OTP.
     * @throws AuthenticationFailedException If an error occurred.
     */
    protected OTP generateOTP(String tenantDomain) throws AuthenticationFailedException {

        String charSet = getOTPCharset(tenantDomain);
        int otpLength = getOTPLength(tenantDomain);

        char[] chars = charSet.toCharArray();
        SecureRandom secureRandom = new SecureRandom();
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < otpLength; i++) {
            stringBuilder.append(chars[secureRandom.nextInt(chars.length)]);
        }
        String token = stringBuilder.toString();
        return new OTP(token, System.currentTimeMillis(), getOtpValidityPeriodInMillis(tenantDomain));
    }

    /**
     * Get the number of maximum attempts the user is allowed resend the OTP.
     *
     * @param tenantDomain  Tenant Domain.
     * @return The maximum number of resend attempts.
     * @throws AuthenticationFailedException If an error occurs when retrieving config.
     */
    protected int getMaximumResendAttempts(String tenantDomain) throws AuthenticationFailedException {

        return DEFAULT_OTP_RESEND_ATTEMPTS;
    }

    /**
     * Initialize or increment the number of times the OTP was resent to the user.
     *
     * @param context   Authentication Context.
     */
    private void updateResendCount(AuthenticationContext context) {

        if (context.getProperty(OTP_RESEND_ATTEMPTS) == null ||
                StringUtils.isBlank(context.getProperty(OTP_RESEND_ATTEMPTS).toString())) {
            context.setProperty(OTP_RESEND_ATTEMPTS, 1);
        } else {
            context.setProperty(OTP_RESEND_ATTEMPTS, (int) context.getProperty(OTP_RESEND_ATTEMPTS) + 1);
        }
    }

    /**
     * This method defines the character set used for the OTP generation.
     *
     * @param tenantDomain  Tenant Domain.
     * @return Character set.
     * @throws AuthenticationFailedException If an error occurs when retrieving config.
     */
    private String getOTPCharset(String tenantDomain) throws AuthenticationFailedException {

        boolean useOnlyNumericChars = useOnlyNumericChars(tenantDomain);
        if (useOnlyNumericChars) {
            return OTP_NUMERIC_CHAR_SET;
        }
        return OTP_ALPHA_NUMERIC_CHAR_SET;
    }

    /**
     * This method defines the length of the OTP to be generated.
     *
     * @param tenantDomain  Tenant Domain.
     * @return length of the OTP.
     * @throws AuthenticationFailedException If an error occurs when retrieving the value.
     */
    protected int getOTPLength(String tenantDomain) throws AuthenticationFailedException {

        return DEFAULT_OTP_LENGTH;
    }

    /**
     * This method defines whether the OTP should consist of only numeric characters.
     * Alternative is to use alphanumeric characters.
     *
     * @param tenantDomain  Tenant Domain.
     * @return if the OTP should consist of only numeric characters.
     * @throws AuthenticationFailedException If an error occurs when retrieving the value.
     */
    protected boolean useOnlyNumericChars(String tenantDomain) throws AuthenticationFailedException {

        return true;
    }

    /**
     * This method defines validity period of the OTP set for the tenant domain.
     *
     * @param tenantDomain  Tenant Domain.
     * @return validity period in milliseconds.
     */
    protected long getOtpValidityPeriodInMillis(String tenantDomain) throws AuthenticationFailedException {

        return DEFAULT_OTP_VALIDITY_IN_MILLIS;
    }

    /**
     * This method defines URI of the claim used to determine if the user account should be locked/unlocked
     * after an authentication attempt completes.
     *
     * @return the URI of the claim that counts consecutive invalid login attempts.
     */
    protected String getOTPFailedAttemptsClaimUri() throws AuthenticationFailedException {

        return FAILED_LOGIN_ATTEMPTS_CLAIM_URI;
    }

    /**
     * Execute account lock flow for OTP verification failures. By default, the OTP
     * authenticator will support account lock on failed attempts if the account locking is enabled for the tenant.
     *
     * @param user AuthenticatedUser.
     * @throws AuthenticationFailedException If an error occurred while resetting the OTP failed attempts.
     */
    protected void handleOtpVerificationFail(AuthenticatedUser user) throws AuthenticationFailedException {

        UserStoreManager userStoreManager = getUserStoreManager(user);
        // Add required meta properties to the event.
        Map<String, Object> metaProperties = new HashMap<>();
        metaProperties.put(AUTHENTICATOR_NAME, getName());
        metaProperties.put(PROPERTY_FAILED_LOGIN_ATTEMPTS_CLAIM, getOTPFailedAttemptsClaimUri());
        metaProperties.put(USER_STORE_MANAGER, userStoreManager);
        metaProperties.put(OPERATION_STATUS, false);

        triggerEvent(POST_NON_BASIC_AUTHENTICATION, user, metaProperties);
    }

    /**
     * Trigger event.
     *
     * @param eventName      Event name.
     * @param user           Authenticated user.
     * @param eventProperties Meta details.
     * @throws AuthenticationFailedException If an error occurred while triggering the event.
     */
    protected void triggerEvent(String eventName, AuthenticatedUser user,
                                Map<String, Object> eventProperties) throws AuthenticationFailedException {

        HashMap<String, Object> properties = new HashMap<>();
        properties.put(IdentityEventConstants.EventProperty.USER_NAME, user.getUserName());
        properties.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, user.getUserStoreDomain());
        properties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, user.getTenantDomain());
        if (eventProperties != null) {
            for (Map.Entry<String, Object> metaProperty : eventProperties.entrySet()) {
                if (StringUtils.isNotBlank(metaProperty.getKey()) && metaProperty.getValue() != null) {
                    properties.put(metaProperty.getKey(), metaProperty.getValue());
                }
            }
        }
        Event identityMgtEvent = new Event(eventName, properties);
        try {
            AuthenticatorDataHolder.getIdentityEventService().handleEvent(identityMgtEvent);
        } catch (IdentityEventException e) {
            throw handleAuthErrorScenario(ERROR_CODE_ERROR_TRIGGERING_EVENT, e, eventName, user.getUserName());
        }
    }

    /**
     * This method is used to redirect the user to the username entering page (IDF: Identifier first).
     *
     * @param request  Request.
     * @param response Response.
     * @param context  The authentication context.
     * @throws AuthenticationFailedException If an error occurred while setting redirect url.
     */
    @SuppressFBWarnings("UNVALIDATED_REDIRECT")
    private void redirectUserToIDF(HttpServletRequest request, HttpServletResponse response,
                                   AuthenticationContext context) throws AuthenticationFailedException {

        StringBuilder redirectUrl = new StringBuilder();
        String loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL();
        redirectUrl.append(loginPage);
        redirectUrl.append("?");

        String queryParams = context.getContextIdIncludedQueryParams();
        String multiOptionURI = AuthenticatorUtils.getMultiOptionURIQueryString(request);
        try {
            LOG.debug("Redirecting to identifier first flow since no authenticated user was found");
            if (queryParams != null) {
                redirectUrl.append(queryParams);
                redirectUrl.append("&");
            }
            redirectUrl.append(AUTHENTICATORS);
            redirectUrl.append(IDF_HANDLER_NAME);
            redirectUrl.append(":");
            redirectUrl.append(LOCAL_AUTHENTICATOR);
            redirectUrl.append(multiOptionURI);
            response.sendRedirect(redirectUrl.toString());
        } catch (IOException e) {
            throw handleAuthErrorScenario(ERROR_CODE_ERROR_REDIRECTING_TO_IDF_PAGE);
        }
    }

    /**
     * This method is used to resolve the user from authentication request from identifier handler.
     *
     * @param request The httpServletRequest.
     * @param context The authentication context.
     * @throws AuthenticationFailedException In occasions of failing.
     */
    private AuthenticatedUser resolveUserFromRequest(HttpServletRequest request, AuthenticationContext context)
            throws AuthenticationFailedException {

        String identifierFromRequest = request.getParameter(USERNAME);
        if (StringUtils.isBlank(identifierFromRequest)) {
            throw handleAuthErrorScenario(ERROR_CODE_EMPTY_USERNAME);
        }
        String username = FrameworkUtils.preprocessUsername(identifierFromRequest, context);
        AuthenticatedUser user = new AuthenticatedUser();
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
        String userStoreDomain = UserCoreUtil.extractDomainFromName(username);
        String tenantDomain = MultitenantUtils.getTenantDomain(username);

        user.setAuthenticatedSubjectIdentifier(tenantAwareUsername);
        user.setUserName(tenantAwareUsername);
        user.setUserStoreDomain(userStoreDomain);
        user.setTenantDomain(tenantDomain);
        return user;
    }

    /**
     * This method checks if all the authentication steps up to now have been performed by authenticators that
     * implements AuthenticationFlowHandler interface. If so, it returns true.
     * AuthenticationFlowHandlers may not perform actual authentication though the authenticated user is set in the
     * context. Hence, this method can be used to determine if the user has been authenticated by a previous step.
     *
     * @param context   AuthenticationContext.
     * @return True if all the authentication steps up to now have been performed by AuthenticationFlowHandlers.
     */
    private boolean isPreviousIdPAuthenticationFlowHandler(AuthenticationContext context) {

        Map<String, AuthenticatedIdPData> currentAuthenticatedIdPs = context.getCurrentAuthenticatedIdPs();
        return currentAuthenticatedIdPs != null && !currentAuthenticatedIdPs.isEmpty() &&
                currentAuthenticatedIdPs.values().stream().filter(Objects::nonNull)
                        .map(AuthenticatedIdPData::getAuthenticators).filter(Objects::nonNull)
                        .flatMap(List::stream)
                        .allMatch(authenticator ->
                                authenticator.getApplicationAuthenticator() instanceof AuthenticationFlowHandler);
    }

    /**
     * This method is used to resolve an authenticated user from the user stores.
     *
     * @param authenticatedUser The authenticated user.
     * @return Authenticated user retrieved from the user store.
     * @throws AuthenticationFailedException In occasions of failing.
     */
    private AuthenticatedUser resolveUserFromUserStore(AuthenticatedUser authenticatedUser)
            throws AuthenticationFailedException {

        User user = getUser(authenticatedUser);
        if (user == null) {
            return null;
        }
        authenticatedUser = new AuthenticatedUser(user);
        authenticatedUser.setAuthenticatedSubjectIdentifier(user.getUsername());
        return authenticatedUser;
    }

    /**
     * This method is used to set the resolved user in context.
     *
     * @param context           The authentication context.
     * @param authenticatedUser The authenticated user.
     */
    private void setResolvedUserInContext(AuthenticationContext context, AuthenticatedUser authenticatedUser) {

        if (authenticatedUser != null) {
            Map<Integer, StepConfig> stepConfigMap = context.getSequenceConfig().getStepMap();
            StepConfig currentStepConfig = stepConfigMap.get(context.getCurrentStep());
            if (currentStepConfig.isSubjectAttributeStep()) {
                context.setSubject(authenticatedUser);
                currentStepConfig.setAuthenticatedUser(authenticatedUser);
                currentStepConfig.setAuthenticatedIdP(LOCAL_AUTHENTICATOR);
            }
        }
    }

    /**
     * Append the recaptcha related params if recaptcha is enabled for OTP authenticator.
     *
     * @param context           Authentication context.
     * @param tenantDomain      Tenant domain.
     * @param authenticatedUser Authenticated User.
     * @return String with the appended recaptcha params.
     */
    private String getCaptchaParams(AuthenticationContext context, String tenantDomain,
                                    AuthenticatedUser authenticatedUser) {

        if (!isOTPAsFirstFactor(context)) {
            return StringUtils.EMPTY;
        }

        SSOLoginReCaptchaConfig connector = new SSOLoginReCaptchaConfig();
        String captchaEnabledConfigName = connector.getName() +
                CaptchaConstants.ReCaptchaConnectorPropertySuffixes.ENABLE;
        String captchaAlwaysEnabledConfigName = connector.getName() +
                CaptchaConstants.ReCaptchaConnectorPropertySuffixes.ENABLE_ALWAYS;
        String maxFailedAttemptCaptchaConfigName = connector.getName() +
                CaptchaConstants.ReCaptchaConnectorPropertySuffixes.MAX_ATTEMPTS;

        String captchaParams = StringUtils.EMPTY;
        Property[] connectorConfigs;

        if (CaptchaUtil.isReCaptchaEnabled()) {
            boolean forcefullyEnabledRecaptchaForAllTenants = CaptchaUtil.isReCaptchaForcefullyEnabledForAllTenants();
            if (forcefullyEnabledRecaptchaForAllTenants) {
                captchaParams = RECAPTCHA_PARAM + "true";
            } else {
                try {
                    connectorConfigs = AuthenticatorDataHolder.getIdentityGovernanceService()
                            .getConfiguration(new String[]{captchaAlwaysEnabledConfigName, captchaEnabledConfigName},
                                    tenantDomain);
                    for (Property connectorConfig : connectorConfigs) {
                        if (captchaAlwaysEnabledConfigName.equals(connectorConfig.getName())
                                && Boolean.parseBoolean(connectorConfig.getValue())) {
                            captchaParams = RECAPTCHA_PARAM + "true";
                            break;
                        } else if (captchaEnabledConfigName.equals(connectorConfig.getName())) {
                            if (!Boolean.parseBoolean(connectorConfig.getValue())) {
                                continue;
                            }
                            if (Boolean.parseBoolean(
                                    String.valueOf(context.getProperty(IS_LOGIN_ATTEMPT_BY_INVALID_USER)))) {
                                continue;
                            }
                            Property[] maxFailedConfig = AuthenticatorDataHolder.getIdentityGovernanceService()
                                    .getConfiguration(new String[]{maxFailedAttemptCaptchaConfigName}, tenantDomain);
                            Property maxFailedProperty = maxFailedConfig[0];
                            int maxFailedAttempts;
                            if (NumberUtils.isNumber(maxFailedProperty.getValue())) {
                                maxFailedAttempts = Integer.parseInt(maxFailedProperty.getValue());
                            } else {
                                maxFailedAttempts = 3;
                            }

                            UserStoreManager userStoreManager = getUserStoreManager(authenticatedUser);
                            Map<String, String> claimValues;
                            String failedAttemptsClaim = getOTPFailedAttemptsClaimUri();
                            if (userStoreManager == null) {
                                throw handleAuthErrorScenario(ERROR_CODE_ERROR_GETTING_USER_STORE_MANAGER);
                            }
                            String fullQualifiedUsername = authenticatedUser.toFullQualifiedUsername();
                            claimValues = userStoreManager.getUserClaimValues(MultitenantUtils
                                            .getTenantAwareUsername(fullQualifiedUsername),
                                    new String[]{failedAttemptsClaim}, null);

                            int currentAttempts = 0;
                            if (NumberUtils.isNumber(claimValues.get(failedAttemptsClaim))) {
                                currentAttempts = Integer.parseInt(claimValues.get(failedAttemptsClaim));
                            }
                            if (maxFailedAttempts > currentAttempts) {
                                continue;
                            }
                            captchaParams = RECAPTCHA_PARAM + "true";
                        }
                    }

                } catch (IdentityGovernanceException | UserStoreException | AuthenticationFailedException e) {
                    LOG.error("Error occurred while verifying the captcha configs. Proceeding the authentication " +
                            "request without enabling recaptcha.", e);
                }
            }
        }
        return captchaParams;
    }

    /**
     * Reset OTP Failed Attempts count upon successful completion of the OTP verification.
     *
     * @param user AuthenticatedUser.
     * @throws AuthenticationFailedException If an error occurred while resetting the OTP failed attempts.
     */
    protected void resetOtpFailedAttempts(AuthenticatedUser user) throws AuthenticationFailedException {

        UserStoreManager userStoreManager = getUserStoreManager(user);
        // Add required meta properties to the event.
        Map<String, Object> metaProperties = new HashMap<>();
        metaProperties.put(AUTHENTICATOR_NAME, getName());
        metaProperties.put(PROPERTY_FAILED_LOGIN_ATTEMPTS_CLAIM, getOTPFailedAttemptsClaimUri());
        metaProperties.put(USER_STORE_MANAGER, userStoreManager);
        metaProperties.put(OPERATION_STATUS, true);

        triggerEvent(POST_NON_BASIC_AUTHENTICATION, user, metaProperties);
    }

    /**
     * Check if the current authentication attempt is performed by a user who is not in the system.
     *
     * @param context               Authentication Context.
     * @param authenticatedUser     User who is attempting the authentication.
     * @return True if the authentication attempt is done by an invalid user.
     */
    private boolean isLoginAttemptByInvalidUser(AuthenticationContext context,
                                                AuthenticatedUser authenticatedUser) {

        return authenticatedUser == null
                && Boolean.parseBoolean(String.valueOf(context.getProperty(IS_LOGIN_ATTEMPT_BY_INVALID_USER)));
    }

    /**
     * Check if the user is redirected from the identifier first UI.
     *
     * @param request   HttpServletRequest.
     * @return True if the user is redirected from the identifier first UI.
     */
    private boolean isUserRedirectedFromIDF(HttpServletRequest request) {

        return StringUtils.isNotBlank(request.getParameter(USERNAME));
    }

    /**
     * Check if the first factor support for the authenticator is enabled through config.
     *
     * @return True if enabled.
     */
    protected boolean isAuthenticatorEnabledForFirstFactor() {

        return true;
    }

    /**
     * Check if the current OTP authenticator is the primary factor of authentication.
     *
     * @param context   Authentication Context.
     * @return True if the current OTP authenticator is the primary factor of authentication.
     */
    protected boolean isOTPAsFirstFactor(AuthenticationContext context) {

        return (context.getCurrentStep() == 1 || isPreviousIdPAuthenticationFlowHandler(context));
    }

    protected abstract String getAuthenticatorErrorPrefix();

    protected abstract void sendOtp(AuthenticatedUser authenticatedUser, OTP otp, boolean isInitialFederationAttempt,
                                    HttpServletRequest request, HttpServletResponse response,
                                    AuthenticationContext context)
            throws AuthenticationFailedException;

    protected abstract String getMaskedUserClaimValue(AuthenticatedUser authenticatedUser, String tenantDomain,
                                                      boolean isInitialFederationAttempt, AuthenticationContext context)
            throws AuthenticationFailedException;

    protected abstract void publishPostOTPValidatedEvent(OTP otpInfo, AuthenticatedUser authenticatedUser,
                                                         boolean isAuthenticationPassed, boolean isExpired,
                                                         HttpServletRequest request, AuthenticationContext context)
            throws AuthenticationFailedException;

    protected abstract void publishPostOTPGeneratedEvent(OTP otpInfo, AuthenticatedUser authenticatedUser,
                                                         HttpServletRequest request, AuthenticationContext context)
            throws AuthenticationFailedException;

    protected abstract String getErrorPageURL(AuthenticationContext context) throws AuthenticationFailedException;

    protected abstract String getOTPLoginPageURL(AuthenticationContext context) throws AuthenticationFailedException;
}
