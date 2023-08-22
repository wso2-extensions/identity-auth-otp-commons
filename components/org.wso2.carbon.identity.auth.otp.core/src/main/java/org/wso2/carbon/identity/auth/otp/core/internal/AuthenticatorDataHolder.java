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

package org.wso2.carbon.identity.auth.otp.core.internal;

import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.handler.event.account.lock.service.AccountLockService;
import org.wso2.carbon.idp.mgt.IdpManager;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * Encapsulates the data of OTP authenticator.
 */
public class AuthenticatorDataHolder {

    private static RealmService realmService;
    private static AccountLockService accountLockService;
    private static IdentityGovernanceService identityGovernanceService;
    private static IdentityEventService identityEventService;
    private static IdpManager idpManager;

    private AuthenticatorDataHolder() {

    }

    /**
     * Get the RealmService.
     *
     * @return RealmService.
     */
    public static RealmService getRealmService() {

        return realmService;
    }

    /**
     * Set the RealmService.
     *
     * @param realmService RealmService.
     */
    public static void setRealmService(RealmService realmService) {

        AuthenticatorDataHolder.realmService = realmService;
    }

    /**
     * Get Account Lock service.
     *
     * @return Account Lock service.
     */
    public static AccountLockService getAccountLockService() {

        return accountLockService;
    }

    /**
     * Set Account Lock service.
     *
     * @param accountLockService Account Lock service.
     */
    public static void setAccountLockService(AccountLockService accountLockService) {

        AuthenticatorDataHolder.accountLockService = accountLockService;
    }

    /**
     * Get Identity Governance service.
     *
     * @return Identity Governance service.
     */
    public static IdentityGovernanceService getIdentityGovernanceService() {

        return identityGovernanceService;
    }

    /**
     * Set Identity Governance service.
     *
     * @param identityGovernanceService Identity Governance service.
     */
    public static void setIdentityGovernanceService(IdentityGovernanceService identityGovernanceService) {

        AuthenticatorDataHolder.identityGovernanceService = identityGovernanceService;
    }

    /**
     * Get IdpManager.
     *
     * @return IdpManager.
     */
    public static IdpManager getIdpManager() {

        return idpManager;
    }

    /**
     * Set IdpManager.
     *
     * @param idpManager IdpManager.
     */
    public static void setIdpManager(IdpManager idpManager) {

        AuthenticatorDataHolder.idpManager = idpManager;
    }

    /**
     * Get IdentityEventService instance.
     *
     * @return IdentityEventService instance.
     */
    public static IdentityEventService getIdentityEventService() {

        return identityEventService;
    }

    /**
     * Set IdentityEventService instance.
     *
     * @param identityEventService IdentityEventService instance.
     */
    public static void setIdentityEventService(IdentityEventService identityEventService) {

        AuthenticatorDataHolder.identityEventService = identityEventService;
    }
}
