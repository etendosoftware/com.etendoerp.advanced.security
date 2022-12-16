/*
 *************************************************************************
 * The contents of this file are subject to the Openbravo  Public  License
 * Version  1.1  (the  "License"),  being   the  Mozilla   Public  License
 * Version 1.1  with a permitted attribution clause; you may not  use this
 * file except in compliance with the License. You  may  obtain  a copy of
 * the License at http://www.openbravo.com/legal/license.html
 * Software distributed under the License  is  distributed  on  an "AS IS"
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
 * License for the specific  language  governing  rights  and  limitations
 * under the License.
 * The Original Code is Openbravo ERP.
 * The Initial Developer of the Original Code is Openbravo SLU
 * All portions are Copyright (C) 2019 Openbravo SLU
 * All Rights Reserved.
 * Contributor(s):  ______________________________________.
 ************************************************************************
 */

package com.etendoerp.advanced.security.process;

import java.io.IOException;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.hibernate.criterion.Restrictions;
import org.openbravo.authentication.AuthenticationException;
import org.openbravo.authentication.basic.DefaultAuthenticationManager;
import org.openbravo.base.exception.OBException;
import org.openbravo.base.secureApp.LoginUtils;
import org.openbravo.base.secureApp.VariablesSecureApp;
import org.openbravo.dal.core.OBContext;
import org.openbravo.dal.service.OBCriteria;
import org.openbravo.dal.service.OBDal;
import org.openbravo.dal.service.OBQuery;
import org.openbravo.database.ConnectionProvider;
import org.openbravo.erpCommon.utility.OBError;
import org.openbravo.erpCommon.utility.OBMessageUtils;
import org.openbravo.model.ad.access.Session;
import org.openbravo.model.ad.access.User;
import org.openbravo.model.ad.system.SystemInformation;
import org.openbravo.service.db.DalConnectionProvider;
import org.openbravo.service.web.BaseWebServiceServlet;

public class AdvancedAuthenticationManager extends DefaultAuthenticationManager {

  private static final String SYSTEM_USER_ID = "100";
  private static final Logger log4j = LogManager.getLogger();

  @Override
  protected String doAuthenticate(HttpServletRequest request, HttpServletResponse response)
      throws AuthenticationException, ServletException, IOException {
    try {
      OBContext.setAdminMode(true);
      final SystemInformation systemInfo = OBDal.getInstance().get(SystemInformation.class, "0");
      var user = getUser(getUserNameByRequest(request));
      if (user != null) {
        if (systemInfo.isEasEnableSessionCheck()) {
          checkActiveUserSessions(request, response, user);
        }
        if (systemInfo.isEasEnablePassAttblock()) {
          executePasswordSecurity(user, systemInfo, request);
        }
      }
    } catch (OBException e) {
      OBError errorMsg = new OBError();
      errorMsg.setType("error");
      errorMsg.setTitle(e.getMessage());
      errorMsg.setMessage(" ");
      throw new AuthenticationException(errorMsg.getTitle(), errorMsg, false);
    } finally {
      OBContext.restorePreviousMode();
    }
    return super.doAuthenticate(request, response);
  }

  /**
   * Checks the number attempts to the password from user
   *
   * @param user
   *     The user of the user to check password attempts
   * @param systemInfo
   *     Unique ad_system_info data
   */
  public void executePasswordSecurity(User user, SystemInformation systemInfo, HttpServletRequest request) {
    try {
      if (!StringUtils.equals(SYSTEM_USER_ID, user.getId()) && !user.isLocked()) {
        ConnectionProvider cp = new DalConnectionProvider(false);
        final String pass = getPassFromRequest(request);
        final boolean isFailedAttempt = LoginUtils.checkUserPassword(cp, user.getUsername(), pass) == null;
        if (isFailedAttempt) {
          String errorMessage = OBMessageUtils.messageBD("LOCKED_USER_MSG");
          var maxAttempts = systemInfo.getEasPasswordAttempts();
          var userPasswordAttempts = user.getEasBadPasswordAttempts();
          var currentAttempts = userPasswordAttempts.add(BigDecimal.ONE);
          user.setEasBadPasswordAttempts(currentAttempts); // update incorrect attempts to user

          final boolean needLocked = maxAttempts.compareTo(currentAttempts) <= 0;
          if (needLocked) {
            user.setLocked(true);
          } else {
            errorMessage = String.format(OBMessageUtils.messageBD("EAS_PasswordIncorrectAttempt"),
                maxAttempts.subtract(currentAttempts)); // returns available password attempts
          }
          OBDal.getInstance().save(user);
          OBDal.getInstance().flush();
          throw new OBException(errorMessage);
        } else {
          cleanUserPasswordAttempts(user);
        }
      }
    } catch (Exception e) {
      throw new OBException(e.getMessage());
    }
  }

  /**
   * Sets the failed attempt count to 0 when login is successful
   *
   * @param user
   *     The username to clear the number of failed password attempts
   */
  private void cleanUserPasswordAttempts(User user) {
    if (user != null && BigDecimal.ZERO.compareTo(
        user.getEasBadPasswordAttempts()) < 0) { // restart password attempts
      user.setEasBadPasswordAttempts(BigDecimal.ZERO);
      OBDal.getInstance().save(user);
      OBDal.getInstance().flush();
    }
  }

  /**
   * @param request
   *     current HttpServletRequest request
   * @return request password
   */
  private String getPassFromRequest(HttpServletRequest request) {
    String pass = "";
    final VariablesSecureApp vars = new VariablesSecureApp(request, false);
    UserLoginInfo authenticationData = decodeBasicAuthenticationData(request);
    if (authenticationData != null) {
      pass = authenticationData.getPassword();
    }
    if (StringUtils.isEmpty(pass)) {
      pass = vars.getStringParameter(PASSWORD_PARAM);
      if (StringUtils.isEmpty(pass)) {
        pass = vars.getStringParameter(BaseWebServiceServlet.PASSWORD_PARAM);
      }
    }
    return pass;
  }

  private static User getUser(String userName) {
    OBCriteria<User> currentUserCriteria = OBDal.getInstance().createCriteria(User.class);
    currentUserCriteria.setMaxResults(1);
    if (!StringUtils.isEmpty(userName)) {
      currentUserCriteria.add(Restrictions.eq(User.PROPERTY_USERNAME, userName));
    }
    currentUserCriteria.setFilterOnReadableClients(false);
    currentUserCriteria.setFilterOnReadableOrganization(false);
    currentUserCriteria.setFilterOnActive(true);
    return (User) currentUserCriteria.uniqueResult();
  }

  /**
   * Verify that there is no more than one active session. In this case, throws an exception informing the user
   *
   * @param request
   *     current HttpServletRequest request
   * @param response
   *     current HttpServletRequest response
   * @param user
   *     current User
   */
  private void checkActiveUserSessions(HttpServletRequest request, HttpServletResponse response,
      User user) throws AuthenticationException, IOException, ServletException {
    try {
      final String userId = user.getId();
      if (!StringUtils.equals(SYSTEM_USER_ID, userId)) {
        final var oldSessions = getActiveSessions(userId);
        if (!oldSessions.isEmpty()) {
          if (user.isEasEnableMultSession()) {
            super.doAuthenticate(request, response);
            final var sessions = getActiveSessions(userId);
            if (!oldSessions.equals(sessions)) {
              killSessions(oldSessions);
            }
          } else {
            throw new AuthenticationException(
                String.format(OBMessageUtils.messageBD("EAS_Multiplelogin"), user.getUsername()));
          }
        }
      }
    } catch (OBException e) {
      throw new OBException(e.getMessage());
    }
  }

  /**
   * @param sUserId
   *     User ID to verify active sessions
   * @return An array with ID of the active sessions
   */
  private List<String> getActiveSessions(String sUserId) {
    try {
      final String hqlActiveSessions = "WHERE sessionActive = true" +
          " AND createdBy.id = :userId AND lastPing IS NOT NULL order by id";
      final OBQuery<Session> queryActiveSessions = OBDal.getInstance().createQuery(Session.class, hqlActiveSessions);
      queryActiveSessions.setNamedParameter("userId", sUserId);
      var activeSessions = queryActiveSessions.list();
      return activeSessions.stream()
          .map(Session::getId)
          .collect(Collectors.toList());
    } catch (Exception e) {
      throw new OBException(e.getMessage());
    }
  }

  private String getUserNameByRequest(HttpServletRequest request) {
    VariablesSecureApp vars = new VariablesSecureApp(request, false);
    String user = vars.getStringParameter(LOGIN_PARAM);
    if (StringUtils.isEmpty(user)) {
      user = vars.getStringParameter(BaseWebServiceServlet.LOGIN_PARAM);
    }
    if (StringUtils.isEmpty(user)) {
      // try basic authentication
      UserLoginInfo authenticationData = decodeBasicAuthenticationData(request);
      if (authenticationData != null) {
        user = authenticationData.getUserName();
      }
    }
    return user;
  }

  private void killSessions(List<String> sessions) {
    try {
      for (String currentSessionId : sessions) {
        var currentSession = OBDal.getInstance().get(Session.class, currentSessionId);
        final String messageFormatted = String.format("Killed session: %s", currentSession.getIdentifier());
        log4j.debug(messageFormatted);
        currentSession.setSessionActive(false);
        OBDal.getInstance().save(currentSession);
      }
      OBDal.getInstance().flush();
    } catch (Exception e) {
      throw new OBException(e.getMessage());
    }
  }
}
