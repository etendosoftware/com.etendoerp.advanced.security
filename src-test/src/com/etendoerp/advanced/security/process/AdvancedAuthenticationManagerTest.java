
package com.etendoerp.advanced.security.process;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Method;
import java.math.BigDecimal;
import java.util.Calendar;
import java.util.Date;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InOrder;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Spy;
import org.mockito.junit.MockitoJUnitRunner;
import org.openbravo.authentication.AuthenticationException;
import org.openbravo.authentication.AuthenticationExpirationPasswordException;
import org.openbravo.authentication.ChangePasswordException;
import org.openbravo.base.exception.OBException;
import org.openbravo.base.secureApp.LoginUtils;
import org.openbravo.dal.core.OBContext;
import org.openbravo.dal.service.OBDal;
import org.openbravo.erpCommon.utility.OBMessageUtils;
import org.openbravo.model.ad.access.User;
import org.openbravo.model.ad.system.SystemInformation;
import org.openbravo.service.db.DalConnectionProvider;

import com.etendoerp.advanced.security.Utility;
import com.etendoerp.advanced.security.utils.AdvancedSecurityUtils;

/**
 * Unit test class for {@link AdvancedAuthenticationManager}.
 * This class includes tests for the authentication mechanism and password security features.
 */
@RunWith(MockitoJUnitRunner.class)
public class AdvancedAuthenticationManagerTest {

  private static final String SYSTEM_USER_ID = "100";

  @Spy
  @InjectMocks
  private AdvancedAuthenticationManager authManager;

  @Mock
  private HttpServletRequest request;

  @Mock
  private HttpServletResponse response;

  @Mock
  private OBDal obDal;

  @Mock
  private User mockUser;

  @Mock
  private OBContext obContext;

  @Mock
  private SystemInformation systemInfo;

  /**
   * Sets up the initial configurations and mocks for the test cases.
   */
  @Before
  public void setUp() {
    when(mockUser.getUsername()).thenReturn(Utility.TEST_USER);
    when(mockUser.getEtasBadPasswordAttempts()).thenReturn(BigDecimal.ZERO);
  }

  /**
   * Tests that the {@code doAuthenticate} method throws an {@link AuthenticationException}
   * when the user being authenticated is a system user.
   */
  @Test
  public void testDoAuthenticateShouldThrowAuthenticationExceptionForSystemUser() {
    Throwable thrown = captureDoAuthenticateFailure(SYSTEM_USER_ID, null);

    assertTrue(thrown instanceof AuthenticationException);
  }

  /**
   * Verifies that the {@code executePasswordSecurity} method locks the user
   * after reaching the maximum allowed failed password attempts.
   */
  @Test
  public void testExecutePasswordSecurityShouldBlockUserAfterMaxAttempts() {
    int maxAttempts = 3;
    BigDecimal currentAttempts = new BigDecimal(2);
    BigDecimal newAttempts = currentAttempts.add(BigDecimal.ONE);

    when(mockUser.isLocked()).thenReturn(false);
    when(mockUser.getUsername()).thenReturn(Utility.TEST_USER);
    when(mockUser.getEtasBadPasswordAttempts()).thenReturn(currentAttempts);

    try (MockedStatic<LoginUtils> loginUtilsMock = mockStatic(LoginUtils.class);
         MockedStatic<OBDal> obDalMock = mockStatic(OBDal.class);
         MockedStatic<OBMessageUtils> messageMock = mockStatic(OBMessageUtils.class)) {

      loginUtilsMock.when(() -> LoginUtils.checkUserPassword(
          any(DalConnectionProvider.class),
          eq(Utility.TEST_USER),
          anyString()
      )).thenReturn(null);

      obDalMock.when(OBDal::getInstance).thenReturn(obDal);

      messageMock.when(() -> OBMessageUtils.messageBD("LOCKED_USER_MSG"))
          .thenReturn("User has been locked");

      try {
        authManager.executePasswordSecurity(mockUser, request, maxAttempts);
        fail("Should throw OBException");
      } catch (OBException e) {
        InOrder inOrder = inOrder(mockUser, obDal);

        inOrder.verify(mockUser).isLocked();
        inOrder.verify(mockUser).getUsername();
        inOrder.verify(mockUser).getEtasBadPasswordAttempts();
        inOrder.verify(mockUser).setEtasBadPasswordAttempts(newAttempts);
        inOrder.verify(mockUser).setLocked(true);
        inOrder.verify(obDal).save(mockUser);

        assertEquals("User has been locked", e.getMessage());
      }
    }
  }

  /**
   * Tests that the password auto-expiration feature works correctly.
   *
   * @throws Exception if an error occurs during testing
   */
  @Test
  public void testExecutePasswordAutoExpiration() throws Exception {
    Method expirePasswordMethod = AdvancedAuthenticationManager.class.getDeclaredMethod(
        "executePasswordAutoExpiration",
        User.class,
        String.class
    );
    expirePasswordMethod.setAccessible(true);

    Calendar cal = Calendar.getInstance();
    cal.add(Calendar.DAY_OF_MONTH, -31);
    Date oldPasswordUpdate = cal.getTime();

    when(mockUser.getLastPasswordUpdate()).thenReturn(oldPasswordUpdate);

    try (MockedStatic<AdvancedSecurityUtils> securityUtilsMock = mockStatic(AdvancedSecurityUtils.class);
         MockedStatic<OBDal> obDalMock = mockStatic(OBDal.class)) {

      securityUtilsMock.when(() -> AdvancedSecurityUtils.getDateLimitToExpire(any(), anyString()))
          .thenReturn(cal.getTime());

      obDalMock.when(OBDal::getInstance).thenReturn(obDal);

      expirePasswordMethod.invoke(authManager, mockUser, "30");

      verify(mockUser).setPasswordExpired(true);
      verify(obDal).save(mockUser);
    }
  }

  /**
   * Verifies that the {@code getUserNameByRequest} method correctly retrieves the username
   * from the HTTP request.
   *
   * @throws Exception if an error occurs during testing
   */
  @Test
  public void testGetUserNameByRequest() throws Exception {
    Method getUserNameMethod = AdvancedAuthenticationManager.class.getDeclaredMethod(
        "getUserNameByRequest",
        HttpServletRequest.class
    );
    getUserNameMethod.setAccessible(true);

    when(request.getParameter("user")).thenReturn(Utility.TEST_USER);

    String result = (String) getUserNameMethod.invoke(authManager, request);

    assertEquals(Utility.TEST_USER, result);
  }
  /**
   * Tests that an expired password reported while authenticating leaves {@code doAuthenticate}
   * with its original type, so that {@code LoginHandler} can route the user to the mandatory
   * password change form instead of showing a dead end error.
   */
  @Test
  public void testDoAuthenticateKeepsExpiredPasswordExceptionType() {
    AuthenticationExpirationPasswordException expired = new AuthenticationExpirationPasswordException(
        "CPExpirationPassword");

    assertSame(expired, captureDoAuthenticateFailure(Utility.TEST_USER_ID, expired));
  }

  /**
   * Tests that a forced password change reported while authenticating leaves
   * {@code doAuthenticate} with its original type, since {@code LoginHandler} routes it through
   * the same password change flow as an expired password.
   */
  @Test
  public void testDoAuthenticateKeepsChangePasswordExceptionType() {
    ChangePasswordException changePassword = new ChangePasswordException("CPUpdatePassword");

    assertSame(changePassword, captureDoAuthenticateFailure(Utility.TEST_USER_ID, changePassword));
  }

  /**
   * Runs {@code doAuthenticate} for the given user and returns the exception that escapes the
   * method.
   *
   * <p>When an exception is supplied it is injected through {@link AdvancedSecurityUtils} rather
   * than through the inherited {@code super.doAuthenticate()} that raises it in production: a
   * {@code super} call is bound at compile time and cannot be stubbed on a spy. What is under test
   * is the catch clause of {@code doAuthenticate}, which treats both origins alike.
   *
   * @param userId
   *     the id of the user being authenticated
   * @param toPropagate
   *     the exception raised inside the body of {@code doAuthenticate}, or {@code null} to let the
   *     inherited authentication fail on its own
   * @return the exception thrown out of {@code doAuthenticate}
   */
  private Throwable captureDoAuthenticateFailure(String userId, RuntimeException toPropagate) {
    when(mockUser.getId()).thenReturn(userId);

    try (MockedStatic<OBContext> obContextMock = mockStatic(OBContext.class);
         MockedStatic<OBDal> obDalMock = mockStatic(OBDal.class);
         MockedStatic<AdvancedSecurityUtils> securityUtilsMock = mockStatic(AdvancedSecurityUtils.class)) {

      obContextMock.when(OBContext::getOBContext).thenReturn(obContext);
      when(obContext.isAdminContext()).thenReturn(false);

      obDalMock.when(OBDal::getInstance).thenReturn(obDal);
      when(obDal.get(SystemInformation.class, Utility.SYSTEM_INFO_ID)).thenReturn(systemInfo);

      securityUtilsMock.when(() -> AdvancedSecurityUtils.getUser(anyString())).thenReturn(mockUser);
      securityUtilsMock.when(() -> AdvancedSecurityUtils.getAttemptsToBlockUser(any())).thenReturn(0);
      if (toPropagate != null) {
        securityUtilsMock.when(() -> AdvancedSecurityUtils.getDaysToPasswordExpirationPreference(any()))
            .thenThrow(toPropagate);
      }

      try {
        authManager.doAuthenticate(request, response);
        fail("doAuthenticate must not authenticate this user");
        return null;
      } catch (Exception e) {
        return e;
      }
    }
  }
}
