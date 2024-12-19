package com.etendoerp.advanced.security.process;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.math.BigDecimal;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.hibernate.criterion.Criterion;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.MockitoJUnitRunner;
import org.openbravo.base.exception.OBException;
import org.openbravo.dal.service.OBCriteria;
import org.openbravo.dal.service.OBDal;
import org.openbravo.dal.service.OBQuery;
import org.openbravo.erpCommon.utility.OBMessageUtils;
import org.openbravo.model.ad.access.Session;
import org.openbravo.model.ad.access.User;

import com.etendoerp.advanced.security.Utility;

/**
 * Unit tests for the {@link AdvancedAuthenticationManager} private methods.
 * These tests verify the functionality of key private methods in the
 * {@code AdvancedAuthenticationManager} class, including session handling and user management.
 * Private methods are accessed through reflection for testing purposes.
 */
@RunWith(MockitoJUnitRunner.class)
public class AdvancedAuthenticationManagerPrivateMethodsTest {





  @Mock
  private HttpServletRequest request;

  @Mock
  private HttpServletResponse response;

  @Mock
  private OBDal obDal;

  @Mock
  private User mockUser;

  @Mock
  private Session mockSession;

  @Mock
  private OBCriteria<Session> mockCriteria;

  @Mock
  private OBQuery<Session> mockQuery;

  private AdvancedAuthenticationManager authManager;

  /**
   * Sets up the test environment by initializing the class under test and mocking required dependencies.
   *
   * @throws ServletException if a servlet exception occurs.
   * @throws IOException      if an I/O exception occurs.
   */
  @Before
  public void setUp() throws ServletException, IOException {
    authManager = spy(new AdvancedAuthenticationManager());
    when(mockUser.getUsername()).thenReturn("testUser");
    when(mockUser.getId()).thenReturn(Utility.TEST_USER_ID);
  }

  /**
   * Utility method to access private methods via reflection.
   *
   * @param methodName     the name of the private method.
   * @param parameterTypes the parameter types of the private method.
   * @return the {@code Method} object for the private method.
   * @throws Exception if reflection fails.
   */
  private Method getPrivateMethod(String methodName, Class<?>... parameterTypes) throws Exception {
    Method method = AdvancedAuthenticationManager.class.getDeclaredMethod(methodName, parameterTypes);
    method.setAccessible(true);
    return method;
  }

  /**
   * Tests the method {@code deleteInactiveSessions(String)} for deactivating
   * sessions that have expired based on the last ping time.
   *
   * @throws Exception if reflection access fails or method execution throws an error.
   */
  @Test
  public void testDeleteInactiveSessionsWithExpiredSessions() throws Exception {
    Method deleteInactiveSessions = getPrivateMethod("deleteInactiveSessions", String.class);

    Calendar cal = Calendar.getInstance();
    cal.add(Calendar.MINUTE, -1);
    Date oldPingTime = cal.getTime();

    when(mockSession.getId()).thenReturn(Utility.SESSION_ONE);
    when(mockSession.getLastPing()).thenReturn(oldPingTime);
    when(mockSession.getIdentifier()).thenReturn("testSessionIdentifier");

    try (MockedStatic<OBDal> obDalMock = mockStatic(OBDal.class)) {
      obDalMock.when(OBDal::getInstance).thenReturn(obDal);
      when(obDal.createCriteria(Session.class)).thenReturn(mockCriteria);
      when(mockCriteria.add(any(Criterion.class))).thenReturn(mockCriteria);
      when(mockCriteria.addOrderBy(anyString(), anyBoolean())).thenReturn(mockCriteria);
      when(mockCriteria.list()).thenReturn(Arrays.asList(mockSession));
      when(obDal.get(User.class, Utility.TEST_USER_ID)).thenReturn(mockUser);
      when(obDal.get(Session.class, Utility.SESSION_ONE)).thenReturn(mockSession);

      deleteInactiveSessions.invoke(authManager, Utility.TEST_USER_ID);

      verify(mockSession).setSessionActive(false);
      verify(obDal).save(mockSession);
      verify(obDal).flush();
    }
  }

  /**
   * Tests the method {@code killSessions(List<String>)} by deactivating multiple sessions.
   *
   * @throws Exception if reflection access fails or method execution throws an error.
   */
  @Test
  public void testKillSessionsWithMultipleSessions() throws Exception {
    Method killSessions = getPrivateMethod("killSessions", List.class);

    Session mockSession2 = mock(Session.class);
    when(mockSession.getIdentifier()).thenReturn("testSessionIdentifier1");
    when(mockSession2.getIdentifier()).thenReturn("testSessionIdentifier2");

    try (MockedStatic<OBDal> obDalMock = mockStatic(OBDal.class)) {
      obDalMock.when(OBDal::getInstance).thenReturn(obDal);
      when(obDal.get(Session.class, Utility.SESSION_ONE)).thenReturn(mockSession);
      when(obDal.get(Session.class, "session2")).thenReturn(mockSession2);

      killSessions.invoke(authManager, Arrays.asList(Utility.SESSION_ONE, "session2"));

      verify(mockSession).setSessionActive(false);
      verify(mockSession2).setSessionActive(false);
      verify(obDal, times(2)).save(any(Session.class));
      verify(obDal).flush();
    }
  }

  /**
   * Tests the method {@code getActiveSessions(String)} for retrieving active sessions
   * when no sessions are available.
   *
   * @throws Exception if reflection access fails or method execution throws an error.
   */
  @Test
  public void testGetActiveSessionsWithNoActiveSessions() throws Exception {
    Method getActiveSessions = getPrivateMethod("getActiveSessions", String.class);

    try (MockedStatic<OBDal> obDalMock = mockStatic(OBDal.class)) {
      obDalMock.when(OBDal::getInstance).thenReturn(obDal);

      when(obDal.get(User.class, Utility.TEST_USER_ID)).thenReturn(mockUser);

      when(obDal.createCriteria(Session.class)).thenReturn(mockCriteria);
      when(mockCriteria.add(any(Criterion.class))).thenReturn(mockCriteria);
      when(mockCriteria.addOrderBy(anyString(), anyBoolean())).thenReturn(mockCriteria);
      when(mockCriteria.list()).thenReturn(List.of());

      when(obDal.createQuery(eq(Session.class), anyString())).thenReturn(mockQuery);
      when(mockQuery.setNamedParameter(anyString(), any())).thenReturn(mockQuery);
      when(mockQuery.list()).thenReturn(List.of());

      @SuppressWarnings("unchecked")
      List<String> result = (List<String>) getActiveSessions.invoke(authManager, Utility.TEST_USER_ID);
      assertTrue(result.isEmpty());
    }
  }

  /**
   * Tests the method {@code checkActiveUserSessions(HttpServletRequest, HttpServletResponse, User)}
   * when no existing sessions are active.
   *
   * @throws Exception if reflection access fails or method execution throws an error.
   */
  @Test
  public void testCheckActiveUserSessionsWithNoExistingSessions() throws Exception {
    Method checkActiveUserSessions = getPrivateMethod("checkActiveUserSessions",
        HttpServletRequest.class, HttpServletResponse.class, User.class);

    try (MockedStatic<OBDal> obDalMock = mockStatic(OBDal.class)) {
      obDalMock.when(OBDal::getInstance).thenReturn(obDal);

      when(obDal.get(User.class, mockUser.getId())).thenReturn(mockUser);

      when(obDal.createCriteria(Session.class)).thenReturn(mockCriteria);
      when(mockCriteria.add(any(Criterion.class))).thenReturn(mockCriteria);
      when(mockCriteria.addOrderBy(anyString(), anyBoolean())).thenReturn(mockCriteria);
      when(mockCriteria.list()).thenReturn(List.of());

      when(obDal.createQuery(eq(Session.class), anyString())).thenReturn(mockQuery);
      when(mockQuery.setNamedParameter(anyString(), any())).thenReturn(mockQuery);
      when(mockQuery.list()).thenReturn(List.of());

      checkActiveUserSessions.invoke(authManager, request, response, mockUser);
    }
  }

  /**
   * Tests the method {@code checkActiveUserSessions(HttpServletRequest, HttpServletResponse, User)}
   * when multiple sessions are disabled.
   *
   * @throws Exception if reflection access fails or method execution throws an error.
   */
  @Test
  public void testCheckActiveUserSessionsWithMultipleSessionsDisabled() throws Exception {
    Method checkActiveUserSessions = getPrivateMethod("checkActiveUserSessions",
        HttpServletRequest.class, HttpServletResponse.class, User.class);

    when(mockUser.isEtasEnableMultSession()).thenReturn(false);
    when(mockSession.getId()).thenReturn("sessionId");

    try (MockedStatic<OBDal> obDalMock = mockStatic(OBDal.class);
         MockedStatic<OBMessageUtils> messageMock = mockStatic(OBMessageUtils.class)) {

      obDalMock.when(OBDal::getInstance).thenReturn(obDal);

      when(obDal.get(User.class, mockUser.getId())).thenReturn(mockUser);

      when(obDal.createCriteria(Session.class)).thenReturn(mockCriteria);
      when(mockCriteria.add(any(Criterion.class))).thenReturn(mockCriteria);
      when(mockCriteria.addOrderBy(anyString(), anyBoolean())).thenReturn(mockCriteria);
      when(mockCriteria.list()).thenReturn(List.of());

      when(obDal.createQuery(eq(Session.class), anyString())).thenReturn(mockQuery);
      when(mockQuery.setNamedParameter(anyString(), any())).thenReturn(mockQuery);
      when(mockQuery.list()).thenReturn(List.of(mockSession));

      messageMock.when(() -> OBMessageUtils.messageBD("ETAS_Multiplelogin"))
          .thenReturn("Multiple login not allowed for user %s");

      InvocationTargetException exception = assertThrows(InvocationTargetException.class, () ->
        checkActiveUserSessions.invoke(authManager, request, response, mockUser)
      );

      assertTrue(exception.getCause() instanceof OBException);
      assertEquals("Multiple login not allowed for user testUser",
          exception.getCause().getMessage());
    }
  }
  /**
   * Tests that the method {@code cleanUserPasswordAttempts(User)} resets the
   * bad password attempts count to zero when the count is positive.
   *
   * @throws Exception if reflection access fails or method execution throws an error.
   */
  @Test
  public void testCleanUserPasswordAttemptsWithPositiveAttempts() throws Exception {
    Method cleanUserPasswordAttempts = getPrivateMethod("cleanUserPasswordAttempts", User.class);

    when(mockUser.getEtasBadPasswordAttempts()).thenReturn(new BigDecimal("3"));

    try (MockedStatic<OBDal> obDalMock = mockStatic(OBDal.class)) {
      obDalMock.when(OBDal::getInstance).thenReturn(obDal);

      cleanUserPasswordAttempts.invoke(authManager, mockUser);

      verify(mockUser).setEtasBadPasswordAttempts(BigDecimal.ZERO);
      verify(obDal).save(mockUser);
      verify(obDal).flush();
    }
  }

  /**
   * Tests that the method {@code cleanUserPasswordAttempts(User)}
   * does not alter the attempts count when it is already zero.
   *
   * @throws Exception if reflection access fails or method execution throws an error.
   */
  @Test
  public void testCleanUserPasswordAttemptsWithZeroAttempts() throws Exception {
    Method cleanUserPasswordAttempts = getPrivateMethod("cleanUserPasswordAttempts", User.class);

    when(mockUser.getEtasBadPasswordAttempts()).thenReturn(BigDecimal.ZERO);

    try (MockedStatic<OBDal> obDalMock = mockStatic(OBDal.class)) {
      obDalMock.when(OBDal::getInstance).thenReturn(obDal);

      cleanUserPasswordAttempts.invoke(authManager, mockUser);

      verify(mockUser, times(0)).setEtasBadPasswordAttempts(any());
      verify(obDal, times(0)).save(any());
      verify(obDal, times(0)).flush();
    }
  }

  /**
   * Tests that the method {@code executePasswordResetForNewUsers(User)}
   * marks the password as expired and sets the user status to not new
   * when the user is a new user.
   *
   * @throws Exception if reflection access fails or method execution throws an error.
   */
  @Test
  public void testExecutePasswordResetForNewUsers() throws Exception {
    Method executePasswordResetForNewUsers = getPrivateMethod(Utility.EXECUTE_PASSWORD_RESET_FOR_NEW_USERS, User.class);

    when(mockUser.isEtasIsNewUser()).thenReturn(true);

    executePasswordResetForNewUsers.invoke(authManager, mockUser);

    verify(mockUser).setPasswordExpired(true);
    verify(mockUser).setEtasIsNewUser(false);
  }

  /**
   * Tests that the method {@code executePasswordResetForNewUsers(User)}
   * does not alter the user when they are not marked as new.
   *
   * @throws Exception if reflection access fails or method execution throws an error.
   */
  @Test
  public void testExecutePasswordResetForExistingUsers() throws Exception {
    Method executePasswordResetForNewUsers = getPrivateMethod(Utility.EXECUTE_PASSWORD_RESET_FOR_NEW_USERS, User.class);

    when(mockUser.isEtasIsNewUser()).thenReturn(false);

    executePasswordResetForNewUsers.invoke(authManager, mockUser);

    verify(mockUser, times(0)).setPasswordExpired(anyBoolean());
    verify(mockUser, times(0)).setEtasIsNewUser(anyBoolean());
  }

  /**
   * Tests the method {@code executePasswordResetForNewUsers(User)}
   * for handling exceptions correctly.
   *
   * @throws Exception if reflection access fails or method execution throws an error.
   */
  @Test
  public void testExecutePasswordResetForNewUsersWithException() throws Exception {
    Method executePasswordResetForNewUsers = getPrivateMethod(Utility.EXECUTE_PASSWORD_RESET_FOR_NEW_USERS, User.class);

    when(mockUser.isEtasIsNewUser()).thenThrow(new RuntimeException("Test exception"));

    InvocationTargetException exception = assertThrows(InvocationTargetException.class, () ->
      executePasswordResetForNewUsers.invoke(authManager, mockUser)
    );

    assertTrue(exception.getCause() instanceof OBException);
    assertEquals("Test exception", exception.getCause().getMessage());
  }
}