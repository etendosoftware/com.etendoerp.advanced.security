package com.etendoerp.advanced.security.hooks;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

import java.util.Date;

import org.junit.Before;
import org.junit.Test;
import org.mockito.MockedStatic;
import org.mockito.junit.MockitoJUnitRunner;
import org.junit.runner.RunWith;
import org.openbravo.dal.service.OBDal;
import org.openbravo.erpCommon.utility.OBError;
import org.openbravo.erpCommon.utility.OBMessageUtils;
import org.openbravo.model.ad.access.User;
import org.openbravo.model.ad.system.SystemInformation;

import com.etendoerp.advanced.security.Utility;
import com.etendoerp.advanced.security.utils.AdvancedSecurityUtils;

/**
 * Test class for LoginHandlerHook.
 * Provides unit tests for the process method to validate its behavior
 * under different scenarios such as user not found, exceptions occurring,
 * and password expiration warnings.
 */
@RunWith(MockitoJUnitRunner.class)
public class LoginHandlerHookTest {

  private LoginHandlerHook loginHandlerHook;

  /**
   * Sets up the test class instance and initializes required objects.
   */
  @Before
  public void setUp() {
    loginHandlerHook = new LoginHandlerHook();
  }

  /**
   * Tests the process method when the user is not found.
   * Verifies that the method returns null when no user is found by AdvancedSecurityUtils.
   */
  @Test
  public void testProcessWhenUserNotFoundShouldReturnNull() {
    try (MockedStatic<AdvancedSecurityUtils> advancedSecurityUtilsMockedStatic = mockStatic(AdvancedSecurityUtils.class)) {
      advancedSecurityUtilsMockedStatic.when(() -> AdvancedSecurityUtils.getUser("unknownUser"))
          .thenReturn(null);

      OBError result = loginHandlerHook.process("unknownUser", Utility.SOME_ACTION);

      assertNull(result);
    }
  }

  /**
   * Tests the process method when an exception occurs.
   * Verifies that the method returns an error OBError object with the correct type and message.
   */
  @Test
  public void testProcessWhenExceptionOccursShouldReturnError() {
    try (MockedStatic<AdvancedSecurityUtils> advancedSecurityUtilsMockedStatic = mockStatic(AdvancedSecurityUtils.class)) {

      advancedSecurityUtilsMockedStatic.when(() -> AdvancedSecurityUtils.getUser(Utility.TEST_USER))
          .thenThrow(new RuntimeException("Mocked Exception"));

      OBError result = loginHandlerHook.process(Utility.TEST_USER, Utility.SOME_ACTION);

      assertNotNull(result);
      assertEquals("Error", result.getType());
      assertEquals("Mocked Exception", result.getMessage());
    }
  }

  /**
   * Tests the process method when the password is near expiration.
   * Verifies that the method returns a warning OBError object with the correct type and message format.
   */
  @Test
  public void testProcessWhenPasswordNearToExpireShouldReturnWarning() {
    try (MockedStatic<OBDal> obDalMockedStatic = mockStatic(OBDal.class);
         MockedStatic<AdvancedSecurityUtils> advancedSecurityUtilsMockedStatic = mockStatic(AdvancedSecurityUtils.class);
         MockedStatic<OBMessageUtils> obMessageUtilsMockedStatic = mockStatic(OBMessageUtils.class)) {

      OBDal mockObDal = mock(OBDal.class);
      SystemInformation mockSystemInfo = mock(SystemInformation.class);

      obDalMockedStatic.when(OBDal::getInstance).thenReturn(mockObDal);
      when(mockObDal.get(SystemInformation.class, Utility.SYSTEM_INFO_ID)).thenReturn(mockSystemInfo);

      when(mockSystemInfo.isEtasShowExpiredMsg()).thenReturn(true);

      User mockUser = mock(User.class);
      when(mockUser.getId()).thenReturn("101");
      when(mockUser.getLastPasswordUpdate()).thenReturn(new Date());

      advancedSecurityUtilsMockedStatic.when(() -> AdvancedSecurityUtils.getUser(Utility.TEST_USER))
          .thenReturn(mockUser);
      advancedSecurityUtilsMockedStatic.when(() -> AdvancedSecurityUtils.getDaysToPasswordExpirationPreference(mockUser))
          .thenReturn("10");
      advancedSecurityUtilsMockedStatic.when(() -> AdvancedSecurityUtils.getDateLimitToExpire(any(), eq("10")))
          .thenReturn(new Date(System.currentTimeMillis() + 2 * 24 * 60 * 60 * 1000L));
      advancedSecurityUtilsMockedStatic.when(() -> AdvancedSecurityUtils.getDiffBetweenDateLimitAndNow(any(), eq(true)))
          .thenReturn(2L);

      obMessageUtilsMockedStatic.when(() -> OBMessageUtils.messageBD("ETAS_PasswordNearToExpTittle"))
          .thenReturn("Password Near to Expire");
      obMessageUtilsMockedStatic.when(() -> OBMessageUtils.messageBD("ETAS_PasswordNearToExp"))
          .thenReturn("Your password will expire in %s days");

      OBError result = loginHandlerHook.process(Utility.TEST_USER, Utility.SOME_ACTION);

      assertNotNull(result);
      assertEquals("Warning", result.getType());
      assertTrue(result.getMessage().contains("2"));
    }
  }

  /**
   * Tests the process method when the password is not near expiration.
   * Verifies that the method returns null under this condition.
   */
  @Test
  public void testProcessWhenPasswordNotNearToExpireShouldReturnNull() {
    try (MockedStatic<OBDal> obDalMockedStatic = mockStatic(OBDal.class);
         MockedStatic<AdvancedSecurityUtils> advancedSecurityUtilsMockedStatic = mockStatic(AdvancedSecurityUtils.class)) {

      OBDal mockObDal = mock(OBDal.class);
      SystemInformation mockSystemInfo = mock(SystemInformation.class);

      obDalMockedStatic.when(OBDal::getInstance).thenReturn(mockObDal);
      when(mockObDal.get(SystemInformation.class, Utility.SYSTEM_INFO_ID)).thenReturn(mockSystemInfo);

      when(mockSystemInfo.isEtasShowExpiredMsg()).thenReturn(true);

      User mockUser = mock(User.class);
      when(mockUser.getId()).thenReturn("101");
      when(mockUser.getLastPasswordUpdate()).thenReturn(new Date());

      advancedSecurityUtilsMockedStatic.when(() -> AdvancedSecurityUtils.getUser(Utility.TEST_USER))
          .thenReturn(mockUser);
      advancedSecurityUtilsMockedStatic.when(() -> AdvancedSecurityUtils.getDaysToPasswordExpirationPreference(mockUser))
          .thenReturn("10");
      advancedSecurityUtilsMockedStatic.when(() -> AdvancedSecurityUtils.getDateLimitToExpire(any(), eq("10")))
          .thenReturn(new Date(System.currentTimeMillis() + 15 * 24 * 60 * 60 * 1000L));
      advancedSecurityUtilsMockedStatic.when(() -> AdvancedSecurityUtils.getDiffBetweenDateLimitAndNow(any(), eq(true)))
          .thenReturn(15L);

      OBError result = loginHandlerHook.process(Utility.TEST_USER, Utility.SOME_ACTION);

      assertNull(result);
    }
  }
}