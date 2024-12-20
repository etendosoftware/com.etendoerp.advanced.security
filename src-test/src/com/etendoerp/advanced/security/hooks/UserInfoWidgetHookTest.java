package com.etendoerp.advanced.security.hooks;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

import java.util.Collections;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.mockito.MockedStatic;
import org.openbravo.dal.service.OBDal;
import org.openbravo.erpCommon.utility.OBError;
import org.openbravo.model.ad.access.User;
import org.openbravo.model.ad.system.SystemInformation;

import com.etendoerp.advanced.security.Utility;
import com.etendoerp.advanced.security.utils.AdvancedSecurityUtils;

/**
 * Unit tests for the {@link UserInfoWidgetHook} class. These tests validate the behavior of the
 * password processing logic under different conditions, ensuring compliance with the advanced
 * security requirements.
 */
@RunWith(MockitoJUnitRunner.class)
public class UserInfoWidgetHookTest {

  @Mock
  private OBDal obDal;

  @Mock
  private SystemInformation systemInfo;

  @Mock
  private User user;

  private UserInfoWidgetHook hook;

  /**
   * Sets up the test environment by initializing the {@link UserInfoWidgetHook} instance.
   */
  @Before
  public void setUp() {
    hook = new UserInfoWidgetHook();
  }

  /**
   * Tests that when password history is disabled, the {@code process} method returns {@code null}.
   */
  @Test
  public void testProcessWhenPasswordHistoryDisabledShouldReturnNull() {
    try (MockedStatic<OBDal> obDalMockedStatic = mockStatic(OBDal.class)) {

      obDalMockedStatic.when(OBDal::getInstance).thenReturn(obDal);
      when(obDal.get(SystemInformation.class, Utility.SYSTEM_INFO_ID)).thenReturn(systemInfo);
      when(systemInfo.isEtasEnablePassHist()).thenReturn(false);

      OBError result = hook.process(user, Utility.NEW_PASSWORD);

      assertNull(result);
    }
  }

  /**
   * Tests that when the password has already been used, the {@code process} method returns an error.
   */
  @Test
  public void testProcessWhenPasswordAlreadyUsedShouldReturnError() {
    try (MockedStatic<OBDal> obDalMockedStatic = mockStatic(OBDal.class);
         MockedStatic<AdvancedSecurityUtils> advancedSecurityUtilsMockedStatic = mockStatic(AdvancedSecurityUtils.class)) {

      obDalMockedStatic.when(OBDal::getInstance).thenReturn(obDal);
      when(obDal.get(SystemInformation.class, Utility.SYSTEM_INFO_ID)).thenReturn(systemInfo);
      when(systemInfo.isEtasEnablePassHist()).thenReturn(true);
      advancedSecurityUtilsMockedStatic.when(() -> AdvancedSecurityUtils.getSavedPasswordFromUser(user))
          .thenReturn(Collections.singletonList(Utility.SAVED_PASSWORD));
      advancedSecurityUtilsMockedStatic.when(() -> AdvancedSecurityUtils.verifySavedPassword(Collections.singletonList(Utility.SAVED_PASSWORD), Utility.NEW_PASSWORD))
          .thenReturn(true);

      OBError result = hook.process(user, Utility.NEW_PASSWORD);

      assertNotNull(result);
      assertEquals("Error", result.getType());
      assertEquals("ETAS_PasswordAlreadyUsed", result.getMessage());
    }
  }

  /**
   * Tests that when the password has not been used before, the {@code process} method returns {@code null}.
   */
  @Test
  public void testProcessWhenPasswordNotUsedBeforeShouldReturnNull() {
    try (MockedStatic<OBDal> obDalMockedStatic = mockStatic(OBDal.class);
         MockedStatic<AdvancedSecurityUtils> advancedSecurityUtilsMockedStatic = mockStatic(AdvancedSecurityUtils.class)) {

      obDalMockedStatic.when(OBDal::getInstance).thenReturn(obDal);
      when(obDal.get(SystemInformation.class, Utility.SYSTEM_INFO_ID)).thenReturn(systemInfo);
      when(systemInfo.isEtasEnablePassHist()).thenReturn(true);
      advancedSecurityUtilsMockedStatic.when(() -> AdvancedSecurityUtils.getSavedPasswordFromUser(user))
          .thenReturn(Collections.singletonList(Utility.SAVED_PASSWORD));
      advancedSecurityUtilsMockedStatic.when(() -> AdvancedSecurityUtils.verifySavedPassword(Collections.singletonList(Utility.SAVED_PASSWORD), Utility.NEW_PASSWORD))
          .thenReturn(false);

      OBError result = hook.process(user, Utility.NEW_PASSWORD);

      assertNull(result);
    }
  }
}
