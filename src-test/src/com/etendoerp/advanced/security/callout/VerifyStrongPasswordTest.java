package com.etendoerp.advanced.security.callout;

import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import org.openbravo.base.weld.WeldUtils;
import org.openbravo.dal.service.OBDal;
import org.openbravo.erpCommon.ad_callouts.SimpleCallout;
import org.openbravo.model.ad.access.User;
import org.openbravo.model.ad.system.SystemInformation;
import org.openbravo.service.password.PasswordStrengthChecker;

import javax.servlet.ServletException;
import java.util.Arrays;
import java.util.List;

import com.etendoerp.advanced.security.Utility;
import com.etendoerp.advanced.security.utils.AdvancedSecurityUtils;

/**
 * Unit tests for the {@link VerifyStrongPassword} class.
 * These tests verify the behavior of the strong password verification logic,
 * including scenarios for empty passwords, new passwords, and reused passwords.
 */
@ExtendWith(MockitoExtension.class)
public class VerifyStrongPasswordTest {

  private VerifyStrongPassword verifyStrongPassword;

  @Mock
  private PasswordStrengthChecker mockPasswordStrengthChecker;

  @Mock
  private SimpleCallout.CalloutInfo mockCalloutInfo;

  @Mock
  private OBDal mockOBDal;

  @Mock
  private SystemInformation mockSystemInfo;

  @Mock
  private User mockUser;

  /**
   * Sets up the test environment by initializing the {@link VerifyStrongPassword} instance
   * and preparing mock objects.
   */
  @BeforeEach
  public void setUp() {
    verifyStrongPassword = spy(new VerifyStrongPassword());
  }

  /**
   * Tests the behavior when the input password is empty.
   * Verifies that the result indicates the password is secure by default.
   *
   * @throws ServletException if there is an error during callout execution.
   */
  @Test
  public void testEmptyPassword() throws ServletException {
    when(mockCalloutInfo.getStringParameter(Utility.INP_PASSWORD)).thenReturn("");

    try (MockedStatic<WeldUtils> weldUtilsMockedStatic = mockStatic(WeldUtils.class);
         MockedStatic<OBDal> obDalMockedStatic = mockStatic(OBDal.class);
         MockedStatic<AdvancedSecurityUtils> securityUtilsMockedStatic = mockStatic(AdvancedSecurityUtils.class)) {

      weldUtilsMockedStatic.when(() -> WeldUtils.getInstanceFromStaticBeanManager(PasswordStrengthChecker.class))
          .thenReturn(mockPasswordStrengthChecker);

      obDalMockedStatic.when(OBDal::getInstance).thenReturn(mockOBDal);
      when(mockOBDal.get(SystemInformation.class, Utility.SYSTEM_INFO_ID)).thenReturn(mockSystemInfo);
      when(mockSystemInfo.isEtasEnablePassHist()).thenReturn(false);

      verifyStrongPassword.execute(mockCalloutInfo);

      verify(mockCalloutInfo).addResult(Utility.INPEM_ETAS_ISSECURE_PW, "Y");
    }
  }

  /**
   * Tests the behavior when password history is enabled and a new, unique password is provided.
   * Verifies that the password is marked as strong and not reused.
   *
   * @throws ServletException if there is an error during callout execution.
   */
  @Test
  public void testPasswordHistoryEnabledNewPassword() throws ServletException {
    String newPassword = "NewSecurePa$$w0rd2024!";
    when(mockCalloutInfo.getStringParameter(Utility.INP_PASSWORD)).thenReturn(newPassword);
    when(mockCalloutInfo.getStringParameter("AD_User_ID")).thenReturn(Utility.TEST_USER_ID);

    try (MockedStatic<WeldUtils> weldUtilsMockedStatic = mockStatic(WeldUtils.class);
         MockedStatic<OBDal> obDalMockedStatic = mockStatic(OBDal.class);
         MockedStatic<AdvancedSecurityUtils> securityUtilsMockedStatic = mockStatic(AdvancedSecurityUtils.class)) {

      weldUtilsMockedStatic.when(() -> WeldUtils.getInstanceFromStaticBeanManager(PasswordStrengthChecker.class))
          .thenReturn(mockPasswordStrengthChecker);
      when(mockPasswordStrengthChecker.isStrongPassword(newPassword)).thenReturn(true);

      obDalMockedStatic.when(OBDal::getInstance).thenReturn(mockOBDal);
      when(mockOBDal.get(SystemInformation.class, Utility.SYSTEM_INFO_ID)).thenReturn(mockSystemInfo);
      when(mockSystemInfo.isEtasEnablePassHist()).thenReturn(true);

      when(mockOBDal.get(User.class, Utility.TEST_USER_ID)).thenReturn(mockUser);
      List<String> savedPasswords = Arrays.asList(Utility.OLD_PASSWORD, "AnotherOldPwd!");

      securityUtilsMockedStatic
          .when(() -> AdvancedSecurityUtils.getSavedPasswordFromUser(mockUser))
          .thenReturn(savedPasswords);
      securityUtilsMockedStatic
          .when(() -> AdvancedSecurityUtils.verifySavedPassword(savedPasswords, newPassword))
          .thenReturn(false);

      verifyStrongPassword.execute(mockCalloutInfo);

      verify(mockCalloutInfo).addResult(Utility.INPEM_ETAS_ISSECURE_PW, "Y");
      verify(mockCalloutInfo).addResult("inpemEtasIsusedPw", "N");
    }
  }

  /**
   * Tests the behavior when password history is enabled and a reused password is provided.
   * Verifies that the password is marked as strong but also flagged as reused.
   *
   * @throws ServletException if there is an error during callout execution.
   */
  @Test
  public void testPasswordHistoryEnabledReusedPassword() throws ServletException {
    String reusedPassword = Utility.OLD_PASSWORD;
    when(mockCalloutInfo.getStringParameter(Utility.INP_PASSWORD)).thenReturn(reusedPassword);
    when(mockCalloutInfo.getStringParameter("AD_User_ID")).thenReturn(Utility.TEST_USER_ID);

    try (MockedStatic<WeldUtils> weldUtilsMockedStatic = mockStatic(WeldUtils.class);
         MockedStatic<OBDal> obDalMockedStatic = mockStatic(OBDal.class);
         MockedStatic<AdvancedSecurityUtils> securityUtilsMockedStatic = mockStatic(AdvancedSecurityUtils.class)) {

      weldUtilsMockedStatic.when(() -> WeldUtils.getInstanceFromStaticBeanManager(PasswordStrengthChecker.class))
          .thenReturn(mockPasswordStrengthChecker);
      when(mockPasswordStrengthChecker.isStrongPassword(reusedPassword)).thenReturn(true);

      obDalMockedStatic.when(OBDal::getInstance).thenReturn(mockOBDal);
      when(mockOBDal.get(SystemInformation.class, Utility.SYSTEM_INFO_ID)).thenReturn(mockSystemInfo);
      when(mockSystemInfo.isEtasEnablePassHist()).thenReturn(true);

      when(mockOBDal.get(User.class, Utility.TEST_USER_ID)).thenReturn(mockUser);
      List<String> savedPasswords = Arrays.asList(Utility.OLD_PASSWORD, "AnotherOldPwd!");

      securityUtilsMockedStatic
          .when(() -> AdvancedSecurityUtils.getSavedPasswordFromUser(mockUser))
          .thenReturn(savedPasswords);
      securityUtilsMockedStatic
          .when(() -> AdvancedSecurityUtils.verifySavedPassword(savedPasswords, reusedPassword))
          .thenReturn(true);

      verifyStrongPassword.execute(mockCalloutInfo);

      verify(mockCalloutInfo).addResult(Utility.INPEM_ETAS_ISSECURE_PW, "Y");
      verify(mockCalloutInfo).addResult("inpemEtasIsusedPw", "Y");
    }
  }
}
