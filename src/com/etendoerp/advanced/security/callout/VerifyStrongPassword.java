package com.etendoerp.advanced.security.callout;

import java.util.List;

import javax.inject.Inject;
import javax.servlet.ServletException;

import org.apache.commons.lang3.StringUtils;
import org.openbravo.base.weld.WeldUtils;
import org.openbravo.dal.service.OBDal;
import org.openbravo.erpCommon.ad_callouts.SimpleCallout;
import org.openbravo.model.ad.access.User;
import org.openbravo.model.ad.system.SystemInformation;
import org.openbravo.service.password.PasswordStrengthChecker;

import com.etendoerp.advanced.security.utils.AdvancedSecurityUtils;

public class VerifyStrongPassword extends SimpleCallout {

  @Inject
  private PasswordStrengthChecker passwordStrengthChecker;

  /**
   * This method checks the password strength and history of a given password for a user.
   *
   * @param info
   *     The CalloutInfo object containing the context for the callout.
   * @throws ServletException
   */
  @Override
  protected void execute(CalloutInfo info) throws ServletException {
    // Retrieve the PasswordStrengthChecker instance from the Bean Manager
    passwordStrengthChecker = WeldUtils.getInstanceFromStaticBeanManager(PasswordStrengthChecker.class);

    // Get the password value from the input parameter
    String password = info.getStringParameter("inppassword");
    // Set the default value for isSecurePassword to true
    boolean isSecurePassword = true;
    if (!StringUtils.isEmpty(password)) {
      // Check if the password is a strong password
      isSecurePassword = passwordStrengthChecker.isStrongPassword(password);
    }

    info.addResult("inpemEtasIssecurePw", isSecurePassword ? "Y" : "N");

    final SystemInformation systemInfo = OBDal.getInstance().get(SystemInformation.class, "0");
    // Check if password history is enabled
    if (!systemInfo.isEtasEnablePassHist()) {
      return;
    }

    final String userId = info.getStringParameter("AD_User_ID");
    User user = OBDal.getInstance().get(User.class, userId);
    if (user != null) {
      // Get the list of saved passwords for the user
      List<String> savedPassword = AdvancedSecurityUtils.getSavedPasswordFromUser(user);
      // Check if the password has been used before for this user
      boolean isUsedPassword = AdvancedSecurityUtils.verifySavedPassword(savedPassword, password);
      info.addResult("inpemEtasIsusedPw", isUsedPassword ? "Y" : "N");
    }
  }
}
