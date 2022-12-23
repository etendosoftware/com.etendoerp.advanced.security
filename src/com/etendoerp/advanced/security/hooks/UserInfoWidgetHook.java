package com.etendoerp.advanced.security.hooks;

import org.openbravo.dal.service.OBDal;
import org.openbravo.erpCommon.utility.OBError;
import org.openbravo.model.ad.access.User;
import org.openbravo.model.ad.system.SystemInformation;

import com.etendoerp.advanced.security.utils.AdvancedSecurityUtils;

public class UserInfoWidgetHook implements org.openbravo.client.application.UserInfoWidgetHook {

  /**
   * Processes a User Password.
   * This method uses the {@link org.openbravo.client.application.UserInfoWidgetHook}
   *
   * @param user
   *     current User
   * @param newPwd
   *     new password
   * @return an {@link OBError} with the message of the resulting operation. Null is success
   */
  @Override
  public OBError process(User user, String newPwd) {
    final SystemInformation systemInfo = OBDal.getInstance().get(SystemInformation.class, "0");
    if (systemInfo.isEtasEnablePassHist() && AdvancedSecurityUtils.verifySavedPassword(
        AdvancedSecurityUtils.getSavedPasswordFromUser(user), newPwd)) {
      OBError error = new OBError();
      error.setType("Error");
      error.setMessage("ETAS_PasswordAlreadyUsed");
      return error;
    }
    return null;
  }

}
