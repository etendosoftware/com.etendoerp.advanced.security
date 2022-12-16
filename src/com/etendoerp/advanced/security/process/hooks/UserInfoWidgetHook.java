package com.etendoerp.advanced.security.process.hooks;

import java.util.ArrayList;
import java.util.List;

import org.hibernate.criterion.Restrictions;
import org.openbravo.authentication.hashing.PasswordHash;
import org.openbravo.dal.service.OBCriteria;
import org.openbravo.dal.service.OBDal;
import org.openbravo.erpCommon.utility.OBError;
import org.openbravo.model.ad.access.User;
import org.openbravo.model.ad.access.UserPassword;
import org.openbravo.model.ad.system.SystemInformation;

public class UserInfoWidgetHook implements org.openbravo.client.application.UserInfoWidgetHook {

  /**
   * Processes a User Password.
   * This method uses the {@link org.openbravo.client.application.UserInfoWidgetHook}
   * @param user current User
   * @param newPwd new password
   * @return an {@link OBError} with the message of the resulting operation. Null is success
   */
  @Override
  public OBError process(User user, String newPwd) {
    final SystemInformation systemInfo = OBDal.getInstance().get(SystemInformation.class, "0");
    if (systemInfo.isEasEnablePassHist() && verifySavedPassword(getSavedPasswordFromUser(user), newPwd)) {
      OBError error = new OBError();
      error.setType("Error");
      error.setMessage("EAS_PasswordAlreadyUsed");
      return error;
    }
    return null;
  }

  /**
   * Verify if the password entered has not been used in the user's password history.
   *
   * @param savedPasswords List of saved password from current user
   * @param newPwd New password to verify
   * @return True when list of saved passwords contains new password, otherwise, false.
   */
  private boolean verifySavedPassword(List<String> savedPasswords, String newPwd) {
    for (String savedPassword : savedPasswords) {
      if (PasswordHash.matches(newPwd, savedPassword)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Retrieves the user's saved password history
   *
   * @param user Current User
   * @return User password history
   */
  private List<String> getSavedPasswordFromUser(User user) {
    List<String> savedPasswordStr = new ArrayList<>();
    OBCriteria<UserPassword> userPasswordOBCriteria = OBDal.getInstance()
        .createCriteria(UserPassword.class);
    userPasswordOBCriteria.add(Restrictions.eq(UserPassword.PROPERTY_USERCONTACT, user));
    var savedPassword = userPasswordOBCriteria.list();
    if (!savedPassword.isEmpty()) {
      for (UserPassword userPassword : savedPassword) {
        savedPasswordStr.add(userPassword.getSavedPassword());
      }
    }
    return savedPasswordStr;
  }
}
